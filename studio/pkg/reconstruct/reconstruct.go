package reconstruct

import (
	"fmt"
	"sort"
	"strings"

	"pktpath/studio/pkg/wire"
)

type lossQual struct {
	kind   int
	name   string
	ws, we uint64
	oid    uint64
}

type rawPath struct {
	slices []ObjectSlice
	rels   []*Relation
}

// Reconstruct builds the full evidence DAG from a loaded session.
func Reconstruct(ls *wire.LoadedSession) *Session {
	s := &Session{
		Loaded:   ls,
		Manifest: ls.Manifest,
		Dict:     ls.Dictionary,
		Objects:  map[uint64]*ObjectNode{},
		Samples:  map[uint64]*SampleGraph{},
	}
	s.sites = parseSites(ls.Dictionary)
	s.topo = parseTopology(ls.Dictionary)
	s.calibs = parseCalibrations(ls.Manifest)

	s.Events, s.DedupDropped, s.SeqGaps = dedupAndDetectSeqGaps(ls.Events)

	if ads, ok := s.Manifest["adapters"].([]any); ok {
		for _, a := range ads {
			m, ok := a.(map[string]any)
			if !ok {
				continue
			}
			if en, ok := m["enabled"]; ok && !wire.Truthy(en) {
				continue
			}
			if rq, ok := m["required"].(bool); ok && !rq {
				continue
			}
			if strings.ToLower(strings.TrimSpace(jstr(m["missed_source"]))) == "none" {
				id := jstr(m["adapter_id"])
				if id == "" {
					id = jstr(m["name"])
				}
				if id == "" {
					id = "unknown"
				}
				s.UnobservableAdapters = append(s.UnobservableAdapters, id)
			}
		}
	}
	s.HasUnobservableMissedSrc = len(s.UnobservableAdapters) > 0

	getObj := func(oid uint64, otype uint8) *ObjectNode {
		n := s.Objects[oid]
		if n == nil {
			n = &ObjectNode{ObjectID: oid, ObjectType: otype, SampleIDs: map[uint64]bool{}}
			s.Objects[oid] = n
			s.ObjectOrder = append(s.ObjectOrder, oid)
		} else if n.ObjectType == wire.ObjSKB && otype != wire.ObjSKB {
			n.ObjectType = otype
		}
		return n
	}

	for _, ev := range s.Events {
		switch ev.Kind {
		case wire.KindObject:
			if ev.ObjectID == 0 {
				continue
			}
			obj := getObj(ev.ObjectID, ev.ObjectType)
			obj.ObjectEvents = append(obj.ObjectEvents, ev)
			if sid := ev.U("sample_id"); sid > 0 {
				obj.SampleIDs[sid] = true
				if obj.PrimarySampleID == 0 {
					obj.PrimarySampleID = sid
				}
			}
			if er, ok := ev.Get("end_reason"); ok && er != wire.EndOpen {
				obj.ExplicitEndReason = int(er)
				if er == wire.EndConflictTruncated {
					obj.IdentityConflict = true
				}
			}
			if dr, ok := ev.Get("drop_reason"); ok {
				obj.DropReason = Some(dr)
			}
			obj.UnknownMust = append(obj.UnknownMust, ev.UnknownMust...)
			obj.UnknownOptional = append(obj.UnknownOptional, ev.UnknownOptional...)
		case wire.KindStep:
			if ev.ObjectID != 0 {
				obj := getObj(ev.ObjectID, ev.ObjectType)
				obj.Steps = append(obj.Steps, ev)
				obj.UnknownMust = append(obj.UnknownMust, ev.UnknownMust...)
				obj.UnknownOptional = append(obj.UnknownOptional, ev.UnknownOptional...)
			} else {
				d := getObj(0, ev.ObjectType)
				d.Steps = append(d.Steps, ev)
			}
		case wire.KindSummary:
			if ev.ObjectID == 0 {
				continue
			}
			obj := getObj(ev.ObjectID, ev.ObjectType)
			obj.Summaries = append(obj.Summaries, ev)
			obj.UnknownMust = append(obj.UnknownMust, ev.UnknownMust...)
			obj.UnknownOptional = append(obj.UnknownOptional, ev.UnknownOptional...)
		case wire.KindRelation:
			srcID := ev.ObjectID
			if v, ok := ev.Get("src_object_id"); ok {
				srcID = v
			}
			dstID := ev.U("dst_object_id")
			rtype := int(ev.U("rel_type"))
			rflags := ev.U("rel_flags")
			name, ok := wire.RelTypeNames[rtype]
			if !ok {
				name = fmt.Sprintf("REL_%d", rtype)
			}
			edge := &Relation{
				Event: ev, OpID: ev.U("op_id"), RelType: rtype, RelTypeName: name,
				SrcObjectID: srcID, DstObjectID: dstID, RelFlags: rflags,
				SuccessorTruncated:  rflags&wire.RelFlagSuccessorTruncated != 0,
				UnknownPredecessors: rflags&wire.RelFlagUnknownPredecessors != 0,
				StreamOffset:        evOpt(ev, "stream_offset"), SpanLen: evOpt(ev, "span_len"), TsNs: ev.TsNs,
			}
			s.Relations = append(s.Relations, edge)
			if srcID != 0 {
				otype := ev.ObjectType
				if _, exists := s.Objects[srcID]; rtype == wire.RelSpanMap && !exists {
					otype = wire.ObjAppMsg
				}
				so := getObj(srcID, otype)
				so.Outgoing = append(so.Outgoing, edge)
				so.UnknownMust = append(so.UnknownMust, ev.UnknownMust...)
				if edge.SuccessorTruncated {
					so.SuccessorTruncated = true
				}
			}
			if dstID != 0 {
				do := getObj(dstID, wire.ObjSKB)
				do.Incoming = append(do.Incoming, edge)
				do.UnknownMust = append(do.UnknownMust, ev.UnknownMust...)
				if edge.UnknownPredecessors {
					do.UnknownPredecessors = true
				}
				if edge.SuccessorTruncated {
					do.SuccessorTruncated = true
				}
			}
		case wire.KindQState:
			s.QStateEvents = append(s.QStateEvents, ev)
		case wire.KindQuality:
			s.QualityEvents = append(s.QualityEvents, ev)
			qkind := int(ev.U("qual_kind"))
			qcnt := uint64(1)
			if c, ok := ev.Get("count"); ok {
				qcnt = c
			}
			if qkind == wire.QualTopoDesync && qcnt > 0 {
				ws := orTs(ev.U("win_start_ns"), ev.TsNs)
				we := orTs(ev.U("win_end_ns"), ev.TsNs)
				if we < ws {
					we = ws
				}
				s.TopoDesyncWindows = append(s.TopoDesyncWindows, [2]uint64{ws, we})
			} else if qkind == wire.QualIdentityConflict && qcnt > 0 && ev.ObjectID != 0 {
				getObj(ev.ObjectID, ev.ObjectType).IdentityConflict = true
			}
		}
	}

	s.QStates = buildQStateAnnotations(s.QStateEvents)

	recomputeTs := func(obj *ObjectNode) {
		first, last, any := uint64(0), uint64(0), false
		for _, l := range [][]*wire.Event{obj.ObjectEvents, obj.Steps, obj.Summaries} {
			for _, e := range l {
				if !any {
					first, last, any = e.TsNs, e.TsNs, true
					continue
				}
				if e.TsNs < first {
					first = e.TsNs
				}
				if e.TsNs > last {
					last = e.TsNs
				}
			}
		}
		if any {
			obj.FirstTsNs, obj.LastTsNs = first, last
		}
	}
	for _, oid := range s.ObjectOrder {
		if oid == 0 {
			continue
		}
		obj := s.Objects[oid]
		recomputeTs(obj)
		obj.Attr = extractAttribution(obj)
	}

	s.UnmatchedReturns = s.pairCallsAndVisits()
	if _, ok := s.Objects[0]; ok {
		delete(s.Objects, 0)
		for i, oid := range s.ObjectOrder {
			if oid == 0 {
				s.ObjectOrder = append(s.ObjectOrder[:i:i], s.ObjectOrder[i+1:]...)
				break
			}
		}
	}

	for _, oid := range s.ObjectOrder {
		obj := s.Objects[oid]
		recomputeTs(obj)
		obj.Attr = extractAttribution(obj)
		obj.EffectiveEndReason = computeEffectiveEndReason(obj)
		for _, st := range obj.Steps {
			switch st.Stage() {
			case wire.StageRequeueGSO:
				s.RequeueGSOCount++
			case wire.StageRequeueBadTxq:
				s.RequeueBadTxqCount++
			}
		}
	}

	// Propagate sample ids across relations.
	minKey := func(m map[uint64]bool) uint64 {
		first := true
		var mn uint64
		for k := range m {
			if first || k < mn {
				mn, first = k, false
			}
		}
		return mn
	}
	for changed := true; changed; {
		changed = false
		for _, rel := range s.Relations {
			src, dst := s.Objects[rel.SrcObjectID], s.Objects[rel.DstObjectID]
			if src == nil || dst == nil {
				continue
			}
			before := len(dst.SampleIDs)
			for k := range src.SampleIDs {
				dst.SampleIDs[k] = true
			}
			if len(dst.SampleIDs) != before {
				if dst.PrimarySampleID == 0 {
					dst.PrimarySampleID = minKey(dst.SampleIDs)
				}
				changed = true
			}
			if len(src.SampleIDs) == 0 && len(dst.SampleIDs) > 0 && rel.RelType == wire.RelSpanMap {
				for k := range dst.SampleIDs {
					src.SampleIDs[k] = true
				}
				src.PrimarySampleID = minKey(src.SampleIDs)
				changed = true
			}
		}
	}
	for _, oid := range s.ObjectOrder {
		obj := s.Objects[oid]
		if len(obj.SampleIDs) == 0 {
			obj.SampleIDs[obj.ObjectID] = true
			obj.PrimarySampleID = obj.ObjectID
		}
	}

	sortedOids := append([]uint64(nil), s.ObjectOrder...)
	sort.Slice(sortedOids, func(i, j int) bool { return sortedOids[i] < sortedOids[j] })
	sampleObjs := map[uint64][]uint64{}
	for _, oid := range sortedOids {
		sids := make([]uint64, 0, len(s.Objects[oid].SampleIDs))
		for sid := range s.Objects[oid].SampleIDs {
			sids = append(sids, sid)
		}
		sort.Slice(sids, func(i, j int) bool { return sids[i] < sids[j] })
		for _, sid := range sids {
			sampleObjs[sid] = append(sampleObjs[sid], oid)
		}
	}
	for sid := range sampleObjs {
		s.SampleOrder = append(s.SampleOrder, sid)
	}
	sort.Slice(s.SampleOrder, func(i, j int) bool { return s.SampleOrder[i] < s.SampleOrder[j] })

	var loss []lossQual
	for _, q := range s.QualityEvents {
		k := int(q.U("qual_kind"))
		cnt := uint64(1)
		if c, ok := q.Get("count"); ok {
			cnt = c
		}
		switch k {
		case wire.QualMissedDelta, wire.QualRbDropDelta, wire.QualRetUnmatched, wire.QualIdentityConflict,
			wire.QualRingEvictedPrefix, wire.QualTopoDesync:
			if cnt > 0 {
				ws := orTs(q.U("win_start_ns"), q.TsNs)
				we := orTs(q.U("win_end_ns"), q.TsNs)
				if we < ws {
					we = ws
				}
				loss = append(loss, lossQual{k, wire.QualKindNames[k], ws, we, q.ObjectID})
			}
		}
	}

	partialManifest := wire.Truthy(s.Manifest["partial_coverage"])

	for _, sid := range s.SampleOrder {
		objList := sampleObjs[sid]
		sidSet := map[uint64]bool{}
		for _, o := range objList {
			sidSet[o] = true
		}
		var sampleRels []*Relation
		for _, r := range s.Relations {
			if sidSet[r.SrcObjectID] || sidSet[r.DstObjectID] {
				sampleRels = append(sampleRels, r)
			}
		}
		var roots []uint64
		for _, oid := range objList {
			hasIn := false
			for _, r := range s.Objects[oid].Incoming {
				if sidSet[r.SrcObjectID] {
					hasIn = true
					break
				}
			}
			if !hasIn {
				roots = append(roots, oid)
			}
		}
		if len(roots) == 0 {
			roots = []uint64{objList[0]}
		}

		var paths []rawPath
		var dfs func(cur uint64, minTs uint64, prefixS []ObjectSlice, prefixR []*Relation, visited map[uint64]bool)
		dfs = func(cur uint64, minTs uint64, prefixS []ObjectSlice, prefixR []*Relation, visited map[uint64]bool) {
			node := s.Objects[cur]
			var forks, xforms []*Relation
			for _, r := range node.Outgoing {
				if _, ok := s.Objects[r.DstObjectID]; !ok || visited[r.DstObjectID] {
					continue
				}
				if r.RelType == wire.RelClone || r.RelType == wire.RelCopy {
					forks = append(forks, r)
				} else {
					xforms = append(xforms, r)
				}
			}
			nv := make(map[uint64]bool, len(visited)+1)
			for k := range visited {
				nv[k] = true
			}
			nv[cur] = true
			cat := func(sl ObjectSlice, r *Relation) ([]ObjectSlice, []*Relation) {
				ns := append(append([]ObjectSlice(nil), prefixS...), sl)
				var nr []*Relation
				if r != nil {
					nr = append(append([]*Relation(nil), prefixR...), r)
				} else {
					nr = append([]*Relation(nil), prefixR...)
				}
				return ns, nr
			}
			for _, fr := range forks {
				ns, nr := cat(ObjectSlice{cur, minTs, Some(fr.TsNs)}, fr)
				dfs(fr.DstObjectID, 0, ns, nr, nv)
			}
			if len(xforms) > 0 {
				for _, xr := range xforms {
					ns, nr := cat(ObjectSlice{cur, minTs, OptU{}}, xr)
					dfs(xr.DstObjectID, 0, ns, nr, nv)
				}
			} else {
				ns, nr := cat(ObjectSlice{cur, minTs, OptU{}}, nil)
				paths = append(paths, rawPath{ns, nr})
			}
		}
		for _, r := range roots {
			dfs(r, 0, nil, nil, map[uint64]bool{})
		}

		var sbranches []*BranchPath
		for bi, p := range paths {
			bIdx := bi + 1
			oids := make([]uint64, len(p.slices))
			for i, sl := range p.slices {
				oids[i] = sl.ObjectID
			}
			leaf := s.Objects[oids[len(oids)-1]]
			br := &BranchPath{
				BranchID: fmt.Sprintf("s%d:b%d", sid, bIdx), SampleID: sid, BranchIndex: bIdx,
				ObjectIDs: oids, Slices: p.slices, RelationChain: p.rels,
			}
			idConflict := false
			for _, r := range p.rels {
				if r.SuccessorTruncated {
					br.SuccessorTruncated = true
				}
				if r.UnknownPredecessors {
					br.UnknownPredecessors = true
				}
			}
			for _, sl := range p.slices {
				on := s.Objects[sl.ObjectID]
				if !sl.MaxTs.OK && on.SuccessorTruncated {
					br.SuccessorTruncated = true
				}
				if on.UnknownPredecessors {
					br.UnknownPredecessors = true
				}
				if on.IdentityConflict {
					idConflict = true
				}
				in := func(ts uint64) bool {
					if ts < sl.MinTs {
						return false
					}
					if sl.MaxTs.OK && ts > sl.MaxTs.V {
						return false
					}
					return true
				}
				for _, ev := range on.ObjectEvents {
					if in(ev.TsNs) {
						br.Events = append(br.Events, ev)
						br.UnknownMust = append(br.UnknownMust, ev.UnknownMust...)
					}
				}
				for _, ev := range on.Steps {
					if in(ev.TsNs) {
						br.Events = append(br.Events, ev)
						br.Steps = append(br.Steps, ev)
						br.UnknownMust = append(br.UnknownMust, ev.UnknownMust...)
					}
				}
				for _, ev := range on.Summaries {
					if in(ev.TsNs) {
						br.Events = append(br.Events, ev)
						br.Summaries = append(br.Summaries, ev)
						br.UnknownMust = append(br.UnknownMust, ev.UnknownMust...)
					}
				}
				for _, v := range on.Visits {
					var vts uint64
					if v.Entry != nil {
						vts = v.Entry.TsNs
					} else if v.Exit != nil {
						vts = v.Exit.TsNs
					}
					if in(vts) {
						br.Visits = append(br.Visits, v)
					}
				}
				for _, cp := range on.Calls {
					var cts uint64
					if cp.Entry != nil {
						cts = cp.Entry.TsNs
					}
					if in(cts) {
						br.Calls = append(br.Calls, cp)
					}
				}
			}
			for _, r := range p.rels {
				br.Events = append(br.Events, r.Event)
				br.UnknownMust = append(br.UnknownMust, r.Event.UnknownMust...)
			}
			sortByTsProdSeq(br.Events)
			sortByTsSeq(br.Steps)
			sortByTsSeq(br.Summaries)
			if len(br.Events) > 0 {
				br.StartTsNs, br.EndTsNs = br.Events[0].TsNs, br.Events[0].TsNs
				for _, e := range br.Events {
					if e.TsNs < br.StartTsNs {
						br.StartTsNs = e.TsNs
					}
					if e.TsNs > br.EndTsNs {
						br.EndTsNs = e.TsNs
					}
				}
			}
			br.EndReason = leaf.EffectiveEndReason
			br.EndReasonName = endReasonName(br.EndReason)
			br.DropReason = leaf.DropReason

			// QSTATE annotations
			seenQS := map[*QStateAnnotation]bool{}
			for _, v := range br.Visits {
				for _, qs := range v.Backpressure {
					if !seenQS[qs] {
						seenQS[qs] = true
						br.QStates = append(br.QStates, qs)
					}
				}
			}
			touched := map[uint64]bool{}
			for _, l := range [][]*wire.Event{br.Steps, br.Summaries} {
				for _, e := range l {
					if ifx := e.U("ifindex"); ifx != 0 {
						touched[ifx] = true
					}
				}
			}
			tl := make([]uint64, 0, len(touched))
			for k := range touched {
				tl = append(tl, k)
			}
			sort.Slice(tl, func(i, j int) bool { return tl[i] < tl[j] })
			for _, ifx := range tl {
				for _, qs := range matchingQStates(s.QStates, ifx, OptU{}, br.StartTsNs, br.EndTsNs) {
					if !seenQS[qs] {
						seenQS[qs] = true
						br.QStates = append(br.QStates, qs)
					}
				}
			}
			sort.SliceStable(br.QStates, func(i, j int) bool { return br.QStates[i].StartNs < br.QStates[j].StartNs })

			for _, st := range br.Steps {
				if g := st.Stage(); g == wire.StageRequeueGSO || g == wire.StageRequeueBadTxq {
					br.RequeueCount++
				}
			}

			// Completeness
			var explicit, vc []string
			if len(br.UnknownMust) > 0 {
				explicit = append(explicit, "INCOMPLETE_UNKNOWN_MUST_TLV")
			}
			partial := partialManifest
			if !partial {
				for _, e := range br.Events {
					if e.Flags&wire.EvFlagPartialCoverage != 0 {
						partial = true
						break
					}
				}
			}
			if partial {
				explicit = append(explicit, "PARTIAL_COVERAGE")
			}
			for _, e := range br.Events {
				if e.Kind != wire.KindQuality && e.EvidenceLevel == wire.EvidenceGap {
					explicit = append(explicit, "EVIDENCE_GAP")
					break
				}
			}
			if idConflict {
				explicit = append(explicit, "IDENTITY_CONFLICT")
			}
			if br.SuccessorTruncated {
				explicit = append(explicit, "SUCCESSOR_TRUNCATED")
			}
			if ls.UncleanTail() {
				if br.EndReason == wire.EndOpen || br.EndTsNs > ls.LastQualityCheckpointTsNs {
					explicit = append(explicit, "UNKNOWN_TAIL")
					if br.EndReason == wire.EndOpen {
						br.EndReasonName = "UNKNOWN_TAIL"
					}
				}
			}
			switch br.EndReason {
			case wire.EndOpen:
				if !containsStr(explicit, "UNKNOWN_TAIL") {
					explicit = append(explicit, "OPEN_UNFINISHED")
				}
			case wire.EndTimeoutTruncated:
				explicit = append(explicit, "TIMEOUT_TRUNCATED")
			case wire.EndConflictTruncated:
				explicit = append(explicit, "CONFLICT_TRUNCATED")
			}
			for _, g := range s.SeqGaps {
				if seqGapOverlapsBranch(g, br) {
					explicit = append(explicit, "SEQ_GAP")
					break
				}
			}
			bset := map[uint64]bool{}
			for _, o := range oids {
				bset[o] = true
			}
			for _, lq := range loss {
				if lq.oid != 0 {
					if bset[lq.oid] && !containsStr(explicit, lq.name) {
						explicit = append(explicit, lq.name)
					}
				} else if br.StartTsNs <= lq.we && br.EndTsNs >= lq.ws && !containsStr(explicit, lq.name) {
					explicit = append(explicit, lq.name)
				}
			}
			for _, v := range br.Visits {
				if v.Ambiguous {
					vc = append(vc, "AMBIGUOUS_VISIT")
				} else if !v.Paired && !v.EnqDropped {
					vc = append(vc, "UNCLOSED_VISIT")
				}
			}
			for _, cp := range br.Calls {
				if cp.Ambiguous {
					vc = append(vc, "AMBIGUOUS_CALL")
				} else if !cp.Paired {
					vc = append(vc, "UNMATCHED_CALL_RETURN")
				}
			}
			switch {
			case len(explicit) > 0:
				br.Completeness, br.Complete = "incomplete", false
				br.GapReasons = dedupStrings(append(explicit, vc...))
			case s.HasUnobservableMissedSrc:
				br.Completeness, br.Complete = "unknown", false
				br.GapReasons = dedupStrings(append([]string{"UNOBSERVABLE_MISSED_SOURCE"}, vc...))
			case len(vc) > 0:
				br.Completeness, br.Complete = "incomplete", false
				br.GapReasons = dedupStrings(vc)
			default:
				br.Completeness, br.Complete = "complete", true
				br.GapReasons = []string{}
			}
			sbranches = append(sbranches, br)
			s.Branches = append(s.Branches, br)
		}

		sg := &SampleGraph{SampleID: sid, RootObjectIDs: roots, ObjectIDs: objList, Relations: sampleRels, Branches: sbranches}
		firstSet := false
		for _, oid := range objList {
			o := s.Objects[oid]
			if o.FirstTsNs > 0 && (!firstSet || o.FirstTsNs < sg.FirstTsNs) {
				sg.FirstTsNs, firstSet = o.FirstTsNs, true
			}
			if o.LastTsNs > sg.LastTsNs {
				sg.LastTsNs = o.LastTsNs
			}
			sg.Attr.mergeMissing(o.Attr)
			if o.SuccessorTruncated {
				sg.SuccessorTruncated = true
			}
			if o.UnknownPredecessors {
				sg.UnknownPredecessors = true
			}
		}
		sg.GapReasons = []string{}
		anyIncomplete, anyUnknown := false, false
		for _, br := range sbranches {
			for _, g := range br.GapReasons {
				if !containsStr(sg.GapReasons, g) {
					sg.GapReasons = append(sg.GapReasons, g)
				}
			}
			if br.SuccessorTruncated {
				sg.SuccessorTruncated = true
			}
			if br.UnknownPredecessors {
				sg.UnknownPredecessors = true
			}
			if br.Completeness == "incomplete" {
				anyIncomplete = true
			}
			if br.Completeness == "unknown" {
				anyUnknown = true
			}
		}
		switch {
		case anyIncomplete || sg.SuccessorTruncated:
			sg.Completeness, sg.Complete = "incomplete", false
		case anyUnknown || s.HasUnobservableMissedSrc:
			sg.Completeness, sg.Complete = "unknown", false
		default:
			sg.Completeness, sg.Complete = "complete", len(sbranches) > 0
		}
		s.Samples[sid] = sg
	}

	s.ReorderCount = s.computeReorderCount()
	s.RequeueCount = s.RequeueGSOCount + s.RequeueBadTxqCount
	return s
}

func orTs(v, def uint64) uint64 {
	if v == 0 {
		return def
	}
	return v
}

func endReasonName(r int) string {
	if n, ok := wire.EndReasonNames[r]; ok {
		return n
	}
	return fmt.Sprintf("END_%d", r)
}

func stageName(st int) string {
	if n, ok := wire.StageNames[st]; ok {
		return n
	}
	return fmt.Sprintf("STAGE_%d", st)
}
