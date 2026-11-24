// Package reconstruct is a pure-Go port of analyzer/reconstruct.py,
// stats.py and show.py: evidence-centric multi-branch DAG reconstruction, queue
// visit pairing, completeness evaluation and JSON-ready views for PktPath Studio.
package reconstruct

import (
	"fmt"
	"sort"
	"strconv"

	"pktpath/studio/pkg/wire"
)

// Linux return codes.
const (
	NetdevTxOK   = 0x00
	NetdevTxBusy = 0x10

	NetXmitSuccess = 0x00
	NetXmitDrop    = 0x01
	NetXmitCN      = 0x02
)

// SeqGap is a per-(producer, cpu) sequence discontinuity.
type SeqGap struct {
	ProducerType uint16
	CPU          uint32
	PrevSeq      uint64
	NextSeq      uint64
	MissingCount uint64
	WinStartNs   uint64
	WinEndNs     uint64
	PrevObjectID uint64
	NextObjectID uint64
}

// CallPair is an entry/return call pairing by call_id.
type CallPair struct {
	CallID       uint64
	ObjectID     uint64
	Entry        *wire.Event
	Ret          *wire.Event
	Paired       bool
	Ambiguous    bool
	RawRet       OptU
	CrossCPULate bool
}

// QStateAnnotation is a TXQ STOP→WAKE span or BQL/standalone qstate.
type QStateAnnotation struct {
	Ifindex   uint64
	Txq       uint64
	QueueGen  uint64
	StateOp   int
	StateName string
	StartNs   uint64
	EndNs     OptU
	Value     uint64
	EventIDs  []string
}

// QueueVisit is one paired (object_id, queue_gen, visit_id) queue residency.
type QueueVisit struct {
	ObjectID           uint64
	QueueGen           uint64
	VisitID            uint64
	VisitKind          string // qdisc | requeue_gso | requeue_bad_txq
	NetnsInum          uint64
	Ifindex            uint64
	DevGen             uint64
	QdiscHandle        uint64
	QdiscParent        uint64
	Classid            uint64
	Bucket             OptU
	Txq                OptU
	Entry              *wire.Event
	EnqRet             *wire.Event
	Exit               *wire.Event
	Paired             bool
	Ambiguous          bool
	EnqDropped         bool
	EnqCN              bool
	EnqRetCode         *int64
	SojournNs          *uint64
	CrossThreadDequeue bool
	Backpressure       []*QStateAnnotation
}

// SojournUs returns the sojourn in microseconds (nil when unpaired).
func (v *QueueVisit) SojournUs() *float64 {
	if v.SojournNs == nil {
		return nil
	}
	f := float64(*v.SojournNs) / 1000.0
	return &f
}

// Relation is one decoded RELATION edge.
type Relation struct {
	Event               *wire.Event
	OpID                uint64
	RelType             int
	RelTypeName         string
	SrcObjectID         uint64
	DstObjectID         uint64
	RelFlags            uint64
	SuccessorTruncated  bool
	UnknownPredecessors bool
	StreamOffset        OptU
	SpanLen             OptU
	TsNs                uint64
}

// Attribution carries L1 pure-Linux ownership info plus optional sock plugin values.
type Attribution struct {
	UID         *uint64        `json:"uid,omitempty"`
	Tgid        *uint64        `json:"tgid,omitempty"`
	Comm        *string        `json:"comm,omitempty"`
	EnqueueTid  *uint64        `json:"enqueue_tid,omitempty"`
	SkbCreateTs *uint64        `json:"skb_create_ts,omitempty"`
	PluginVals  map[int]uint64 `json:"plugin_vals,omitempty"`
	InTask      *bool          `json:"in_task,omitempty"`
	XmitTid     *uint64        `json:"xmit_tid,omitempty"`
	XmitInTask  *bool          `json:"xmit_in_task,omitempty"`
}

func (a *Attribution) mergeMissing(o Attribution) {
	if a.UID == nil {
		a.UID = o.UID
	}
	if a.Tgid == nil {
		a.Tgid = o.Tgid
	}
	if a.Comm == nil {
		a.Comm = o.Comm
	}
	if a.EnqueueTid == nil {
		a.EnqueueTid = o.EnqueueTid
	}
	if a.SkbCreateTs == nil {
		a.SkbCreateTs = o.SkbCreateTs
	}
	if len(o.PluginVals) > 0 {
		if a.PluginVals == nil {
			a.PluginVals = map[int]uint64{}
		}
		for slot, val := range o.PluginVals {
			if _, exists := a.PluginVals[slot]; !exists {
				a.PluginVals[slot] = val
			}
		}
	}
	if a.InTask == nil {
		a.InTask = o.InTask
	}
	if a.XmitTid == nil {
		a.XmitTid = o.XmitTid
	}
	if a.XmitInTask == nil {
		a.XmitInTask = o.XmitInTask
	}
}

// ObjectNode is one tracked object (skb, app msg, ...).
type ObjectNode struct {
	ObjectID            uint64
	ObjectType          uint8
	SampleIDs           map[uint64]bool
	PrimarySampleID     uint64
	ObjectEvents        []*wire.Event
	Steps               []*wire.Event
	Summaries           []*wire.Event
	Visits              []*QueueVisit
	Calls               []*CallPair
	Outgoing            []*Relation
	Incoming            []*Relation
	ExplicitEndReason   int
	EffectiveEndReason  int
	DropReason          OptU
	UnknownMust         []wire.UnknownTLV
	UnknownOptional     []wire.UnknownTLV
	SuccessorTruncated  bool
	UnknownPredecessors bool
	IdentityConflict    bool
	Attr                Attribution
	FirstTsNs           uint64
	LastTsNs            uint64
}

// InitialSummary is the first SUMMARY of the object.
func (o *ObjectNode) InitialSummary() *wire.Event {
	if len(o.Summaries) == 0 {
		return nil
	}
	return o.Summaries[0]
}

// LatestSummary is the last SUMMARY of the object.
func (o *ObjectNode) LatestSummary() *wire.Event {
	if len(o.Summaries) == 0 {
		return nil
	}
	return o.Summaries[len(o.Summaries)-1]
}

// ObjectSlice is a (object_id, min_ts, max_ts|None) branch slice.
type ObjectSlice struct {
	ObjectID uint64
	MinTs    uint64
	MaxTs    OptU
}

// BranchPath is one root-to-leaf path through the sample DAG.
type BranchPath struct {
	BranchID            string
	SampleID            uint64
	BranchIndex         int
	ObjectIDs           []uint64
	Slices              []ObjectSlice
	RelationChain       []*Relation
	Events              []*wire.Event
	Steps               []*wire.Event
	Summaries           []*wire.Event
	Visits              []*QueueVisit
	Calls               []*CallPair
	QStates             []*QStateAnnotation
	Tcpdump             []*TcpdumpCandidate
	EndReason           int
	EndReasonName       string
	DropReason          OptU
	Complete            bool
	Completeness        string
	GapReasons          []string
	UnknownMust         []wire.UnknownTLV
	SuccessorTruncated  bool
	UnknownPredecessors bool
	RequeueCount        int
	StartTsNs           uint64
	EndTsNs             uint64
}

// LeafObjectID is the last object of the branch.
func (b *BranchPath) LeafObjectID() uint64 { return b.ObjectIDs[len(b.ObjectIDs)-1] }

// SampleGraph is one sample (root admission) and its branches.
type SampleGraph struct {
	SampleID            uint64
	RootObjectIDs       []uint64
	ObjectIDs           []uint64
	Relations           []*Relation
	Branches            []*BranchPath
	Complete            bool
	Completeness        string
	GapReasons          []string
	SuccessorTruncated  bool
	UnknownPredecessors bool
	Attr                Attribution
	FirstTsNs           uint64
	LastTsNs            uint64
}

// Session is the fully reconstructed session (ReconstructedSession in Python).
type Session struct {
	Loaded                     *wire.LoadedSession
	Manifest                   map[string]any
	Dict                       map[string]any
	Events                     []*wire.Event
	DedupDropped               int
	SeqGaps                    []SeqGap
	QualityEvents              []*wire.Event
	QStateEvents               []*wire.Event
	QStates                    []*QStateAnnotation
	Objects                    map[uint64]*ObjectNode
	ObjectOrder                []uint64 // insertion order (Python dict order)
	Relations                  []*Relation
	Samples                    map[uint64]*SampleGraph
	SampleOrder                []uint64 // ascending sample ids
	Branches                   []*BranchPath
	UnmatchedReturns           []*wire.Event
	HasUnobservableMissedSrc   bool
	UnobservableAdapters       []string
	TopoDesyncWindows          [][2]uint64
	RequeueCount               int
	RequeueGSOCount            int
	RequeueBadTxqCount         int
	ReorderCount               int

	sites  map[int64]*Site
	topo   []topoEpoch
	calibs []calibration
}

// Open loads and reconstructs a session directory (crash-tolerant tail).
func Open(dir string) (*Session, error) {
	ls, err := wire.LoadSession(dir, false)
	if err != nil {
		return nil, err
	}
	return Reconstruct(ls), nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func dedupAndDetectSeqGaps(raw []*wire.Event) ([]*wire.Event, int, []SeqGap) {
	seen := map[wire.DedupKey]bool{}
	var deduped []*wire.Event
	dropped := 0
	type streamKey struct {
		p uint16
		c uint32
	}
	byStream := map[streamKey][]*wire.Event{}
	for _, ev := range raw {
		k := ev.DedupKey()
		if seen[k] {
			dropped++
			continue
		}
		seen[k] = true
		deduped = append(deduped, ev)
		sk := streamKey{ev.ProducerType, ev.CPU}
		byStream[sk] = append(byStream[sk], ev)
	}
	keys := make([]streamKey, 0, len(byStream))
	for k := range byStream {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].p != keys[j].p {
			return keys[i].p < keys[j].p
		}
		return keys[i].c < keys[j].c
	})
	var gaps []SeqGap
	for _, k := range keys {
		evs := append([]*wire.Event(nil), byStream[k]...)
		sort.SliceStable(evs, func(i, j int) bool { return evs[i].Seq < evs[j].Seq })
		for i := 1; i < len(evs); i++ {
			p, c := evs[i-1], evs[i]
			if c.Seq > p.Seq+1 {
				gaps = append(gaps, SeqGap{
					ProducerType: k.p, CPU: k.c, PrevSeq: p.Seq, NextSeq: c.Seq,
					MissingCount: c.Seq - p.Seq - 1, WinStartNs: p.TsNs, WinEndNs: c.TsNs,
					PrevObjectID: p.ObjectID, NextObjectID: c.ObjectID,
				})
			}
		}
	}
	sort.SliceStable(deduped, func(i, j int) bool {
		a, b := deduped[i], deduped[j]
		if a.TsNs != b.TsNs {
			return a.TsNs < b.TsNs
		}
		if a.ProducerType != b.ProducerType {
			return a.ProducerType < b.ProducerType
		}
		return a.Seq < b.Seq
	})
	return deduped, dropped, gaps
}

func sortByTsSeq(evs []*wire.Event) {
	sort.SliceStable(evs, func(i, j int) bool {
		if evs[i].TsNs != evs[j].TsNs {
			return evs[i].TsNs < evs[j].TsNs
		}
		return evs[i].Seq < evs[j].Seq
	})
}

func sortByTsProdSeq(evs []*wire.Event) {
	sort.SliceStable(evs, func(i, j int) bool {
		a, b := evs[i], evs[j]
		if a.TsNs != b.TsNs {
			return a.TsNs < b.TsNs
		}
		if a.ProducerType != b.ProducerType {
			return a.ProducerType < b.ProducerType
		}
		return a.Seq < b.Seq
	})
}

func buildQStateAnnotations(evs []*wire.Event) []*QStateAnnotation {
	sorted := append([]*wire.Event(nil), evs...)
	sortByTsSeq(sorted)
	var out []*QStateAnnotation
	type key struct{ ifidx, txq uint64 }
	open := map[key]*QStateAnnotation{}
	var openOrder []key
	removeOpen := func(k key) {
		delete(open, k)
		for i, ok := range openOrder {
			if ok == k {
				openOrder = append(openOrder[:i], openOrder[i+1:]...)
				break
			}
		}
	}
	for _, ev := range sorted {
		ifidx, txq, qgen := ev.U("ifindex"), ev.U("txq"), ev.U("queue_gen")
		op, val := int(ev.U("state_op")), ev.U("value")
		k := key{ifidx, txq}
		switch op {
		case wire.QStateTxqStop:
			if a, ok := open[k]; ok {
				out = append(out, a)
				removeOpen(k)
			}
			open[k] = &QStateAnnotation{Ifindex: ifidx, Txq: txq, QueueGen: qgen, StateOp: op,
				StateName: "TXQ_STOP_WAKE", StartNs: ev.TsNs, Value: val, EventIDs: []string{ev.EventID()}}
			openOrder = append(openOrder, k)
		case wire.QStateTxqWake:
			if a, ok := open[k]; ok {
				removeOpen(k)
				a.EndNs = Some(ev.TsNs)
				a.EventIDs = append(a.EventIDs, ev.EventID())
				out = append(out, a)
			} else {
				out = append(out, &QStateAnnotation{Ifindex: ifidx, Txq: txq, QueueGen: qgen, StateOp: op,
					StateName: "TXQ_WAKE", StartNs: ev.TsNs, EndNs: Some(ev.TsNs), Value: val, EventIDs: []string{ev.EventID()}})
			}
		default:
			name, ok := wire.QStateOpNames[op]
			if !ok {
				name = "QSTATE_" + itoa(op)
			}
			out = append(out, &QStateAnnotation{Ifindex: ifidx, Txq: txq, QueueGen: qgen, StateOp: op,
				StateName: name, StartNs: ev.TsNs, EndNs: Some(ev.TsNs), Value: val, EventIDs: []string{ev.EventID()}})
		}
	}
	for _, k := range openOrder {
		out = append(out, open[k])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].StartNs < out[j].StartNs })
	return out
}

func matchingQStates(all []*QStateAnnotation, ifindex uint64, txq OptU, ws, we uint64) []*QStateAnnotation {
	var out []*QStateAnnotation
	for _, qs := range all {
		if ifindex != 0 && qs.Ifindex != 0 && qs.Ifindex != ifindex {
			continue
		}
		if txq.OK && qs.Txq != txq.V {
			continue
		}
		qend := we
		if qs.EndNs.OK {
			qend = qs.EndNs.V
		}
		if qs.StartNs <= we && qend >= ws {
			out = append(out, qs)
		}
	}
	return out
}

var entryCallStages = map[int]bool{
	wire.StageQdiscEnq: true, wire.StageRequeueGSO: true, wire.StageRequeueBadTxq: true,
	wire.StageXmitStart: true, wire.StageClassify: true, wire.StageEntry: true, wire.StageHandoffLayer: true,
}
var retCallStages = map[int]bool{wire.StageQdiscEnqRet: true, wire.StageXmitRet: true}
var visitEntryStages = map[int]string{
	wire.StageQdiscEnq: "qdisc", wire.StageRequeueGSO: "requeue_gso", wire.StageRequeueBadTxq: "requeue_bad_txq",
}

type ocKey struct{ oid, cid uint64 }
type visitKey struct{ qgen, vid uint64 }

func (s *Session) pairCallsAndVisits() []*wire.Event {
	var unmatched []*wire.Event
	byID := map[uint64][]*CallPair{}
	byObj := map[ocKey][]*CallPair{}
	objects := s.Objects

	for _, oid := range s.ObjectOrder {
		obj := objects[oid]
		for _, st := range obj.Steps {
			stage := st.Stage()
			if stage == wire.StageClassify && st.Has("raw_ret") {
				continue
			}
			cid, ok := st.Get("call_id")
			if ok && cid > 0 && entryCallStages[stage] {
				cp := &CallPair{CallID: cid, ObjectID: oid, Entry: st}
				obj.Calls = append(obj.Calls, cp)
				byID[cid] = append(byID[cid], cp)
				byObj[ocKey{oid, cid}] = append(byObj[ocKey{oid, cid}], cp)
			}
		}
	}

	for _, oid := range s.ObjectOrder {
		obj := objects[oid]
		var reassigned []*wire.Event
		steps := obj.Steps
		for i := 0; i < len(steps); i++ {
			st := steps[i]
			if !retCallStages[st.Stage()] {
				reassigned = append(reassigned, st)
				continue
			}
			cid, ok := st.Get("call_id")
			if !ok || cid == 0 {
				reassigned = append(reassigned, st)
				continue
			}
			cands := byObj[ocKey{oid, cid}]
			if len(cands) == 0 {
				global := byID[cid]
				if len(global) == 1 {
					cands = global
					target := global[0].ObjectID
					if target != oid {
						objects[target].Steps = append(objects[target].Steps, st)
					} else {
						reassigned = append(reassigned, st)
					}
				} else {
					unmatched = append(unmatched, st)
					continue
				}
			} else {
				reassigned = append(reassigned, st)
			}
			if len(cands) != 1 || cands[0].Ret != nil {
				for _, c := range cands {
					c.Ambiguous = true
					c.Paired = false
				}
				unmatched = append(unmatched, st)
			} else {
				cp := cands[0]
				cp.Ret = st
				cp.Paired = true
				cp.RawRet = evOpt(st, "raw_ret")
			}
		}
		obj.Steps = reassigned
	}

	for _, oid := range s.ObjectOrder {
		obj := objects[oid]
		sortByTsSeq(obj.Steps)
		for _, cp := range obj.Calls {
			if cp.Paired && cp.Entry != nil && cp.Ret != nil {
				for _, other := range obj.Steps {
					if other == cp.Entry || other == cp.Ret {
						continue
					}
					if cp.Entry.TsNs <= other.TsNs && other.TsNs <= cp.Ret.TsNs && other.CPU != cp.Entry.CPU {
						cp.CrossCPULate = true
						break
					}
				}
			}
		}
	}

	type entrySig struct{ netns, ifidx, devGen, dir uint64 }
	for _, oid := range s.ObjectOrder {
		obj := objects[oid]
		seen := map[entrySig]bool{}
		handoff := false
		for _, st := range obj.Steps {
			switch st.Stage() {
			case wire.StageHandoffLayer:
				handoff = true
			case wire.StageEntry:
				sig := entrySig{st.U("netns_inum"), st.U("ifindex"), st.U("dev_gen"), st.U("dir")}
				if seen[sig] && !handoff {
					obj.IdentityConflict = true
				}
				seen[sig] = true
				handoff = false
			}
		}
	}

	for _, oid := range s.ObjectOrder {
		if oid == 0 {
			continue
		}
		obj := objects[oid]
		entries := map[visitKey][]*wire.Event{}
		type qgEv struct {
			qgen uint64
			ev   *wire.Event
		}
		entriesByVid := map[uint64][]qgEv{}
		enqRets := map[visitKey][]*wire.Event{}
		exits := map[visitKey][]*wire.Event{}
		var unkeyedExits []*wire.Event
		callMap := map[uint64]*CallPair{}
		for _, cp := range obj.Calls {
			if !cp.Ambiguous {
				callMap[cp.CallID] = cp
			}
		}
		knownTxq := OptU{}
		for _, st := range obj.Steps {
			stg := st.Stage()
			if t, ok := st.Get("txq"); ok && (stg == wire.StageXmitStart || stg == wire.StageQdiscEnq || stg == wire.StageQdiscDeq) {
				knownTxq = Some(t)
				break
			}
		}
		var keyOrder []visitKey
		seenKey := map[visitKey]bool{}
		noteKey := func(k visitKey) {
			if !seenKey[k] {
				seenKey[k] = true
				keyOrder = append(keyOrder, k)
			}
		}
		for _, st := range obj.Steps {
			stage := st.Stage()
			vid, ok := st.Get("visit_id")
			if !ok || vid == 0 {
				continue
			}
			qraw, hasQ := st.Get("queue_gen")
			k := visitKey{qraw, vid}
			if _, isEntry := visitEntryStages[stage]; isEntry {
				entries[k] = append(entries[k], st)
				entriesByVid[vid] = append(entriesByVid[vid], qgEv{qraw, st})
				noteKey(k)
			} else if stage == wire.StageQdiscEnqRet {
				enqRets[k] = append(enqRets[k], st)
			} else if stage == wire.StageQdiscDeq || stage == wire.StageDrop {
				if !hasQ || qraw == 0 {
					unkeyedExits = append(unkeyedExits, st)
				} else {
					exits[k] = append(exits[k], st)
					noteKey(k)
				}
			}
		}
		ambiguousVids := map[uint64]bool{}
		for _, ex := range unkeyedExits {
			vid := ex.U("visit_id")
			cands := entriesByVid[vid]
			uniq := map[uint64]bool{}
			for _, c := range cands {
				uniq[c.qgen] = true
			}
			if len(uniq) == 1 {
				var only uint64
				for q := range uniq {
					only = q
				}
				k := visitKey{only, vid}
				exits[k] = append(exits[k], ex)
				noteKey(k)
			} else if len(uniq) > 1 {
				ambiguousVids[vid] = true
			} else {
				k := visitKey{0, vid}
				exits[k] = append(exits[k], ex)
				noteKey(k)
			}
		}
		refTs := func(k visitKey) uint64 {
			if l := entries[k]; len(l) > 0 {
				return l[0].TsNs
			}
			return exits[k][0].TsNs
		}
		// Python sorts the key set by (first_ts, visit_id); qgen breaks any remaining tie deterministically.
		sort.SliceStable(keyOrder, func(i, j int) bool {
			ti, tj := refTs(keyOrder[i]), refTs(keyOrder[j])
			if ti != tj {
				return ti < tj
			}
			if keyOrder[i].vid != keyOrder[j].vid {
				return keyOrder[i].vid < keyOrder[j].vid
			}
			return keyOrder[i].qgen < keyOrder[j].qgen
		})

		enqueueTid := obj.Attr.EnqueueTid
		for _, k := range keyOrder {
			en := entries[k]
			ex := exits[k]
			var ref *wire.Event
			if len(en) > 0 {
				ref = en[0]
			} else {
				ref = ex[0]
			}
			refStage := ref.Stage()
			if !ref.Has("stage") || refStage == 0 {
				refStage = wire.StageQdiscEnq
			}
			vkind, ok := visitEntryStages[refStage]
			if !ok {
				vkind = "qdisc"
			}
			v := &QueueVisit{
				ObjectID: oid, QueueGen: k.qgen, VisitID: k.vid, VisitKind: vkind,
				NetnsInum: ref.U("netns_inum"), Ifindex: ref.U("ifindex"), DevGen: ref.U("dev_gen"),
				QdiscHandle: ref.U("qdisc_handle"), QdiscParent: ref.U("qdisc_parent"), Classid: ref.U("classid"),
				Bucket: evOpt(ref, "bucket"), Txq: evOpt(ref, "txq"),
			}
			if len(en) == 1 {
				v.Entry = en[0]
			}
			if len(ex) == 1 {
				v.Exit = ex[0]
			}
			if ambiguousVids[k.vid] || len(en) > 1 || len(ex) > 1 {
				v.Ambiguous = true
			}
			if v.Entry != nil {
				var retEv *wire.Event
				cid, hasCid := v.Entry.Get("call_id")
				if cp, inMap := callMap[cid]; hasCid && inMap {
					retEv = cp.Ret
				} else if l := enqRets[k]; len(l) == 1 {
					retEv = l[0]
				}
				if retEv != nil {
					v.EnqRet = retEv
					if rc, ok := retEv.I("raw_ret"); ok {
						rcv := rc
						v.EnqRetCode = &rcv
						if rc == NetXmitDrop || rc < 0 {
							v.EnqDropped = true
						} else if rc == NetXmitCN {
							v.EnqCN = true
						}
					}
				}
			}
			if !v.Ambiguous && !v.EnqDropped && v.Entry != nil && v.Exit != nil {
				if v.Exit.TsNs >= v.Entry.TsNs {
					d := v.Exit.TsNs - v.Entry.TsNs
					v.Paired = true
					v.SojournNs = &d
					if enqueueTid != nil && *enqueueTid != 0 {
						if exTid, ok := v.Exit.Get("ctx_tid"); ok && exTid != *enqueueTid {
							v.CrossThreadDequeue = true
						}
					}
				}
			}
			ws := ref.TsNs
			if v.Entry != nil {
				ws = v.Entry.TsNs
			}
			we := obj.LastTsNs
			if ws > we {
				we = ws
			}
			if v.Exit != nil {
				we = v.Exit.TsNs
			}
			txqFilter := v.Txq
			if !txqFilter.OK {
				txqFilter = knownTxq
			}
			v.Backpressure = matchingQStates(s.QStates, v.Ifindex, txqFilter, ws, we)
			obj.Visits = append(obj.Visits, v)
		}
	}
	return unmatched
}

func u64p(v uint64) *uint64 { return &v }
func boolp(v bool) *bool    { return &v }
func strp(v string) *string { return &v }

func extractAttribution(obj *ObjectNode) Attribution {
	var a Attribution
	for _, sm := range obj.Summaries {
		if v, ok := sm.Get("uid"); ok && a.UID == nil {
			a.UID = u64p(v)
		}
		if v, ok := sm.Get("tgid"); ok && a.Tgid == nil {
			a.Tgid = u64p(v)
		}
		if v, ok := sm.Str("comm"); ok && a.Comm == nil {
			a.Comm = strp(v)
		}
		if v, ok := sm.Get("enqueue_tid"); ok && a.EnqueueTid == nil {
			a.EnqueueTid = u64p(v)
		}
		if v, ok := sm.Get("skb_create_ts"); ok && a.SkbCreateTs == nil {
			a.SkbCreateTs = u64p(v)
		}
		for slot := 0; slot < 4; slot++ {
			k := fmt.Sprintf("plugin_val%d", slot)
			if v, ok := sm.Get(k); ok {
				if a.PluginVals == nil {
					a.PluginVals = map[int]uint64{}
				}
				if _, exists := a.PluginVals[slot]; !exists {
					a.PluginVals[slot] = v
				}
			}
		}
		if a.InTask == nil {
			a.InTask = boolp(sm.Flags&wire.EvFlagInTask != 0)
		}
	}
	for _, st := range obj.Steps {
		switch st.Stage() {
		case wire.StageEntry:
			if v, ok := st.Get("ctx_tid"); ok && a.EnqueueTid == nil {
				a.EnqueueTid = u64p(v)
			}
			if a.InTask == nil {
				a.InTask = boolp(st.Flags&wire.EvFlagInTask != 0)
			}
		case wire.StageXmitStart:
			if v, ok := st.Get("ctx_tid"); ok {
				a.XmitTid = u64p(v)
				a.XmitInTask = boolp(st.Flags&wire.EvFlagInTask != 0)
			}
		}
	}
	return a
}

func computeEffectiveEndReason(obj *ObjectNode) int {
	if obj.ExplicitEndReason != wire.EndOpen {
		return obj.ExplicitEndReason
	}
	for _, r := range obj.Outgoing {
		if r.RelType != wire.RelClone && r.RelType != wire.RelCopy {
			return wire.EndConsume
		}
	}
	for i := len(obj.Steps) - 1; i >= 0; i-- {
		st := obj.Steps[i]
		switch st.Stage() {
		case wire.StageXmitRet:
			rc, ok := st.I("raw_ret")
			if !ok || rc == NetdevTxOK {
				return wire.EndTxOK
			}
		case wire.StageDrop:
			return wire.EndDrop
		case wire.StageConsume:
			return wire.EndConsume
		case wire.StageDeliverSock:
			return wire.EndSockEnqueue
		}
	}
	return wire.EndOpen
}

func seqGapOverlapsBranch(g SeqGap, b *BranchPath) bool {
	if g.PrevObjectID != 0 {
		for _, oid := range b.ObjectIDs {
			if oid == g.PrevObjectID {
				if g.WinStartNs <= b.EndTsNs {
					return true
				}
				break
			}
		}
	}
	var minSeq, maxSeq uint64
	found := false
	for _, e := range b.Events {
		if e.ProducerType == g.ProducerType && e.CPU == g.CPU {
			if !found {
				minSeq, maxSeq, found = e.Seq, e.Seq, true
			} else {
				if e.Seq < minSeq {
					minSeq = e.Seq
				}
				if e.Seq > maxSeq {
					maxSeq = e.Seq
				}
			}
		}
	}
	if found {
		if minSeq >= g.NextSeq && b.StartTsNs >= g.WinEndNs {
			return false
		}
		if maxSeq <= g.PrevSeq && b.EndTsNs < g.WinStartNs {
			return false
		}
		if minSeq <= g.PrevSeq && maxSeq >= g.NextSeq {
			return true
		}
	}
	return b.StartTsNs < g.WinEndNs && b.EndTsNs >= g.WinStartNs
}

type tsSeq struct{ ts, seq uint64 }

func lessTS(a, b tsSeq) bool {
	if a.ts != b.ts {
		return a.ts < b.ts
	}
	return a.seq < b.seq
}

func (s *Session) computeReorderCount() int {
	type portKey struct{ netns, ifidx, dir uint64 }
	type pair struct{ entry, depart tsSeq }
	per := map[portKey][]pair{}
	var portOrder []portKey
	for _, oid := range s.ObjectOrder {
		obj := s.Objects[oid]
		if obj == nil || obj.ObjectType != wire.ObjSKB {
			continue
		}
		var entry, depart *wire.Event
		for _, st := range obj.Steps {
			stg := st.Stage()
			if stg == wire.StageEntry && entry == nil {
				entry = st
			} else if (stg == wire.StageQdiscDeq || stg == wire.StageXmitStart) && depart == nil {
				depart = st
			}
		}
		if entry != nil && depart != nil {
			k := portKey{entry.U("netns_inum"), entry.U("ifindex"), entry.U("dir")}
			if _, ok := per[k]; !ok {
				portOrder = append(portOrder, k)
			}
			per[k] = append(per[k], pair{tsSeq{entry.TsNs, entry.Seq}, tsSeq{depart.TsNs, depart.Seq}})
		}
	}
	total := 0
	for _, k := range portOrder {
		items := per[k]
		if len(items) < 2 {
			continue
		}
		byEntry := append([]pair(nil), items...)
		sort.SliceStable(byEntry, func(i, j int) bool { return lessTS(byEntry[i].entry, byEntry[j].entry) })
		type ranked struct {
			rank   int
			depart tsSeq
		}
		rs := make([]ranked, len(byEntry))
		for i, p := range byEntry {
			rs[i] = ranked{i, p.depart}
		}
		sort.SliceStable(rs, func(i, j int) bool { return lessTS(rs[i].depart, rs[j].depart) })
		maxSeen := -1
		for _, r := range rs {
			if r.rank < maxSeen {
				total++
			} else {
				maxSeen = r.rank
			}
		}
	}
	return total
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func itoa(i int) string { return strconv.Itoa(i) }
