package reconstruct

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"pktpath/studio/pkg/wire"
)

// Admissions holds all 5 entry-admission denominators.
type Admissions struct {
	FilterUnknown int64 `json:"filter_unknown"`
	Matched       int64 `json:"matched"`
	Selected      int64 `json:"selected"`
	Created       int64 `json:"created"`
	Rejected      int64 `json:"rejected"`
}

// BranchCounts is the completeness breakdown.
type BranchCounts struct {
	Total               int `json:"total"`
	Complete            int `json:"complete"`
	Incomplete          int `json:"incomplete"`
	Unknown             int `json:"unknown"`
	UnknownCompleteness int `json:"unknown_completeness"`
}

// SampleCounts mirrors stats.py "samples".
type SampleCounts struct {
	Total        int `json:"total"`
	ObjectsTotal int `json:"objects_total"`
	EventsTotal  int `json:"events_total"`
	DedupDropped int `json:"dedup_dropped"`
}

// QueueStat is a per-queue-instance paired sojourn summary.
type QueueStat struct {
	Label        string   `json:"label"`
	Kind         string   `json:"kind"`
	VisitKind    string   `json:"visit_kind"`
	Handle       string   `json:"handle"`
	Parent       string   `json:"parent"`
	ClassID      string   `json:"class_id,omitempty"`
	ClassRate    string   `json:"class_rate,omitempty"`
	ClassRateBps *uint64  `json:"class_rate_bps,omitempty"`
	ClassCeilBps *uint64  `json:"class_ceil_bps,omitempty"`
	ClassPrio    *int64   `json:"class_prio,omitempty"`
	QueueGen     uint64   `json:"queue_gen"`
	NetnsInum    uint64   `json:"netns_inum"`
	Ifindex      uint64   `json:"ifindex"`
	DevGen       uint64   `json:"dev_gen"`
	DevName      string   `json:"dev_name"`
	Txq          *uint64  `json:"txq"`
	N            int      `json:"n"`
	PairedN      int      `json:"paired_n"`
	UnpairedN    int      `json:"unpaired_n"`
	EnqDropN     int      `json:"enq_drop_n"`
	DropCount    int      `json:"drop_count"`
	P50Us        *float64 `json:"p50_us"`
	P95Us        *float64 `json:"p95_us"`
	P99Us        *float64 `json:"p99_us"`
	MinUs        *float64 `json:"min_us"`
	MaxUs        *float64 `json:"max_us"`
	MeanUs       *float64 `json:"mean_us"`
}

// PathGroup aggregates branches sharing the same path signature.
type PathGroup struct {
	PathSig             string         `json:"path_sig"`
	Tokens              []string       `json:"tokens"`
	Endpoint            string         `json:"endpoint"`
	Count               int            `json:"count"`
	CompleteCount       int            `json:"complete_count"`
	IncompleteCount     int            `json:"incomplete_count"`
	UnknownCount        int            `json:"unknown_count"`
	P50Us               *float64       `json:"p50_us"`
	P95Us               *float64       `json:"p95_us"`
	P99Us               *float64       `json:"p99_us"`
	SojournP50Us        *float64       `json:"sojourn_p50_us"`
	SojournP95Us        *float64       `json:"sojourn_p95_us"`
	SojournP99Us        *float64       `json:"sojourn_p99_us"`
	WireBytes           int64          `json:"wire_bytes"`
	SkbBytes            int64          `json:"skb_bytes"`
	Endpoints           map[string]int `json:"endpoints"`
	SampleIDs           []uint64       `json:"sample_ids"`
}

// Group is a generic cohort group (stats.py "groups").
type Group struct {
	Key                 string         `json:"key"`
	BranchCount         int            `json:"branch_count"`
	Complete            int            `json:"complete"`
	Incomplete          int            `json:"incomplete"`
	UnknownCompleteness int            `json:"unknown_completeness"`
	SkbBytes            int64          `json:"skb_bytes"`
	WireBytes           int64          `json:"wire_bytes"`
	Endpoints           map[string]int `json:"endpoints"`
}

// QualitySummary mirrors stats.py "quality".
type QualitySummary struct {
	SeqGapWindows            int    `json:"seq_gap_windows"`
	SeqGapMissingEvents      uint64 `json:"seq_gap_missing_events"`
	MissedDelta              uint64 `json:"missed_delta"`
	RbDropDelta              uint64 `json:"rb_drop_delta"`
	RetUnmatched             uint64 `json:"ret_unmatched"`
	IdentityConflict         uint64 `json:"identity_conflict"`
	TopoDesync               uint64 `json:"topo_desync"`
	UncleanTail              bool   `json:"unclean_tail"`
	UnobservableMissedSource bool   `json:"unobservable_missed_source"`
}

// QualityAlert is one human-facing quality warning.
type QualityAlert struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"` // info | warn | error
	Count    uint64 `json:"count"`
	Message  string `json:"message"`
}

// Stats is the session-wide statistics block.
type Stats struct {
	SessionUUID        string         `json:"session_uuid"`
	Scope              string         `json:"scope"`
	Mode               string         `json:"mode"`
	SampleRate         string         `json:"sample_rate"`
	GroupBy            string         `json:"group_by"`
	Admissions         Admissions     `json:"admissions"`
	SampleCounts       SampleCounts   `json:"samples"`
	Branches           BranchCounts   `json:"branches"`
	Endpoints          map[string]int `json:"endpoints"`
	RequeueCount       int            `json:"requeue_count"`
	RequeueGSOCount    int            `json:"requeue_gso_count"`
	RequeueBadTxqCount int            `json:"requeue_bad_txq_count"`
	ReorderCount       int            `json:"reorder_count"`
	SkbBytes           int64          `json:"skb_bytes"`
	WireBytes          int64          `json:"wire_bytes"`
	SkbPackets         int            `json:"skb_packets"`
	WirePackets        int            `json:"wire_packets"`
	Queues             []QueueStat    `json:"queues"`
	Paths              []PathGroup    `json:"paths"`
	Groups             []Group        `json:"groups"`
	Quality            QualitySummary `json:"quality"`
	UncleanTail        bool           `json:"unclean_tail"`
	TailErrors         []string       `json:"tail_errors"`
	QualityAlerts      []QualityAlert `json:"quality_alerts"`
}

func round3(x float64) float64 { return math.Round(x*1000) / 1000 }

// Percentile implements stats.py `_percentile` (linear interpolation, rounded to 3 dp).
func Percentile(sorted []float64, pct float64) *float64 {
	if len(sorted) == 0 {
		return nil
	}
	if len(sorted) == 1 {
		v := round3(sorted[0])
		return &v
	}
	rank := pct / 100.0 * float64(len(sorted)-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	var v float64
	if lo == hi {
		v = round3(sorted[lo])
	} else {
		w := rank - float64(lo)
		v = round3(sorted[lo]*(1-w) + sorted[hi]*w)
	}
	return &v
}

func f64p(v float64) *float64 { return &v }

// BranchPathSignature is stats.py `_branch_path_signature`.
func (s *Session) BranchPathSignature(br *BranchPath) string {
	return strings.Join(s.branchPathTokens(br), " -> ")
}

func (s *Session) branchPathTokens(br *BranchPath) []string {
	var tokens []string
	push := func(tok string) {
		if len(tokens) == 0 || tokens[len(tokens)-1] != tok {
			tokens = append(tokens, tok)
		}
	}
	for _, st := range br.Steps {
		stage := st.Stage()
		ifidx := st.U("ifindex")
		dev := s.ResolveDevName(ifidx, evOpt(st, "dev_gen"), OptU{})
		switch stage {
		case wire.StageEntry:
			tokens = append(tokens, "ENTRY("+dev+")")
		case wire.StageClassify, wire.StageQdiscEnq:
			qhandle := st.U("qdisc_handle")
			qparent := st.U("qdisc_parent")
			cid := st.U("classid")
			if stage == wire.StageClassify && qhandle == 0 && cid != 0 {
				push("CLASS:" + FormatTCHandle(Some(cid)))
				continue
			}
			if cid != 0 {
				push("CLASS:" + FormatTCHandle(Some(cid)))
			}
			qi := s.ResolveQdiscInfo(ifidx, evOpt(st, "queue_gen"), evOpt(st, "qdisc_handle"), evOpt(st, "qdisc_parent"), evOpt(st, "dev_gen"), Some(st.TsNs))
			kind := "QDISC"
			if qi != nil && qi.Kind != "" {
				kind = upper(qi.Kind)
			} else if !s.IsTopoDesyncedAt(st.TsNs) {
				if inf := s.InferQdiscKind(st.SiteDictIdx); inf != "" {
					kind = upper(inf)
				}
			}
			var lbl string
			if qhandle == 0 && isParentTCClass(qparent) {
				lbl = kind + "@" + FormatTCHandle(Some(qparent))
			} else {
				lbl = kind + ":" + FormatTCHandle(evOpt(st, "qdisc_handle"))
			}
			push(lbl)
		case wire.StageBypassDirect:
			tokens = append(tokens, "BYPASS_DIRECT")
		case wire.StageRequeueGSO:
			tokens = append(tokens, "REQUEUE_GSO")
		case wire.StageRequeueBadTxq:
			tokens = append(tokens, "REQUEUE_BAD_TXQ")
		case wire.StageHandoffLayer:
			tokens = append(tokens, "HANDOFF("+dev+")")
		case wire.StageXmitStart:
			tokens = append(tokens, fmt.Sprintf("XMIT(%s:txq%d)", dev, st.U("txq")))
		}
	}
	return append(tokens, br.EndReasonName)
}

func (s *Session) branchLeafSignature(br *BranchPath) string {
	if len(br.Visits) > 0 {
		var v *QueueVisit
		for _, x := range br.Visits {
			if x.VisitKind == "qdisc" {
				v = x
			}
		}
		if v == nil {
			v = br.Visits[len(br.Visits)-1]
		}
		dev := s.ResolveDevName(v.Ifindex, Some(v.DevGen), OptU{})
		kind := v.VisitKind
		if v.VisitKind == "qdisc" {
			if resolved := s.resolveVisitQdiscKind(v); resolved != "" {
				kind = resolved
			}
		}
		txq := ""
		if v.Txq.OK {
			txq = fmt.Sprintf(":txq%d", v.Txq.V)
		}
		if v.QdiscHandle == 0 && isParentTCClass(v.QdiscParent) {
			return fmt.Sprintf("%s:%s@%s(gen=%d%s)", dev, kind, FormatTCHandle(Some(v.QdiscParent)), v.QueueGen, txq)
		}
		return fmt.Sprintf("%s:%s:%s(parent=%s,gen=%d%s)", dev, kind, FormatTCHandle(Some(v.QdiscHandle)), FormatTCHandle(Some(v.QdiscParent)), v.QueueGen, txq)
	}
	for _, st := range br.Steps {
		if st.Stage() == wire.StageBypassDirect {
			return "BYPASS_DIRECT"
		}
	}
	return "NO_QUEUE_VISIT"
}

func (s *Session) branchUIDKey(br *BranchPath) string {
	if sg := s.Samples[br.SampleID]; sg != nil && sg.Attr.UID != nil {
		return fmt.Sprint(*sg.Attr.UID)
	}
	for _, sm := range br.Summaries {
		if v, ok := sm.Get("uid"); ok {
			return fmt.Sprint(v)
		}
	}
	return "unknown"
}

func admissionVal(m map[string]any, keys ...string) int64 {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			// Python: int(raw.get(a, raw.get(b, 0)) or 0)
			return wire.IntOr(v, 0)
		}
	}
	return 0
}

// QueueLabel renders a short human label for a queue instance.
func (s *Session) queueLabel(dev, kind string, handle, parent, txq OptU, qgen uint64, vkind string) string {
	var b strings.Builder
	b.WriteString(dev)
	b.WriteString(" ")
	if vkind == "qdisc" && (!handle.OK || handle.V == 0) && parent.OK && isParentTCClass(parent.V) {
		b.WriteString(upper(kind))
		b.WriteString(" @ ")
		b.WriteString(FormatTCHandle(parent))
		if qgen > 0 {
			b.WriteString(fmt.Sprintf(" (gen=%d)", qgen))
		}
		return b.String()
	}
	switch vkind {
	case "requeue_gso":
		b.WriteString("gso_skb 重排队列")
	case "requeue_bad_txq":
		b.WriteString("skb_bad_txq 队列")
	default:
		b.WriteString(upper(kind))
		b.WriteString(" ")
		b.WriteString(FormatTCHandle(handle))
	}
	var extras []string
	if handle.OK && handle.V == 0 && txq.OK {
		extras = append(extras, fmt.Sprintf("txq=%d", txq.V))
	}
	if qgen > 0 {
		extras = append(extras, fmt.Sprintf("gen=%d", qgen))
	}
	if len(extras) > 0 {
		b.WriteString(" (" + strings.Join(extras, ", ") + ")")
	}
	return b.String()
}

func branchSojournSumUs(br *BranchPath) (float64, bool) {
	sum, any := 0.0, false
	for _, v := range br.Visits {
		if v.Paired && v.SojournNs != nil {
			sum += float64(*v.SojournNs) / 1000.0
			any = true
		}
	}
	return sum, any
}

// ComputeStats is stats.py `compute_stats` (groupBy: path|leaf|status|uid).
func (s *Session) ComputeStats(groupBy string) (*Stats, error) {
	switch groupBy {
	case "path", "leaf", "status", "uid":
	case "":
		groupBy = "path"
	default:
		return nil, fmt.Errorf("unsupported group_by value: %q", groupBy)
	}
	st := &Stats{
		SessionUUID: s.Loaded.SessionUUIDString(),
		Scope:       manifestStr(s.Manifest, "scope", "tc-egress"),
		Mode:        manifestStr(s.Manifest, "mode", "oneshot"),
		SampleRate:  manifestStr(s.Manifest, "sample_rate", "1/1"),
		GroupBy:     groupBy,
		Endpoints:   map[string]int{},
		Queues:      []QueueStat{},
		Paths:       []PathGroup{},
		Groups:      []Group{},
		TailErrors:  append([]string{}, s.Loaded.TailErrors...),
	}
	raw, _ := s.Manifest["admissions"].(map[string]any)
	if raw == nil {
		raw = map[string]any{}
	}
	st.Admissions = Admissions{
		FilterUnknown: admissionVal(raw, "filter_unknown"),
		Matched:       admissionVal(raw, "matched", "admission_matched"),
		Selected:      admissionVal(raw, "selected", "admission_selected"),
		Created:       admissionVal(raw, "created", "admission_created"),
		Rejected:      admissionVal(raw, "rejected", "admission_rejected"),
	}
	st.SampleCounts = SampleCounts{len(s.Samples), len(s.Objects), len(s.Events), s.DedupDropped}
	for _, b := range s.Branches {
		switch b.Completeness {
		case "complete":
			st.Branches.Complete++
		case "incomplete":
			st.Branches.Incomplete++
		case "unknown":
			st.Branches.Unknown++
		}
		st.Endpoints[b.EndReasonName]++
	}
	st.Branches.Total = len(s.Branches)
	st.Branches.UnknownCompleteness = st.Branches.Unknown

	// skb_bytes vs wire_bytes
	var rxWire int64
	rxPk := 0
	for _, oid := range s.ObjectOrder {
		obj := s.Objects[oid]
		if obj.ObjectType != wire.ObjSKB {
			continue
		}
		hasSkbParent := false
		for _, r := range obj.Incoming {
			if p := s.Objects[r.SrcObjectID]; p != nil && p.ObjectType == wire.ObjSKB {
				hasSkbParent = true
				break
			}
		}
		if hasSkbParent {
			continue
		}
		init := obj.InitialSummary()
		var plen int64
		if init != nil {
			plen = int64(init.U("pkt_len"))
		}
		st.SkbBytes += plen
		st.SkbPackets++
		if init != nil {
			if d, ok := init.Get("dir"); ok && d == wire.DirRX {
				rxWire += plen
				rxPk++
			}
		}
	}
	var txWire int64
	txPk := 0
	counted := map[uint64]bool{}
	for _, br := range s.Branches {
		leaf := br.LeafObjectID()
		if br.EndReason == wire.EndTxOK && !counted[leaf] {
			counted[leaf] = true
			last := s.Objects[leaf].LatestSummary()
			if last == nil && len(br.Summaries) > 0 {
				last = br.Summaries[len(br.Summaries)-1]
			}
			if last != nil {
				txWire += int64(last.U("pkt_len"))
			}
			txPk++
		}
	}
	st.WireBytes = txWire + rxWire
	st.WirePackets = txPk + rxPk

	// Per-queue sojourn
	type qKey struct {
		netns, ifidx, dgen, qgen uint64
		vkind                    string
		handle, parent           uint64
		txqOK                    bool
		txq                      uint64
	}
	type vuid struct{ o, q, v uint64 }
	seenV := map[vuid]bool{}
	buckets := map[qKey][]*QueueVisit{}
	var bkeys []qKey
	for _, oid := range s.ObjectOrder {
		for _, v := range s.Objects[oid].Visits {
			u := vuid{v.ObjectID, v.QueueGen, v.VisitID}
			if seenV[u] {
				continue
			}
			seenV[u] = true
			k := qKey{v.NetnsInum, v.Ifindex, v.DevGen, v.QueueGen, v.VisitKind, v.QdiscHandle, v.QdiscParent, false, 0}
			if v.QdiscHandle == 0 && v.Txq.OK {
				k.txqOK, k.txq = true, v.Txq.V
			}
			if _, ok := buckets[k]; !ok {
				bkeys = append(bkeys, k)
			}
			buckets[k] = append(buckets[k], v)
		}
	}
	sort.SliceStable(bkeys, func(i, j int) bool {
		a, b := bkeys[i], bkeys[j]
		switch {
		case a.netns != b.netns:
			return a.netns < b.netns
		case a.ifidx != b.ifidx:
			return a.ifidx < b.ifidx
		case a.dgen != b.dgen:
			return a.dgen < b.dgen
		case a.qgen != b.qgen:
			return a.qgen < b.qgen
		case a.vkind != b.vkind:
			return a.vkind < b.vkind
		case a.handle != b.handle:
			return a.handle < b.handle
		case a.parent != b.parent:
			return a.parent < b.parent
		case a.txqOK != b.txqOK:
			return !a.txqOK
		}
		return a.txq < b.txq
	})
	for _, k := range bkeys {
		vl := buckets[k]
		dev := s.ResolveDevName(k.ifidx, Some(k.dgen), Some(k.netns))
		var refTs OptU
		if vl[0].Entry != nil {
			refTs = Some(vl[0].Entry.TsNs)
		} else if vl[0].Exit != nil {
			refTs = Some(vl[0].Exit.TsNs)
		}
		qi := s.ResolveQdiscInfo(k.ifidx, Some(k.qgen), Some(k.handle), Some(k.parent), Some(k.dgen), refTs)
		kind := "qdisc"
		if k.vkind != "qdisc" {
			kind = k.vkind
		} else if qi != nil && qi.Kind != "" {
			kind = qi.Kind
		} else if inf := s.resolveVisitQdiscKind(vl[0]); inf != "" {
			kind = inf
		}
		var us []float64
		unpaired, enqDrop, qdrop := 0, 0, 0
		for _, v := range vl {
			if v.Paired && v.SojournNs != nil {
				us = append(us, float64(*v.SojournNs)/1000.0)
			}
			if !v.Paired && !v.EnqDropped {
				unpaired++
			}
			if v.EnqDropped {
				enqDrop++
			}
			if v.Exit != nil && v.Exit.Stage() == wire.StageDrop {
				qdrop++
			}
		}
		sort.Float64s(us)
		q := QueueStat{
			Kind: kind, VisitKind: k.vkind, Handle: FormatTCHandle(Some(k.handle)), Parent: FormatTCHandle(Some(k.parent)),
			QueueGen: k.qgen, NetnsInum: k.netns, Ifindex: k.ifidx, DevGen: k.dgen, DevName: dev,
			N: len(us), PairedN: len(us), UnpairedN: unpaired, EnqDropN: enqDrop, DropCount: enqDrop + qdrop,
			P50Us: Percentile(us, 50), P95Us: Percentile(us, 95), P99Us: Percentile(us, 99),
		}
		cidLookup := uint64(0)
		if isParentTCClass(k.parent) {
			cidLookup = k.parent
		} else if vl[0].Classid != 0 {
			cidLookup = vl[0].Classid
		}
		if cidLookup != 0 {
			q.ClassID = FormatTCHandle(Some(cidLookup))
			if ci := s.ResolveClassInfo(k.ifidx, cidLookup, Some(k.dgen), refTs); ci != nil {
				q.ClassRate = FormatClassRate(ci.RateBps, ci.CeilBps)
				if ci.RateBps > 0 {
					q.ClassRateBps = u64p(ci.RateBps)
				}
				if ci.CeilBps > 0 {
					q.ClassCeilBps = u64p(ci.CeilBps)
				}
				if ci.HasPrio {
					p := ci.Prio
					q.ClassPrio = &p
				}
			}
		}
		txq := OptU{}
		if k.txqOK {
			txq = Some(k.txq)
		} else if vl[0].Txq.OK {
			txq = vl[0].Txq
		}
		if txq.OK {
			q.Txq = u64p(txq.V)
		}
		if len(us) > 0 {
			q.MinUs = f64p(round3(us[0]))
			q.MaxUs = f64p(round3(us[len(us)-1]))
			sum := 0.0
			for _, x := range us {
				sum += x
			}
			q.MeanUs = f64p(round3(sum / float64(len(us))))
		}
		q.Label = s.queueLabel(dev, kind, Some(k.handle), Some(k.parent), txq, k.qgen, k.vkind)
		st.Queues = append(st.Queues, q)
	}

	// Groups for the requested key + path groups for the overview
	st.Groups = s.groupBranches(groupBy)
	st.Paths = s.pathGroups()

	// Quality
	var qt struct{ missed, rbdrop, retun, idc, topo uint64 }
	for _, q := range s.QualityEvents {
		k := int(q.U("qual_kind"))
		c := q.U("count")
		atLeast1 := c
		if atLeast1 < 1 {
			atLeast1 = 1
		}
		switch k {
		case wire.QualMissedDelta:
			qt.missed += c
		case wire.QualRbDropDelta:
			qt.rbdrop += c
		case wire.QualRetUnmatched:
			qt.retun += atLeast1
		case wire.QualIdentityConflict:
			qt.idc += atLeast1
		case wire.QualTopoDesync:
			qt.topo += atLeast1
		}
	}
	var gapMissing uint64
	for _, g := range s.SeqGaps {
		gapMissing += g.MissingCount
	}
	st.Quality = QualitySummary{
		SeqGapWindows: len(s.SeqGaps), SeqGapMissingEvents: gapMissing,
		MissedDelta: qt.missed, RbDropDelta: qt.rbdrop, RetUnmatched: qt.retun + uint64(len(s.UnmatchedReturns)),
		IdentityConflict: qt.idc, TopoDesync: qt.topo,
		UncleanTail: s.Loaded.UncleanTail(), UnobservableMissedSource: s.HasUnobservableMissedSrc,
	}
	st.RequeueCount, st.RequeueGSOCount, st.RequeueBadTxqCount = s.RequeueCount, s.RequeueGSOCount, s.RequeueBadTxqCount
	st.ReorderCount = s.ReorderCount
	st.UncleanTail = s.Loaded.UncleanTail()
	st.QualityAlerts = s.qualityAlerts(st)
	return st, nil
}

func (s *Session) qualityAlerts(st *Stats) []QualityAlert {
	out := []QualityAlert{}
	q := st.Quality
	add := func(kind, sev string, cnt uint64, msg string) {
		out = append(out, QualityAlert{Kind: kind, Severity: sev, Count: cnt, Message: msg})
	}
	if q.SeqGapWindows > 0 {
		add("SEQ_GAP", "warn", q.SeqGapMissingEvents, fmt.Sprintf("检测到 %d 个事件序号缺口（共缺失 %d 个事件，ringbuf 导出丢失）", q.SeqGapWindows, q.SeqGapMissingEvents))
	}
	if q.MissedDelta > 0 {
		add("MISSED_DELTA", "warn", q.MissedDelta, fmt.Sprintf("探针漏触发 nmissed/recursion_misses 累计 %d 次，重叠支路已标记不完整", q.MissedDelta))
	}
	if q.RbDropDelta > 0 {
		add("RB_DROP_DELTA", "warn", q.RbDropDelta, fmt.Sprintf("ringbuf 预留失败丢弃 %d 个事件", q.RbDropDelta))
	}
	if q.RetUnmatched > 0 {
		add("RET_UNMATCHED", "warn", q.RetUnmatched, fmt.Sprintf("%d 个函数返回事件未能与入口配对", q.RetUnmatched))
	}
	if q.IdentityConflict > 0 {
		add("IDENTITY_CONFLICT", "warn", q.IdentityConflict, fmt.Sprintf("%d 次地址身份冲突（已隔离，不污染其他样本）", q.IdentityConflict))
	}
	if q.TopoDesync > 0 {
		add("TOPO_DESYNC", "warn", q.TopoDesync, fmt.Sprintf("拓扑快照失步 %d 次，期间 Qdisc 种类标记为未知", q.TopoDesync))
	}
	if q.UncleanTail {
		msg := "会话缺少 END_MARKER 或末尾数据块损坏 (UNKNOWN_TAIL)，已重放有效数据块"
		if len(st.TailErrors) > 0 {
			msg += "：" + strings.Join(st.TailErrors, "; ")
		}
		add("UNCLEAN_TAIL", "error", 1, msg)
	}
	if q.UnobservableMissedSource {
		add("UNOBSERVABLE_MISSED_SOURCE", "info", uint64(len(s.UnobservableAdapters)),
			"部分适配器无法观测漏报计数 (missed_source=none)，完整性记为未知: "+strings.Join(s.UnobservableAdapters, ", "))
	}
	if st.Branches.Incomplete > 0 {
		add("INCOMPLETE_BRANCHES", "info", uint64(st.Branches.Incomplete), fmt.Sprintf("%d/%d 条支路不完整", st.Branches.Incomplete, st.Branches.Total))
	}
	return out
}

func (s *Session) groupBranches(groupBy string) []Group {
	groups := map[string][]*BranchPath{}
	var keys []string
	for _, br := range s.Branches {
		var k string
		switch groupBy {
		case "path":
			k = s.BranchPathSignature(br)
		case "leaf":
			k = s.branchLeafSignature(br)
		case "status":
			k = br.Completeness + ":" + br.EndReasonName
		default:
			k = s.branchUIDKey(br)
		}
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], br)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		li, lj := len(groups[keys[i]]), len(groups[keys[j]])
		if li != lj {
			return li > lj
		}
		return keys[i] < keys[j]
	})
	out := []Group{}
	for _, k := range keys {
		bl := groups[k]
		g := Group{Key: k, BranchCount: len(bl), Endpoints: map[string]int{}}
		g.SkbBytes, g.WireBytes = s.groupBytes(bl)
		for _, b := range bl {
			g.Endpoints[b.EndReasonName]++
			switch b.Completeness {
			case "complete":
				g.Complete++
			case "incomplete":
				g.Incomplete++
			case "unknown":
				g.UnknownCompleteness++
			}
		}
		out = append(out, g)
	}
	return out
}

func (s *Session) groupBytes(bl []*BranchPath) (int64, int64) {
	var skb, wireB int64
	roots, txs := map[uint64]bool{}, map[uint64]bool{}
	for _, b := range bl {
		root := b.ObjectIDs[0]
		if !roots[root] && s.Objects[root].ObjectType == wire.ObjSKB {
			roots[root] = true
			if s0 := s.Objects[root].InitialSummary(); s0 != nil {
				skb += int64(s0.U("pkt_len"))
			}
		}
		leaf := b.LeafObjectID()
		if b.EndReason == wire.EndTxOK && !txs[leaf] {
			txs[leaf] = true
			if sl := s.Objects[leaf].LatestSummary(); sl != nil {
				wireB += int64(sl.U("pkt_len"))
			}
		}
	}
	return skb, wireB
}

func (s *Session) pathGroups() []PathGroup {
	groups := map[string][]*BranchPath{}
	tokensOf := map[string][]string{}
	var keys []string
	for _, br := range s.Branches {
		toks := s.branchPathTokens(br)
		k := strings.Join(toks, " -> ")
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
			tokensOf[k] = toks
		}
		groups[k] = append(groups[k], br)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		li, lj := len(groups[keys[i]]), len(groups[keys[j]])
		if li != lj {
			return li > lj
		}
		return keys[i] < keys[j]
	})
	out := []PathGroup{}
	for _, k := range keys {
		bl := groups[k]
		toks := tokensOf[k]
		pg := PathGroup{PathSig: k, Tokens: toks, Endpoint: toks[len(toks)-1], Count: len(bl), Endpoints: map[string]int{}, SampleIDs: []uint64{}}
		var totals, sojs []float64
		seenS := map[uint64]bool{}
		for _, b := range bl {
			pg.Endpoints[b.EndReasonName]++
			switch b.Completeness {
			case "complete":
				pg.CompleteCount++
			case "incomplete":
				pg.IncompleteCount++
			case "unknown":
				pg.UnknownCount++
			}
			totals = append(totals, float64(b.EndTsNs-b.StartTsNs)/1000.0)
			if sum, ok := branchSojournSumUs(b); ok {
				sojs = append(sojs, sum)
			}
			if !seenS[b.SampleID] {
				seenS[b.SampleID] = true
				pg.SampleIDs = append(pg.SampleIDs, b.SampleID)
			}
		}
		sort.Float64s(totals)
		sort.Float64s(sojs)
		pg.P50Us, pg.P95Us, pg.P99Us = Percentile(totals, 50), Percentile(totals, 95), Percentile(totals, 99)
		pg.SojournP50Us, pg.SojournP95Us, pg.SojournP99Us = Percentile(sojs, 50), Percentile(sojs, 95), Percentile(sojs, 99)
		pg.SkbBytes, pg.WireBytes = s.groupBytes(bl)
		out = append(out, pg)
	}
	return out
}
