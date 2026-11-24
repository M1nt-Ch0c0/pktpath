package reconstruct

import (
	"fmt"
	"strings"

	"pktpath/studio/pkg/wire"
)

var (
	dirLabelsZH = map[int]string{
		wire.DirRX:  "RX 接收",
		wire.DirTX:  "本地 TX",
		wire.DirFWD: "转发 FWD",
	}
	l4ProtoNames = map[uint64]string{
		1:  "ICMP",
		6:  "TCP",
		17: "UDP",
		58: "ICMPv6",
	}
)

// SessionOverview is the JSON payload returned by GET /api/session/overview
// and POST /api/capture/stop / POST /api/sessions/open.
type SessionOverview struct {
	Manifest map[string]any `json:"manifest"`
	Dict     map[string]any `json:"dict"`
	Stats    *Stats         `json:"stats"`
	Samples  []SampleRow    `json:"samples"`
}

// SampleRow is one row in the interactive sample table.
type SampleRow struct {
	SampleID     uint64   `json:"sample_id"`
	UID          *uint64  `json:"uid"`
	Tgid         *uint64  `json:"tgid"`
	Comm         string   `json:"comm"`
	EnqueueTid   uint64   `json:"enqueue_tid"`
	InTask       bool     `json:"in_task"`
	Proto        string   `json:"proto"`
	Src          string   `json:"src"`
	Dst          string   `json:"dst"`
	SrcIP        string   `json:"src_ip"`
	DstIP        string   `json:"dst_ip"`
	SrcPort      *uint64  `json:"src_port"`
	DstPort      *uint64  `json:"dst_port"`
	TCPSeq       *uint64  `json:"tcp_seq"`
	TCPSeqEnd    *uint64  `json:"tcp_seq_end"`
	PktLen       uint64   `json:"pkt_len"`
	MaxSojournUs float64  `json:"max_sojourn_us"`
	TotalUs      float64  `json:"total_us"`
	Complete     bool     `json:"complete"`
	Completeness string   `json:"completeness"`
	GapReasons   []string `json:"gap_reasons"`
	Endpoint     string   `json:"endpoint"`
	BranchCount  int      `json:"branch_count"`
	Requeued     bool     `json:"requeued"`
	PathSig      string   `json:"path_sig"`
	PathSigs     []string `json:"path_sigs"`
}

// SampleSummary is the packet/attribution header of SampleDetail.
type SampleSummary struct {
	SampleID       uint64   `json:"sample_id"`
	UID            *uint64  `json:"uid"`
	Tgid           *uint64  `json:"tgid"`
	Comm           string   `json:"comm"`
	EnqueueTid     uint64   `json:"enqueue_tid"`
	Proto          string   `json:"proto"`
	Src            string   `json:"src"`
	Dst            string   `json:"dst"`
	TCPSeq         *uint64  `json:"tcp_seq"`
	PktLen         uint64   `json:"pkt_len"`
	MaxSojournUs   float64  `json:"max_sojourn_us"`
	TotalUs        float64  `json:"total_us"`
	Complete       bool     `json:"complete"`
	Completeness   string   `json:"completeness"`
	Endpoint       string   `json:"endpoint"`
	BranchCount    int      `json:"branch_count"`
	Requeued       bool     `json:"requeued"`
	PathSig        string   `json:"path_sig"`
	DevName        string   `json:"dev_name"`
	DirLabel       string   `json:"dir_label"`
	XmitTid        *uint64           `json:"xmit_tid,omitempty"`
	SkbCreateRelUs *float64          `json:"skb_create_rel_us,omitempty"`
	PluginTags     map[string]uint64 `json:"plugin_tags,omitempty"`
	TCPSeqEnd      *uint64           `json:"tcp_seq_end,omitempty"`
	SkbMark        *uint64  `json:"skb_mark,omitempty"`
	SkbPriority    *uint64  `json:"skb_priority,omitempty"`
	SkbHash        *uint64  `json:"skb_hash,omitempty"`
	LinearLen      *uint64  `json:"linear_len,omitempty"`
	Headline       string   `json:"headline,omitempty"`
	GapReasons     []string `json:"gap_reasons"`
}

// TimelineEvent is one card/bar in a branch waterfall timeline.
type TimelineEvent struct {
	RelUs         float64  `json:"rel_us"`
	TsNs          uint64   `json:"ts_ns"`
	EvidenceLevel int      `json:"evidence_level"`
	EvidenceLabel string   `json:"evidence_label"`
	Stage         string   `json:"stage"`
	StageCode     int      `json:"stage_code"`
	Title         string   `json:"title"`
	Detail        string   `json:"detail"`
	SojournUs     *float64 `json:"sojourn_us"`
	CPU           *uint32  `json:"cpu"`
	Tid           *uint64  `json:"tid"`
	InTask        *bool    `json:"in_task"`
	EnqueueCPU    *uint32  `json:"enqueue_cpu,omitempty"`
	EnqueueTid    *uint64  `json:"enqueue_tid,omitempty"`
	CrossCPU      bool     `json:"cross_cpu"`
	CrossThread   bool     `json:"cross_thread"`
	ObjectID      uint64   `json:"object_id"`
	VisitID       *uint64  `json:"visit_id,omitempty"`
	QdiscHandle   string   `json:"qdisc_handle,omitempty"`
	Txq           *uint64  `json:"txq,omitempty"`
	EventID       string   `json:"event_id"`
	ProbeName     string   `json:"probe_name"`
	ProbeType     string   `json:"probe_type"`
	ProbeVersion  string   `json:"probe_version"`
	AdapterName   string   `json:"adapter_name"`
}

// BranchDetail is one branch in SampleDetail.
type BranchDetail struct {
	BranchID     string          `json:"branch_id"`
	BranchIndex  int             `json:"branch_index"`
	Label        string          `json:"label"`
	PathSig      string          `json:"path_sig"`
	Complete     bool            `json:"complete"`
	Completeness string          `json:"completeness"`
	GapReasons   []string        `json:"gap_reasons"`
	Endpoint     string          `json:"endpoint"`
	EndReason    int             `json:"end_reason"`
	DropReason   *uint64         `json:"drop_reason"`
	BoundaryNote string          `json:"boundary_note"`
	ObjectChain  []uint64        `json:"object_chain"`
	RequeueCount int             `json:"requeue_count"`
	StartRelUs   float64         `json:"start_rel_us"`
	EndRelUs     float64         `json:"end_rel_us"`
	TotalUs      float64         `json:"total_us"`
	MaxSojournUs float64         `json:"max_sojourn_us"`
	Timeline     []TimelineEvent `json:"timeline"`
}

// RelationEdge is a serializable DAG relation edge for SampleDetail.
type RelationEdge struct {
	OpID                uint64  `json:"op_id"`
	RelType             string  `json:"rel_type"`
	RelTypeCode         int     `json:"rel_type_code"`
	SrcObjectID         uint64  `json:"src_object_id"`
	DstObjectID         uint64  `json:"dst_object_id"`
	RelUs               float64 `json:"rel_us"`
	TsNs                uint64  `json:"ts_ns"`
	StreamOffset        *uint64 `json:"stream_offset,omitempty"`
	SpanLen             *uint64 `json:"span_len,omitempty"`
	SuccessorTruncated  bool    `json:"successor_truncated"`
	UnknownPredecessors bool    `json:"unknown_predecessors"`
}

// QStateSpan is a serializable TXQ STOP→WAKE / BQL backpressure span.
type QStateSpan struct {
	Ifindex     uint64   `json:"ifindex"`
	DevName     string   `json:"dev_name"`
	Txq         uint64   `json:"txq"`
	QueueGen    uint64   `json:"queue_gen"`
	StateOp     string   `json:"state_op"`
	StateOpCode int      `json:"state_op_code"`
	StartRelUs  float64  `json:"start_rel_us"`
	EndRelUs    *float64 `json:"end_rel_us"`
	StartNs     uint64   `json:"start_ns"`
	EndNs       *uint64  `json:"end_ns"`
	Open        bool     `json:"open"`
	Value       uint64   `json:"value"`
}

// SampleDetail is the JSON payload returned by GET /api/session/sample.
type SampleDetail struct {
	SampleID  uint64         `json:"sample_id"`
	Summary   SampleSummary  `json:"summary"`
	Branches  []BranchDetail `json:"branches"`
	Relations []RelationEdge `json:"relations"`
	QStates   []QStateSpan   `json:"qstates"`
}

func relUs(tsNs, baseNs uint64) float64 {
	return round3(float64(int64(tsNs)-int64(baseNs)) / 1000.0)
}

func durUs(startNs, endNs uint64) float64 {
	if endNs <= startNs {
		return 0
	}
	return round3(float64(endNs-startNs) / 1000.0)
}

func fmtDurUsText(ns uint64) string {
	if ns%1000 == 0 {
		return fmt.Sprintf("%d µs", ns/1000)
	}
	return fmt.Sprintf("%.1f µs", float64(ns)/1000.0)
}

func fmtRelUsText(tsNs, baseNs uint64) string {
	d := int64(tsNs) - int64(baseNs)
	if d%1000 == 0 {
		return fmt.Sprintf("%d µs", d/1000)
	}
	return fmt.Sprintf("%.1f µs", float64(d)/1000.0)
}

func protoLabel(summ *wire.Event) string {
	if summ == nil {
		return "PKT"
	}
	p, ok := summ.Get("l4_proto")
	if !ok {
		return "PKT"
	}
	if n, ok := l4ProtoNames[p]; ok {
		return n
	}
	return fmt.Sprintf("L4(%d)", p)
}

func formatEndpointAddr(ip string, port OptU, proto OptU) string {
	if ip == "" {
		return ""
	}
	if port.OK && (proto.V == 6 || proto.V == 17) {
		if strings.Contains(ip, ":") {
			return fmt.Sprintf("[%s]:%d", ip, port.V)
		}
		return fmt.Sprintf("%s:%d", ip, port.V)
	}
	return ip
}

func optPtr(o OptU) *uint64 {
	if !o.OK {
		return nil
	}
	v := o.V
	return &v
}

func primarySummary(s *Session, sg *SampleGraph) *wire.Event {
	if len(sg.RootObjectIDs) > 0 {
		if init := s.Objects[sg.RootObjectIDs[0]].InitialSummary(); init != nil {
			return init
		}
	}
	for _, oid := range sg.ObjectIDs {
		if init := s.Objects[oid].InitialSummary(); init != nil {
			return init
		}
	}
	return nil
}

// primaryBranch picks the representative branch for SampleRow (preferring the main
// non-clone continuation or TX_OK/DROP path with queue visits over auxiliary CLONE -> CONSUME taps).
func primaryBranch(branches []*BranchPath) *BranchPath {
	if len(branches) == 0 {
		return nil
	}
	best := branches[0]
	score := func(b *BranchPath) int {
		sc := 0
		isClone := false
		for _, r := range b.RelationChain {
			if r.RelType == wire.RelClone || r.RelType == wire.RelCopy {
				isClone = true
				break
			}
		}
		if !isClone {
			sc += 1000
		}
		if b.EndReason == wire.EndTxOK || b.EndReason == wire.EndDrop || b.EndReason == wire.EndSockEnqueue || b.EndReason == wire.EndAppRead {
			sc += 500
		}
		if len(b.Visits) > 0 {
			sc += 200
		}
		sc += len(b.Steps)
		return sc
	}
	bestScore := score(best)
	for _, b := range branches[1:] {
		if sc := score(b); sc > bestScore {
			best, bestScore = b, sc
		}
	}
	return best
}

func sampleMaxSojournUs(sg *SampleGraph) float64 {
	mx := 0.0
	for _, br := range sg.Branches {
		for _, v := range br.Visits {
			if v.Paired && v.SojournNs != nil {
				u := round3(float64(*v.SojournNs) / 1000.0)
				if u > mx {
					mx = u
				}
			}
		}
	}
	return mx
}

func branchMaxSojournUs(br *BranchPath) float64 {
	mx := 0.0
	for _, v := range br.Visits {
		if v.Paired && v.SojournNs != nil {
			u := round3(float64(*v.SojournNs) / 1000.0)
			if u > mx {
				mx = u
			}
		}
	}
	return mx
}

// BuildOverview constructs the complete SessionOverview for HTTP API / UI consumption.
func BuildOverview(s *Session) *SessionOverview {
	stats, _ := s.ComputeStats("path")
	rows := make([]SampleRow, 0, len(s.SampleOrder))
	for _, sid := range s.SampleOrder {
		sg := s.Samples[sid]
		rows = append(rows, s.buildSampleRow(sg))
	}
	return &SessionOverview{
		Manifest: s.Manifest,
		Dict:     s.Dict,
		Stats:    stats,
		Samples:  rows,
	}
}

func (s *Session) buildSampleRow(sg *SampleGraph) SampleRow {
	summ := primarySummary(s, sg)
	row := SampleRow{
		SampleID:     sg.SampleID,
		UID:          sg.Attr.UID,
		Tgid:         sg.Attr.Tgid,
		Proto:        protoLabel(summ),
		MaxSojournUs: sampleMaxSojournUs(sg),
		TotalUs:      durUs(sg.FirstTsNs, sg.LastTsNs),
		Complete:     sg.Complete,
		Completeness: sg.Completeness,
		GapReasons:   append([]string{}, sg.GapReasons...),
		BranchCount:  len(sg.Branches),
		PathSigs:     make([]string, 0, len(sg.Branches)),
	}
	if sg.Attr.Comm != nil {
		row.Comm = *sg.Attr.Comm
	}
	if sg.Attr.EnqueueTid != nil {
		row.EnqueueTid = *sg.Attr.EnqueueTid
	}
	if sg.Attr.InTask != nil {
		row.InTask = *sg.Attr.InTask
	}
	if summ != nil {
		protoOpt := evOpt(summ, "l4_proto")
		sip, _ := summ.Str("src_ip")
		dip, _ := summ.Str("dst_ip")
		sp := evOpt(summ, "src_port")
		dp := evOpt(summ, "dst_port")
		row.SrcIP, row.DstIP = sip, dip
		row.SrcPort, row.DstPort = optPtr(sp), optPtr(dp)
		row.Src = formatEndpointAddr(sip, sp, protoOpt)
		row.Dst = formatEndpointAddr(dip, dp, protoOpt)
		row.TCPSeq = optPtr(evOpt(summ, "tcp_seq"))
		row.TCPSeqEnd = optPtr(evOpt(summ, "tcp_seq_end"))
		row.PktLen = summ.U("pkt_len")
	}
	seenSig := map[string]bool{}
	for _, br := range sg.Branches {
		if br.RequeueCount > 0 {
			row.Requeued = true
		}
		sig := s.BranchPathSignature(br)
		if !seenSig[sig] {
			seenSig[sig] = true
			row.PathSigs = append(row.PathSigs, sig)
		}
	}
	if pb := primaryBranch(sg.Branches); pb != nil {
		row.Endpoint = pb.EndReasonName
		primarySig := s.BranchPathSignature(pb)
		ordered := []string{primarySig}
		for _, sig := range row.PathSigs {
			if sig != primarySig {
				ordered = append(ordered, sig)
			}
		}
		row.PathSigs = ordered
		row.PathSig = strings.Join(ordered, " || ")
	}
	return row
}

// BuildSampleDetail builds the rich single-packet waterfall & branch DAG view for a sample.
func BuildSampleDetail(s *Session, sampleID uint64) (*SampleDetail, error) {
	sg := s.Samples[sampleID]
	if sg == nil {
		return nil, fmt.Errorf("sample %d not found", sampleID)
	}
	baseNs := sg.FirstTsNs
	summary := s.buildSampleSummary(sg, baseNs)

	branches := make([]BranchDetail, 0, len(sg.Branches))
	qstateSeen := map[*QStateAnnotation]bool{}
	var qstates []QStateSpan

	for _, br := range sg.Branches {
		branches = append(branches, s.buildBranchDetail(sg, br, baseNs))
		for _, qs := range br.QStates {
			if !qstateSeen[qs] {
				qstateSeen[qs] = true
				span := QStateSpan{
					Ifindex:     qs.Ifindex,
					DevName:     s.ResolveDevName(qs.Ifindex, OptU{}, OptU{}),
					Txq:         qs.Txq,
					QueueGen:    qs.QueueGen,
					StateOp:     qs.StateName,
					StateOpCode: qs.StateOp,
					StartRelUs:  relUs(qs.StartNs, baseNs),
					StartNs:     qs.StartNs,
					Open:        !qs.EndNs.OK,
					Value:       qs.Value,
				}
				if qs.EndNs.OK {
					span.EndNs = u64p(qs.EndNs.V)
					span.EndRelUs = f64p(relUs(qs.EndNs.V, baseNs))
				}
				qstates = append(qstates, span)
			}
		}
	}

	rels := make([]RelationEdge, 0, len(sg.Relations))
	for _, r := range sg.Relations {
		rels = append(rels, RelationEdge{
			OpID:                r.OpID,
			RelType:             r.RelTypeName,
			RelTypeCode:         r.RelType,
			SrcObjectID:         r.SrcObjectID,
			DstObjectID:         r.DstObjectID,
			RelUs:               relUs(r.TsNs, baseNs),
			TsNs:                r.TsNs,
			StreamOffset:        optPtr(r.StreamOffset),
			SpanLen:             optPtr(r.SpanLen),
			SuccessorTruncated:  r.SuccessorTruncated,
			UnknownPredecessors: r.UnknownPredecessors,
		})
	}

	return &SampleDetail{
		SampleID:  sampleID,
		Summary:   summary,
		Branches:  branches,
		Relations: rels,
		QStates:   qstates,
	}, nil
}

func (s *Session) buildSampleSummary(sg *SampleGraph, baseNs uint64) SampleSummary {
	rootObj := s.Objects[sg.RootObjectIDs[0]]
	initSum := primarySummary(s, sg)
	var firstStep *wire.Event
	if len(rootObj.Steps) > 0 {
		firstStep = rootObj.Steps[0]
	}

	var ifidx uint64
	if initSum != nil && initSum.U("ifindex") != 0 {
		ifidx = initSum.U("ifindex")
	} else if firstStep != nil {
		ifidx = firstStep.U("ifindex")
	}
	dirVal := wire.DirTX
	if initSum != nil && initSum.Has("dir") {
		dirVal = int(initSum.U("dir"))
	} else if firstStep != nil && firstStep.Has("dir") {
		dirVal = int(firstStep.U("dir"))
	}
	devName := s.ResolveDevName(ifidx, OptU{}, OptU{})
	dirLbl, ok := dirLabelsZH[dirVal]
	if !ok {
		dirLbl = "TX"
	}

	sm := SampleSummary{
		SampleID:     sg.SampleID,
		UID:          sg.Attr.UID,
		Tgid:         sg.Attr.Tgid,
		XmitTid:      sg.Attr.XmitTid,
		DirLabel:     dirLbl,
		DevName:      devName,
		Proto:        protoLabel(initSum),
		TotalUs:      durUs(sg.FirstTsNs, sg.LastTsNs),
		MaxSojournUs: sampleMaxSojournUs(sg),
		Complete:     sg.Complete,
		Completeness: sg.Completeness,
		GapReasons:   append([]string{}, sg.GapReasons...),
		BranchCount:  len(sg.Branches),
	}
	if len(sg.Attr.PluginVals) > 0 {
		labels := map[int]string{}
		if pfs, ok := s.Dict["plugin_fields"].([]any); ok {
			for _, raw := range pfs {
				if m, ok := raw.(map[string]any); ok {
					if slot, ok := wire.AsInt(m["slot"]); ok {
						if lbl := jstr(m["label"]); lbl != "" {
							labels[int(slot)] = lbl
						}
					}
				}
			}
		}
		sm.PluginTags = map[string]uint64{}
		for slot, val := range sg.Attr.PluginVals {
			lbl := labels[slot]
			if lbl == "" {
				lbl = fmt.Sprintf("ext%d", slot)
			}
			sm.PluginTags[lbl] = val
		}
	}
	if sg.Attr.Comm != nil {
		sm.Comm = *sg.Attr.Comm
	}
	if sg.Attr.EnqueueTid != nil {
		sm.EnqueueTid = *sg.Attr.EnqueueTid
	}
	if sg.Attr.SkbCreateTs != nil {
		sm.SkbCreateRelUs = f64p(relUs(*sg.Attr.SkbCreateTs, baseNs))
	}
	if initSum != nil {
		protoOpt := evOpt(initSum, "l4_proto")
		sip, _ := initSum.Str("src_ip")
		dip, _ := initSum.Str("dst_ip")
		sp := evOpt(initSum, "src_port")
		dp := evOpt(initSum, "dst_port")
		sm.Src = formatEndpointAddr(sip, sp, protoOpt)
		sm.Dst = formatEndpointAddr(dip, dp, protoOpt)
		sm.TCPSeq = optPtr(evOpt(initSum, "tcp_seq"))
		sm.TCPSeqEnd = optPtr(evOpt(initSum, "tcp_seq_end"))
		sm.PktLen = initSum.U("pkt_len")
		sm.LinearLen = optPtr(evOpt(initSum, "linear_len"))
		sm.SkbHash = optPtr(evOpt(initSum, "skb_hash"))
		sm.SkbMark = optPtr(evOpt(initSum, "skb_mark"))
		sm.SkbPriority = optPtr(evOpt(initSum, "skb_priority"))
	}
	for _, br := range sg.Branches {
		if br.RequeueCount > 0 {
			sm.Requeued = true
		}
	}
	if pb := primaryBranch(sg.Branches); pb != nil {
		sm.Endpoint = pb.EndReasonName
		sm.PathSig = s.BranchPathSignature(pb)
	}

	uidStr := "UID unknown"
	if sm.UID != nil {
		uidStr = fmt.Sprintf("UID %d", *sm.UID)
	}
	owner := uidStr
	if sm.Tgid != nil || sm.Comm != "" {
		tg := "?"
		if sm.Tgid != nil {
			tg = fmt.Sprint(*sm.Tgid)
		}
		cm := sm.Comm
		if cm == "" {
			cm = "?"
		}
		owner = fmt.Sprintf("%s (pid %s/%s)", uidStr, tg, cm)
	}
	flow := formatSummaryBrief(initSum)
	sm.Headline = strings.TrimSpace(fmt.Sprintf("样本 %d  %s → %s  %s  %s", sg.SampleID, dirLbl, devName, owner, flow))
	return sm
}

func formatSummaryBrief(summ *wire.Event) string {
	if summ == nil {
		return ""
	}
	p := protoLabel(summ)
	protoOpt := evOpt(summ, "l4_proto")
	sip, _ := summ.Str("src_ip")
	dip, _ := summ.Str("dst_ip")
	sp := evOpt(summ, "src_port")
	dp := evOpt(summ, "dst_port")
	var pieces []string
	if sip != "" && dip != "" {
		pieces = append(pieces, fmt.Sprintf("%s %s → %s", p, formatEndpointAddr(sip, sp, protoOpt), formatEndpointAddr(dip, dp, protoOpt)))
	}
	if protoOpt.V == 6 {
		if tseq, ok := summ.Get("tcp_seq"); ok {
			tend := tseq
			if te, ok2 := summ.Get("tcp_seq_end"); ok2 && te != 0 {
				tend = te
			}
			pieces = append(pieces, fmt.Sprintf("TCP seq %d:%d", tseq, tend))
		}
	}
	if plen, ok := summ.Get("pkt_len"); ok {
		pieces = append(pieces, fmt.Sprintf("len=%dB", plen))
	}
	return strings.Join(pieces, "  ")
}

func (s *Session) qdiscStepLabel(st *wire.Event) string {
	return s.qdiscStepLabelWithHint(st, "")
}

func (s *Session) qdiscStepLabelWithHint(st *wire.Event, fallbackKind string) string {
	ifidx := st.U("ifindex")
	qgen := evOpt(st, "queue_gen")
	handle := evOpt(st, "qdisc_handle")
	parent := evOpt(st, "qdisc_parent")
	devGen := evOpt(st, "dev_gen")
	qi := s.ResolveQdiscInfo(ifidx, qgen, handle, parent, devGen, Some(st.TsNs))
	hStr := FormatTCHandle(handle)
	var kindStr string
	switch {
	case qi != nil && qi.Kind != "":
		kindStr = upper(qi.Kind)
	case s.IsTopoDesyncedAt(st.TsNs):
		kindStr = "Qdisc(拓扑失步未知)"
	case fallbackKind != "":
		kindStr = upper(fallbackKind)
	default:
		if inf := s.InferQdiscKind(st.SiteDictIdx); inf != "" {
			kindStr = upper(inf)
		} else {
			kindStr = "Qdisc"
		}
	}
	if (!handle.OK || handle.V == 0) && parent.OK && isParentTCClass(parent.V) {
		lbl := fmt.Sprintf("%s @ %s", kindStr, FormatTCHandle(parent))
		if qgen.OK && qgen.V > 0 {
			lbl += fmt.Sprintf(" (gen=%d)", qgen.V)
		}
		return lbl
	}
	var extras []string
	if handle.OK && handle.V == 0 {
		if txq, ok := st.Get("txq"); ok {
			extras = append(extras, fmt.Sprintf("txq=%d", txq))
		}
	}
	if qgen.OK && qgen.V > 0 {
		extras = append(extras, fmt.Sprintf("gen=%d", qgen.V))
	}
	if len(extras) > 0 {
		return fmt.Sprintf("%s %s (%s)", kindStr, hStr, strings.Join(extras, ", "))
	}
	return fmt.Sprintf("%s %s", kindStr, hStr)
}

func boundaryMessage(scope string, br *BranchPath) string {
	if br.EndReasonName == "UNKNOWN_TAIL" {
		return "会话异常中断/缺少末尾健康检查点 (UNKNOWN_TAIL)；后续状态不可证"
	}
	switch br.EndReason {
	case wire.EndTxOK:
		return fmt.Sprintf("驱动接手 (NETDEV_TX_OK)；硬件队列/Wi-Fi 固件排队与空口 ACK 位于 %s 软件观测范围之外", scope)
	case wire.EndDrop:
		if br.DropReason.OK {
			return fmt.Sprintf("内核协议栈/队列明确丢包 (DROP) (drop_reason=%d)", br.DropReason.V)
		}
		return "内核协议栈/队列明确丢包 (DROP)"
	case wire.EndConsume:
		return "内核正常消费释放 (CONSUME)"
	case wire.EndSockEnqueue:
		return "已交付 Socket 接收队列 (SOCK_ENQUEUE)；应用态 recvmsg 读取不在默认边界内"
	case wire.EndAppRead:
		return "应用态已完成读取 (APP_READ)"
	case wire.EndTimeoutTruncated:
		return "采集窗口到期或 Epoch 切换排空截断 (TIMEOUT_TRUNCATED)"
	case wire.EndConflictTruncated:
		return "检测到地址身份冲突并隔离截断 (CONFLICT_TRUNCATED)"
	case wire.EndBoundary:
		return fmt.Sprintf("跨出当前已挂载观测边界 (%s BOUNDARY)", scope)
	}
	return "未观测到终点事件 (OPEN_UNFINISHED)"
}

func (s *Session) fillProbeMeta(te *TimelineEvent, ev *wire.Event) {
	if ev == nil {
		return
	}
	te.EventID = ev.EventID()
	if ev.CPU != wire.UserspaceCPU {
		c := ev.CPU
		te.CPU = &c
	}
	inTask := ev.Flags&wire.EvFlagInTask != 0
	te.InTask = &inTask
	if tid, ok := ev.Get("ctx_tid"); ok {
		te.Tid = u64p(tid)
	}
	if site := s.ResolveSite(ev.SiteDictIdx); site != nil {
		sym := site.Symbol
		if sym == "" {
			sym = site.Name
		}
		ptype := site.ProbeType
		if ptype == "" {
			ptype = "probe"
		}
		pver := site.ProbeVersion
		if pver == "" {
			pver = "1.0"
		}
		te.ProbeType = ptype
		te.ProbeName = ptype + ":" + sym
		te.ProbeVersion = pver
		te.AdapterName = s.adapterName(site.AdapterID)
	} else {
		te.ProbeName = fmt.Sprintf("site#%d", ev.SiteDictIdx)
	}
}

func evLabel(lvl uint8) string {
	if l, ok := wire.EvidenceLabelsZH[int(lvl)]; ok {
		return l
	}
	return "直接观测"
}

func (s *Session) buildBranchDetail(sg *SampleGraph, br *BranchPath, baseNs uint64) BranchDetail {
	scope := manifestStrOr(s.Manifest, "scope", "tc-egress")
	relDesc := "主路径"
	if len(br.RelationChain) > 0 {
		parts := make([]string, len(br.RelationChain))
		for i, r := range br.RelationChain {
			parts[i] = fmt.Sprintf("%s(#%d→#%d)", r.RelTypeName, r.SrcObjectID, r.DstObjectID)
		}
		relDesc = strings.Join(parts, " / ")
	}
	bd := BranchDetail{
		BranchID:     br.BranchID,
		BranchIndex:  br.BranchIndex,
		Label:        relDesc,
		PathSig:      s.BranchPathSignature(br),
		Complete:     br.Complete,
		Completeness: br.Completeness,
		GapReasons:   append([]string{}, br.GapReasons...),
		Endpoint:     br.EndReasonName,
		EndReason:    br.EndReason,
		DropReason:   optPtr(br.DropReason),
		BoundaryNote: boundaryMessage(scope, br),
		ObjectChain:  append([]uint64{}, br.ObjectIDs...),
		RequeueCount: br.RequeueCount,
		StartRelUs:   relUs(br.StartTsNs, baseNs),
		EndRelUs:     relUs(br.EndTsNs, baseNs),
		TotalUs:      durUs(br.StartTsNs, br.EndTsNs),
		MaxSojournUs: branchMaxSojournUs(br),
		Timeline:     []TimelineEvent{},
	}

	addEv := func(te TimelineEvent) { bd.Timeline = append(bd.Timeline, te) }

	// Pre-entry skb_create_ts annotation on first branch when present
	if br.BranchIndex == 1 && sg.Attr.SkbCreateTs != nil && baseNs >= *sg.Attr.SkbCreateTs {
		cts := *sg.Attr.SkbCreateTs
		pre := fmtDurUsText(baseNs - cts)
		addEv(TimelineEvent{
			RelUs:         relUs(cts, baseNs),
			TsNs:          cts,
			EvidenceLevel: int(wire.EvidenceDirect),
			EvidenceLabel: evLabel(wire.EvidenceDirect),
			Stage:         "SOCK_CREATE_TS",
			Title:         "Socket 发包创建",
			Detail:        fmt.Sprintf("skb_create_ts 距协议栈入口 %s", pre),
			Tid:           sg.Attr.EnqueueTid,
			ObjectID:      br.ObjectIDs[0],
		})
	}

	visitByEntry := map[string]*QueueVisit{}
	visitByExit := map[string]*QueueVisit{}
	for _, v := range br.Visits {
		if v.Entry != nil {
			visitByEntry[v.Entry.EventID()] = v
		}
		if v.Exit != nil {
			visitByExit[v.Exit.EventID()] = v
		}
	}

	// Relations along the chain
	for _, rel := range br.RelationChain {
		extra := ""
		if rel.StreamOffset.OK || rel.SpanLen.OK {
			extra = fmt.Sprintf(" (stream_offset=%d, span_len=%d)", rel.StreamOffset.V, rel.SpanLen.V)
		}
		te := TimelineEvent{
			RelUs:         relUs(rel.TsNs, baseNs),
			TsNs:          rel.TsNs,
			EvidenceLevel: int(rel.Event.EvidenceLevel),
			EvidenceLabel: evLabel(rel.Event.EvidenceLevel),
			Stage:         "RELATION",
			Title:         "对象派生/交接 (" + rel.RelTypeName + ")",
			Detail:        fmt.Sprintf("%s #%d → #%d%s", rel.RelTypeName, rel.SrcObjectID, rel.DstObjectID, extra),
			ObjectID:      rel.DstObjectID,
		}
		s.fillProbeMeta(&te, rel.Event)
		addEv(te)
		if rel.UnknownPredecessors {
			addEv(TimelineEvent{
				RelUs: relUs(rel.TsNs, baseNs), TsNs: rel.TsNs,
				EvidenceLevel: int(wire.EvidenceGap), EvidenceLabel: evLabel(wire.EvidenceGap),
				Stage: "GAP", Title: "合并前驱缺失",
				Detail: "存在未追踪到的输入前驱 (UNKNOWN_PREDECESSORS)", ObjectID: rel.DstObjectID,
			})
		}
		if rel.SuccessorTruncated {
			addEv(TimelineEvent{
				RelUs: relUs(rel.TsNs, baseNs), TsNs: rel.TsNs,
				EvidenceLevel: int(wire.EvidenceGap), EvidenceLabel: evLabel(wire.EvidenceGap),
				Stage: "GAP", Title: "分段遍历截断",
				Detail: "超出最大遍历步长，部分后继段未追踪 (SUCCESSOR_TRUNCATED)", ObjectID: rel.DstObjectID,
			})
		}
	}

	for _, oid := range br.ObjectIDs {
		on := s.Objects[oid]
		if len(on.Incoming) > 1 {
			preds := make([]string, len(on.Incoming))
			for i, r := range on.Incoming {
				preds[i] = fmt.Sprintf("#%d", r.SrcObjectID)
			}
			addEv(TimelineEvent{
				RelUs: relUs(on.FirstTsNs, baseNs), TsNs: on.FirstTsNs,
				EvidenceLevel: int(wire.EvidenceDirect), EvidenceLabel: evLabel(wire.EvidenceDirect),
				Stage: "MERGE", Title: "多前驱合并",
				Detail: fmt.Sprintf("对象 #%d 汇聚自前驱 [%s]", oid, strings.Join(preds, ", ")), ObjectID: oid,
			})
		}
	}

	var rewrites []*wire.Event
	if len(br.Summaries) > 1 {
		rewrites = br.Summaries[1:]
	}
	rwIdx := 0
	emitRewrite := func(rws *wire.Event) {
		te := TimelineEvent{
			RelUs:         relUs(rws.TsNs, baseNs),
			TsNs:          rws.TsNs,
			EvidenceLevel: int(rws.EvidenceLevel),
			EvidenceLabel: evLabel(rws.EvidenceLevel),
			Stage:         "SUMMARY_REWRITE",
			Title:         "原地包头改写",
			Detail:        fmt.Sprintf("object_id=#%d  %s", rws.ObjectID, formatSummaryBrief(rws)),
			ObjectID:      rws.ObjectID,
		}
		s.fillProbeMeta(&te, rws)
		addEv(te)
	}

	lastClassID := uint64(0)
	emitClassStep := func(ev *wire.Event, cid uint64, direct bool) {
		cStr := FormatTCHandle(Some(cid))
		ci := s.ResolveClassInfo(ev.U("ifindex"), cid, evOpt(ev, "dev_gen"), Some(ev.TsNs))
		lvl := uint8(wire.EvidenceContractDerived)
		if direct {
			lvl = ev.EvidenceLevel
			if lvl == 0 {
				lvl = wire.EvidenceDirect
			}
		}
		var detailParts []string
		if sum := FormatClassSummary(ci); sum != "" {
			detailParts = append(detailParts, sum)
		}
		if direct {
			if rc, ok := ev.I("raw_ret"); ok {
				detailParts = append(detailParts, fmt.Sprintf("tcf_classify verdict=%d", rc))
			} else {
				detailParts = append(detailParts, "TC 过滤器直接命中子类 "+cStr)
			}
		} else {
			detailParts = append(detailParts, "由下级队列 parent="+cStr+" 推导归属子类")
		}
		te := TimelineEvent{
			RelUs:         relUs(ev.TsNs, baseNs),
			TsNs:          ev.TsNs,
			EvidenceLevel: int(lvl),
			EvidenceLabel: evLabel(lvl),
			Stage:         "CLASSIFY",
			StageCode:     wire.StageClassify,
			Title:         "TC 规则命中子类 CLASS " + cStr,
			Detail:        strings.Join(detailParts, " · "),
			ObjectID:      ev.ObjectID,
			QdiscHandle:   cStr,
		}
		s.fillProbeMeta(&te, ev)
		addEv(te)
		lastClassID = cid
	}

	steps := br.Steps
	for i := 0; i < len(steps); {
		st := steps[i]
		for rwIdx < len(rewrites) && rewrites[rwIdx].TsNs <= st.TsNs {
			emitRewrite(rewrites[rwIdx])
			rwIdx++
		}
		stage := st.Stage()
		dev := s.ResolveDevName(st.U("ifindex"), evOpt(st, "dev_gen"), evOpt(st, "netns_inum"))

		// Direct kr_tcf_classify step (qdisc_handle==0, classid!=0)
		if stage == wire.StageClassify && st.U("qdisc_handle") == 0 && st.U("classid") != 0 {
			emitClassStep(st, st.U("classid"), true)
			i++
			continue
		}

		// Collapse consecutive non-visit CLASSIFY / hierarchy QDISC_ENQ(visit_id==0) steps
		if stage == wire.StageClassify || (stage == wire.StageQdiscEnq && st.U("visit_id") == 0) {
			if cid := st.U("classid"); cid != 0 && cid != lastClassID {
				emitClassStep(st, cid, false)
			}
			chain := []*wire.Event{st}
			j := i + 1
			for j < len(steps) {
				nx := steps[j]
				ns := nx.Stage()
				if nx.ObjectID == st.ObjectID && (ns == wire.StageClassify || (ns == wire.StageQdiscEnq && nx.U("visit_id") == 0)) {
					if ns == wire.StageClassify && nx.U("qdisc_handle") == 0 && nx.U("classid") != 0 {
						break
					}
					if ncid := nx.U("classid"); ncid != 0 && ncid != lastClassID {
						break
					}
					chain = append(chain, nx)
					j++
				} else {
					break
				}
			}
			lbls := make([]string, len(chain))
			eids := make([]string, len(chain))
			for k, e := range chain {
				lbls[k] = s.qdiscStepLabel(e)
				eids[k] = e.EventID()
			}
			te := TimelineEvent{
				RelUs:         relUs(st.TsNs, baseNs),
				TsNs:          st.TsNs,
				EvidenceLevel: int(st.EvidenceLevel),
				EvidenceLabel: evLabel(st.EvidenceLevel),
				Stage:         "CLASSIFY",
				StageCode:     stage,
				Title:         strings.Join(lbls, " → "),
				Detail:        "实读各级 Qdisc 分类层级 handle/parent",
				ObjectID:      st.ObjectID,
				QdiscHandle:   FormatTCHandle(evOpt(st, "qdisc_handle")),
			}
			s.fillProbeMeta(&te, st)
			te.EventID = strings.Join(eids, ",")
			addEv(te)
			i = j
			continue
		}

		if stage == wire.StageEntry {
			tid := st.U("ctx_tid")
			if !st.Has("ctx_tid") && sg.Attr.EnqueueTid != nil {
				tid = *sg.Attr.EnqueueTid
			}
			inTask := st.Flags&wire.EvFlagInTask != 0
			ctxTag := "softirq"
			if inTask && tid != 0 {
				ctxTag = "in_task"
			}
			te := TimelineEvent{
				RelUs:         relUs(st.TsNs, baseNs),
				TsNs:          st.TsNs,
				EvidenceLevel: int(st.EvidenceLevel),
				EvidenceLabel: evLabel(st.EvidenceLevel),
				Stage:         "ENTRY",
				StageCode:     stage,
				Title:         "入口准入 (" + dev + ")",
				Detail:        fmt.Sprintf("dev=%s, object_id=#%d, enqueue_tid=%d (%s)", dev, st.ObjectID, tid, ctxTag),
				ObjectID:      st.ObjectID,
			}
			s.fillProbeMeta(&te, st)
			te.Tid = u64p(tid)
			addEv(te)
			i++
			continue
		}

		if v, ok := visitByEntry[st.EventID()]; ok {
			if cid := st.U("classid"); cid != 0 && cid != lastClassID {
				emitClassStep(st, cid, false)
			} else if cid == 0 && v.QdiscHandle == 0 && isParentTCClass(v.QdiscParent) && v.QdiscParent != lastClassID {
				emitClassStep(st, v.QdiscParent, false)
			}
			qlbl := s.visitQueueLabel(v, st)
			act := "接收入队"
			if v.VisitKind != "qdisc" {
				act = "重新排队入队"
			}
			note := ""
			if v.EnqDropped {
				note = " -> 入队即丢弃 (NET_XMIT_DROP)"
			} else if v.EnqCN {
				note = " [NET_XMIT_CN 拥塞提示]"
			}
			if isParentTCClass(v.QdiscParent) {
				if ci := s.ResolveClassInfo(v.Ifindex, v.QdiscParent, Some(v.DevGen), Some(st.TsNs)); ci != nil {
					if sum := FormatClassSummary(ci); sum != "" {
						note += " · " + sum
					}
				}
			}
			te := TimelineEvent{
				RelUs:         relUs(st.TsNs, baseNs),
				TsNs:          st.TsNs,
				EvidenceLevel: int(st.EvidenceLevel),
				EvidenceLabel: evLabel(st.EvidenceLevel),
				Stage:         stageName(stage),
				StageCode:     stage,
				Title:         qlbl + " " + act,
				Detail:        fmt.Sprintf("visit #%d 开始%s", v.VisitID, note),
				ObjectID:      st.ObjectID,
				VisitID:       u64p(v.VisitID),
				QdiscHandle:   FormatTCHandle(Some(v.QdiscHandle)),
				Txq:           optPtr(v.Txq),
			}
			s.fillProbeMeta(&te, st)
			if te.Tid == nil && sg.Attr.EnqueueTid != nil {
				te.Tid = sg.Attr.EnqueueTid
			}
			addEv(te)
			if !v.Paired && !v.EnqDropped {
				addEv(TimelineEvent{
					RelUs: relUs(st.TsNs, baseNs), TsNs: st.TsNs,
					EvidenceLevel: int(wire.EvidenceGap), EvidenceLabel: evLabel(wire.EvidenceGap),
					Stage: "GAP", Title: "队列访问未闭合",
					Detail:   fmt.Sprintf("visit #%d 缺少匹配出队/丢弃事件，不计算伪驻留时间", v.VisitID),
					ObjectID: st.ObjectID, VisitID: u64p(v.VisitID),
				})
			}
			i++
			continue
		}

		if v, ok := visitByExit[st.EventID()]; ok {
			qlbl := s.visitQueueLabel(v, st)
			var sojPtr *float64
			if v.SojournNs != nil {
				sojPtr = f64p(round3(float64(*v.SojournNs) / 1000.0))
			}
			lvl := st.EvidenceLevel
			var title, detail string
			if stage == wire.StageDrop {
				title = qlbl + " 队列内淘汰丢弃"
				sojTxt := ""
				if v.SojournNs != nil {
					sojTxt = "，丢弃前停留 " + fmtDurUsText(*v.SojournNs)
				}
				detail = fmt.Sprintf("visit #%d 闭合%s", v.VisitID, sojTxt)
			} else if v.SojournNs != nil {
				title = qlbl + " 出队"
				xth := ""
				if v.CrossThreadDequeue {
					xth = "，由另一线程出队"
				}
				detail = fmt.Sprintf("本次停留 %s (visit #%d 闭合%s)", fmtDurUsText(*v.SojournNs), v.VisitID, xth)
			} else {
				lvl = wire.EvidenceGap
				title = qlbl + " 出队 (未配对)"
				detail = fmt.Sprintf("visit #%d 缺少唯一入队，不计算驻留", v.VisitID)
			}
			te := TimelineEvent{
				RelUs:         relUs(st.TsNs, baseNs),
				TsNs:          st.TsNs,
				EvidenceLevel: int(lvl),
				EvidenceLabel: evLabel(lvl),
				Stage:         stageName(stage),
				StageCode:     stage,
				Title:         title,
				Detail:        detail,
				SojournUs:     sojPtr,
				CrossThread:   v.CrossThreadDequeue,
				ObjectID:      st.ObjectID,
				VisitID:       u64p(v.VisitID),
				QdiscHandle:   FormatTCHandle(Some(v.QdiscHandle)),
				Txq:           optPtr(v.Txq),
			}
			s.fillProbeMeta(&te, st)
			if v.Entry != nil {
				if v.Entry.CPU != wire.UserspaceCPU {
					ec := v.Entry.CPU
					te.EnqueueCPU = &ec
					if te.CPU != nil && *te.CPU != ec {
						te.CrossCPU = true
					}
				}
				if et, ok := v.Entry.Get("ctx_tid"); ok {
					te.EnqueueTid = u64p(et)
				} else if sg.Attr.EnqueueTid != nil {
					te.EnqueueTid = sg.Attr.EnqueueTid
				}
			}
			addEv(te)
			i++
			continue
		}

		switch stage {
		case wire.StageQdiscEnqRet:
			rc, hasRc := st.I("raw_ret")
			if hasRc && rc != 0 {
				te := TimelineEvent{
					RelUs: relUs(st.TsNs, baseNs), TsNs: st.TsNs,
					EvidenceLevel: int(st.EvidenceLevel), EvidenceLabel: evLabel(st.EvidenceLevel),
					Stage: "QDISC_ENQ_RET", StageCode: stage, Title: "入队返回",
					Detail: fmt.Sprintf("call_id=%d, rc=%d", st.U("call_id"), rc), ObjectID: st.ObjectID,
				}
				s.fillProbeMeta(&te, st)
				addEv(te)
			}
		case wire.StageBypassDirect:
			te := TimelineEvent{
				RelUs: relUs(st.TsNs, baseNs), TsNs: st.TsNs,
				EvidenceLevel: int(st.EvidenceLevel), EvidenceLabel: evLabel(st.EvidenceLevel),
				Stage: "BYPASS_DIRECT", StageCode: stage, Title: "直接旁路发送 (" + dev + ")",
				Detail: dev + " sch_direct_xmit (空队列旁路，0 队列驻留)", ObjectID: st.ObjectID,
			}
			s.fillProbeMeta(&te, st)
			addEv(te)
		case wire.StageHandoffLayer:
			te := TimelineEvent{
				RelUs: relUs(st.TsNs, baseNs), TsNs: st.TsNs,
				EvidenceLevel: int(st.EvidenceLevel), EvidenceLabel: evLabel(st.EvidenceLevel),
				Stage: "HANDOFF_LAYER", StageCode: stage, Title: "跨层/设备交接 (" + dev + ")",
				Detail: fmt.Sprintf("%s (合法延续 object_id=#%d)", dev, st.ObjectID), ObjectID: st.ObjectID,
			}
			s.fillProbeMeta(&te, st)
			addEv(te)
		case wire.StageXmitStart:
			txq := st.U("txq")
			xtid := st.U("ctx_tid")
			var pairedRet *wire.Event
			if cid := st.U("call_id"); cid != 0 {
				for _, cp := range br.Calls {
					if cp.Entry == st && cp.Ret != nil {
						pairedRet = cp.Ret
						break
					}
				}
			}
			var detail string
			if pairedRet != nil {
				rc, hasRc := pairedRet.I("raw_ret")
				rcStr := "NETDEV_TX_OK, 驱动接受"
				if hasRc && rc != 0 {
					rcStr = fmt.Sprintf("NETDEV_TX_BUSY/rc=%d", rc)
				}
				detail = fmt.Sprintf("%s 返回 (%s, xmit_tid=%d)", fmtRelUsText(pairedRet.TsNs, baseNs), rcStr, xtid)
			} else {
				detail = fmt.Sprintf("ndo_start_xmit (xmit_tid=%d)", xtid)
			}
			te := TimelineEvent{
				RelUs: relUs(st.TsNs, baseNs), TsNs: st.TsNs,
				EvidenceLevel: int(st.EvidenceLevel), EvidenceLabel: evLabel(st.EvidenceLevel),
				Stage: "XMIT_START", StageCode: stage,
				Title:  fmt.Sprintf("TX queue %d 提交驱动 (%s)", txq, dev),
				Detail: detail, ObjectID: st.ObjectID, Txq: u64p(txq),
			}
			s.fillProbeMeta(&te, st)
			addEv(te)
		case wire.StageXmitRet:
			shown := false
			for _, cp := range br.Calls {
				if cp.Ret == st {
					for _, x := range steps {
						if x == cp.Entry {
							shown = true
							break
						}
					}
				}
			}
			if !shown {
				rc, hasRc := st.I("raw_ret")
				rcStr := "NETDEV_TX_OK"
				if hasRc && rc != 0 {
					rcStr = fmt.Sprintf("NETDEV_TX_BUSY/rc=%d", rc)
				}
				te := TimelineEvent{
					RelUs: relUs(st.TsNs, baseNs), TsNs: st.TsNs,
					EvidenceLevel: int(st.EvidenceLevel), EvidenceLabel: evLabel(st.EvidenceLevel),
					Stage: "XMIT_RET", StageCode: stage, Title: "驱动发送返回",
					Detail: fmt.Sprintf("%s (call_id=%d)", rcStr, st.U("call_id")), ObjectID: st.ObjectID,
				}
				s.fillProbeMeta(&te, st)
				addEv(te)
			}
		default:
			sname := stageName(stage)
			te := TimelineEvent{
				RelUs: relUs(st.TsNs, baseNs), TsNs: st.TsNs,
				EvidenceLevel: int(st.EvidenceLevel), EvidenceLabel: evLabel(st.EvidenceLevel),
				Stage: sname, StageCode: stage, Title: sname,
				Detail: fmt.Sprintf("dev=%s, object_id=#%d", dev, st.ObjectID), ObjectID: st.ObjectID,
			}
			s.fillProbeMeta(&te, st)
			addEv(te)
		}
		i++
	}

	for rwIdx < len(rewrites) {
		emitRewrite(rewrites[rwIdx])
		rwIdx++
	}

	// External tcpdump candidates strictly as Level-3 ANNOTATION
	for _, cand := range br.Tcpdump {
		addEv(TimelineEvent{
			RelUs:         relUs(cand.EstBoottimeNs, baseNs),
			TsNs:          cand.EstBoottimeNs,
			EvidenceLevel: int(wire.EvidenceAnnotation),
			EvidenceLabel: evLabel(wire.EvidenceAnnotation),
			Stage:         "TCPDUMP_CANDIDATE",
			Title:         fmt.Sprintf("外部抓包候选 #%d (%s)", cand.FrameIndex, cand.MatchKind),
			Detail:        fmt.Sprintf("len=%dB, Δt=%.1f µs (±%s) — %s", cand.OrigLen, float64(cand.DeltaFromXmitNs)/1000.0, fmtDurUsText(uint64(cand.ClockErrNs)), cand.Note),
			ObjectID:      br.LeafObjectID(),
		})
	}

	// Explicit gap banner if branch is incomplete/unknown with quality/tail reasons not yet surfaced inline
	for _, g := range br.GapReasons {
		switch g {
		case "UNCLOSED_VISIT":
			continue
		default:
			addEv(TimelineEvent{
				RelUs: relUs(br.EndTsNs, baseNs), TsNs: br.EndTsNs,
				EvidenceLevel: int(wire.EvidenceGap), EvidenceLabel: evLabel(wire.EvidenceGap),
				Stage: "GAP", Title: "完整性缺口 (" + g + ")",
				Detail: "受影响支路标记为 " + br.Completeness + ": " + g, ObjectID: br.LeafObjectID(),
			})
		}
	}

	// Explicit scope boundary footer
	addEv(TimelineEvent{
		RelUs:         relUs(br.EndTsNs, baseNs),
		TsNs:          br.EndTsNs,
		EvidenceLevel: int(wire.EvidenceContractDerived),
		EvidenceLabel: evLabel(wire.EvidenceContractDerived),
		Stage:         "BOUNDARY",
		Title:         "本次观测终点 (" + br.EndReasonName + ")",
		Detail:        bd.BoundaryNote,
		ObjectID:      br.LeafObjectID(),
	})

	return bd
}

func (s *Session) visitQueueLabel(v *QueueVisit, st *wire.Event) string {
	switch v.VisitKind {
	case "requeue_gso":
		return "gso_skb 重排队列"
	case "requeue_bad_txq":
		return "skb_bad_txq 队列"
	default:
		return s.qdiscStepLabelWithHint(st, s.resolveVisitQdiscKind(v))
	}
}
