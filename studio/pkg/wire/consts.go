// Package wire implements the pktpath v1.0 canonical offline wire format
// (include/pktpath_wire.h) and the crash-tolerant session directory loader.
//
// It is a byte-for-byte Go port of analyzer/wire.py.
package wire

// Wire format constants.
const (
	BlockMagic        uint32 = 0x42544B50 // "PKTB" little-endian
	WireMajor         uint16 = 1
	WireMinor         uint16 = 0
	MaxPayloadLen     uint32 = 16 * 1024 * 1024
	TLVMustUnderstand uint16 = 0x8000
	UserspaceCPU      uint32 = 0xFFFFFFFF

	BlockHdrSize = 64
	EventHdrSize = 40
	TLVHdrSize   = 4
	CRC32Size    = 4

	BlockFlagZstd uint32 = 1 << 0
)

// Block types.
const (
	BlockEventBatch        uint16 = 1
	BlockQualityCheckpoint uint16 = 2
	BlockDictDelta         uint16 = 3
	BlockEndMarker         uint16 = 4
)

// Producer types.
const (
	ProdKernelBPF    uint16 = 1
	ProdRtnetlink    uint16 = 2
	ProdUserspaceApp uint16 = 3
	ProdController   uint16 = 4
)

// Event kinds.
const (
	KindObject   uint16 = 1
	KindStep     uint16 = 2
	KindRelation uint16 = 3
	KindSummary  uint16 = 4
	KindQState   uint16 = 5
	KindQuality  uint16 = 6
)

// Object types.
const (
	ObjSKB      uint8 = 1
	ObjXDPFrame uint8 = 2
	ObjSockSpan uint8 = 3
	ObjAppMsg   uint8 = 4
	ObjHWDesc   uint8 = 5
)

// Evidence levels.
const (
	EvidenceDirect          uint8 = 1
	EvidenceContractDerived uint8 = 2
	EvidenceAnnotation      uint8 = 3
	EvidenceGap             uint8 = 4
)

// Event flags.
const (
	EvFlagInTask          uint32 = 1 << 0
	EvFlagNonlinearTrunc  uint32 = 1 << 1
	EvFlagPartialCoverage uint32 = 1 << 2
)

// OBJECT end reasons.
const (
	EndOpen              = 0
	EndTxOK              = 1
	EndDrop              = 2
	EndConsume           = 3
	EndSockEnqueue       = 4
	EndAppRead           = 5
	EndTimeoutTruncated  = 6
	EndConflictTruncated = 7
	EndBoundary          = 8
)

// Directions.
const (
	DirRX  = 0
	DirTX  = 1
	DirFWD = 2
)

// STEP stages.
const (
	StageEntry         = 1
	StageClassify      = 2
	StageQdiscEnq      = 3
	StageQdiscEnqRet   = 4
	StageQdiscDeq      = 5
	StageBypassDirect  = 6
	StageRequeueGSO    = 7
	StageRequeueBadTxq = 8
	StageXmitStart     = 9
	StageXmitRet       = 10
	StageDeliverSock   = 11
	StageDrop          = 12
	StageConsume       = 13
	StageHandoffLayer  = 14
)

// RELATION types.
const (
	RelClone   = 1
	RelCopy    = 2
	RelReplace = 3
	RelSegment = 4
	RelMerge   = 5
	RelHandoff = 6
	RelSpanMap = 7
)

// RELATION flags.
const (
	RelFlagSuccessorTruncated  = 1 << 0
	RelFlagUnknownPredecessors = 1 << 1
)

// Link types.
const (
	LinkTypeEthernet = 1
	LinkTypeRawIP    = 101
)

// QSTATE ops.
const (
	QStateTxqStop  = 1
	QStateTxqWake  = 2
	QStateBQLLimit = 3
)

// QUALITY kinds.
const (
	QualMissedDelta       = 1
	QualRbDropDelta       = 2
	QualEpochSwitch       = 3
	QualRetUnmatched      = 4
	QualIdentityConflict  = 5
	QualRingEvictedPrefix = 6
	QualTopoDesync        = 7
)

// Canonical TLV tags.
const (
	TLVObjSampleID   uint16 = 0x0001
	TLVObjEndReason  uint16 = 0x0002
	TLVObjDropReason uint16 = 0x0003

	TLVStepVisitID     uint16 = 0x0101
	TLVStepCallID      uint16 = 0x0102
	TLVStepNetnsInum   uint16 = 0x0103
	TLVStepDevGen      uint16 = 0x0104
	TLVStepIfindex     uint16 = 0x0105
	TLVStepDir         uint16 = 0x0106
	TLVStepStage       uint16 = 0x0107
	TLVStepQueueGen    uint16 = 0x0108
	TLVStepQdiscHandle uint16 = 0x0109
	TLVStepQdiscParent uint16 = 0x010A
	TLVStepClassid     uint16 = 0x010B
	TLVStepBucket      uint16 = 0x010C
	TLVStepTxq         uint16 = 0x010D
	TLVStepRawRet      uint16 = 0x010E
	TLVStepCtxTid      uint16 = 0x010F

	TLVRelOpID         uint16 = 0x0201
	TLVRelType         uint16 = 0x0202
	TLVRelSrcObjectID  uint16 = 0x0203
	TLVRelDstObjectID  uint16 = 0x0204
	TLVRelFlags        uint16 = 0x0205
	TLVRelStreamOffset uint16 = 0x0206
	TLVRelSpanLen      uint16 = 0x0207

	TLVSumPktLen      uint16 = 0x0301
	TLVSumLinearLen   uint16 = 0x0302
	TLVSumIfindex     uint16 = 0x0303
	TLVSumDir         uint16 = 0x0304
	TLVSumIPVersion   uint16 = 0x0305
	TLVSumL4Proto     uint16 = 0x0306
	TLVSumSrcIP       uint16 = 0x0307
	TLVSumDstIP       uint16 = 0x0308
	TLVSumSrcPort     uint16 = 0x0309
	TLVSumDstPort     uint16 = 0x030A
	TLVSumTCPSeq      uint16 = 0x030B
	TLVSumTCPSeqEnd   uint16 = 0x030C
	TLVSumTCPFlags    uint16 = 0x030D
	TLVSumIPID        uint16 = 0x030E
	TLVSumFragFlags   uint16 = 0x030F
	TLVSumSkbHash     uint16 = 0x0310
	TLVSumSkbMark     uint16 = 0x0311
	TLVSumSkbPriority uint16 = 0x0312
	TLVSumUID         uint16 = 0x0313
	TLVSumTgid        uint16 = 0x0314
	TLVSumComm        uint16 = 0x0315
	TLVSumEnqueueTid  uint16 = 0x0316
	TLVSumSkbCreateTs uint16 = 0x0317
	TLVSumHdrBytes    uint16 = 0x0319
	TLVSumLinktype     uint16 = 0x031A
	TLVSumPluginVal0   uint16 = 0x0320
	TLVSumPluginVal1   uint16 = 0x0321
	TLVSumPluginVal2   uint16 = 0x0322
	TLVSumPluginVal3   uint16 = 0x0323
	TLVSumPluginVal4   uint16 = 0x0324
	TLVSumPluginVal5   uint16 = 0x0325
	TLVSumPluginVal6   uint16 = 0x0326
	TLVSumPluginVal7   uint16 = 0x0327
	TLVSumPluginVal8   uint16 = 0x0328
	TLVSumPluginVal9   uint16 = 0x0329
	TLVSumPluginVal10  uint16 = 0x032A
	TLVSumPluginVal11  uint16 = 0x032B
	TLVSumPluginVal12  uint16 = 0x032C
	TLVSumPluginVal13  uint16 = 0x032D
	TLVSumPluginVal14  uint16 = 0x032E
	TLVSumPluginVal15  uint16 = 0x032F

	TLVQSQueueGen uint16 = 0x0401
	TLVQSIfindex  uint16 = 0x0402
	TLVQSTxq      uint16 = 0x0403
	TLVQSStateOp  uint16 = 0x0404
	TLVQSValue    uint16 = 0x0405

	TLVQualKind        uint16 = 0x0501
	TLVQualSiteDictIdx uint16 = 0x0502
	TLVQualWinStartNs  uint16 = 0x0503
	TLVQualWinEndNs    uint16 = 0x0504
	TLVQualCount       uint16 = 0x0505
)

type tlvCodec uint8

const (
	codecU8 tlvCodec = iota + 1
	codecU16
	codecU32
	codecS32
	codecU64
	codecIP
	codecComm
	codecBytes
)

type tlvSpec struct {
	name  string
	codec tlvCodec
}

// knownTLVs maps base tag -> (field name, codec), identical to wire.py KNOWN_TLV_SPECS.
var knownTLVs = map[uint16]tlvSpec{
	TLVObjSampleID:   {"sample_id", codecU64},
	TLVObjEndReason:  {"end_reason", codecU16},
	TLVObjDropReason: {"drop_reason", codecU32},

	TLVStepVisitID:     {"visit_id", codecU64},
	TLVStepCallID:      {"call_id", codecU64},
	TLVStepNetnsInum:   {"netns_inum", codecU32},
	TLVStepDevGen:      {"dev_gen", codecU32},
	TLVStepIfindex:     {"ifindex", codecU32},
	TLVStepDir:         {"dir", codecU8},
	TLVStepStage:       {"stage", codecU8},
	TLVStepQueueGen:    {"queue_gen", codecU64},
	TLVStepQdiscHandle: {"qdisc_handle", codecU32},
	TLVStepQdiscParent: {"qdisc_parent", codecU32},
	TLVStepClassid:     {"classid", codecU32},
	TLVStepBucket:      {"bucket", codecU32},
	TLVStepTxq:         {"txq", codecU16},
	TLVStepRawRet:      {"raw_ret", codecS32},
	TLVStepCtxTid:      {"ctx_tid", codecU32},

	TLVRelOpID:         {"op_id", codecU64},
	TLVRelType:         {"rel_type", codecU8},
	TLVRelSrcObjectID:  {"src_object_id", codecU64},
	TLVRelDstObjectID:  {"dst_object_id", codecU64},
	TLVRelFlags:        {"rel_flags", codecU8},
	TLVRelStreamOffset: {"stream_offset", codecU64},
	TLVRelSpanLen:      {"span_len", codecU32},

	TLVSumPktLen:      {"pkt_len", codecU32},
	TLVSumLinearLen:   {"linear_len", codecU32},
	TLVSumIfindex:     {"ifindex", codecU32},
	TLVSumDir:         {"dir", codecU8},
	TLVSumIPVersion:   {"ip_version", codecU8},
	TLVSumL4Proto:     {"l4_proto", codecU8},
	TLVSumSrcIP:       {"src_ip", codecIP},
	TLVSumDstIP:       {"dst_ip", codecIP},
	TLVSumSrcPort:     {"src_port", codecU16},
	TLVSumDstPort:     {"dst_port", codecU16},
	TLVSumTCPSeq:      {"tcp_seq", codecU32},
	TLVSumTCPSeqEnd:   {"tcp_seq_end", codecU32},
	TLVSumTCPFlags:    {"tcp_flags", codecU8},
	TLVSumIPID:        {"ip_id", codecU16},
	TLVSumFragFlags:   {"frag_flags", codecU8},
	TLVSumSkbHash:     {"skb_hash", codecU32},
	TLVSumSkbMark:     {"skb_mark", codecU32},
	TLVSumSkbPriority: {"skb_priority", codecU32},
	TLVSumUID:         {"uid", codecU32},
	TLVSumTgid:        {"tgid", codecU32},
	TLVSumComm:        {"comm", codecComm},
	TLVSumEnqueueTid:  {"enqueue_tid", codecU32},
	TLVSumSkbCreateTs: {"skb_create_ts", codecU64},
	TLVSumHdrBytes:    {"hdr_bytes", codecBytes},
	TLVSumLinktype:    {"linktype", codecU16},
	TLVSumPluginVal0:  {"plugin_val0", codecU64},
	TLVSumPluginVal1:  {"plugin_val1", codecU64},
	TLVSumPluginVal2:  {"plugin_val2", codecU64},
	TLVSumPluginVal3:  {"plugin_val3", codecU64},
	TLVSumPluginVal4:  {"plugin_val4", codecU64},
	TLVSumPluginVal5:  {"plugin_val5", codecU64},
	TLVSumPluginVal6:  {"plugin_val6", codecU64},
	TLVSumPluginVal7:  {"plugin_val7", codecU64},
	TLVSumPluginVal8:  {"plugin_val8", codecU64},
	TLVSumPluginVal9:  {"plugin_val9", codecU64},
	TLVSumPluginVal10: {"plugin_val10", codecU64},
	TLVSumPluginVal11: {"plugin_val11", codecU64},
	TLVSumPluginVal12: {"plugin_val12", codecU64},
	TLVSumPluginVal13: {"plugin_val13", codecU64},
	TLVSumPluginVal14: {"plugin_val14", codecU64},
	TLVSumPluginVal15: {"plugin_val15", codecU64},

	TLVQSQueueGen: {"queue_gen", codecU64},
	TLVQSIfindex:  {"ifindex", codecU32},
	TLVQSTxq:      {"txq", codecU16},
	TLVQSStateOp:  {"state_op", codecU8},
	TLVQSValue:    {"value", codecU32},

	TLVQualKind:        {"qual_kind", codecU8},
	TLVQualSiteDictIdx: {"qual_site_dict_idx", codecU16},
	TLVQualWinStartNs:  {"win_start_ns", codecU64},
	TLVQualWinEndNs:    {"win_end_ns", codecU64},
	TLVQualCount:       {"count", codecU64},
}

// Human-readable name tables (matching reconstruct.py).
var (
	EndReasonNames = map[int]string{
		EndOpen: "OPEN", EndTxOK: "TX_OK", EndDrop: "DROP", EndConsume: "CONSUME",
		EndSockEnqueue: "SOCK_ENQUEUE", EndAppRead: "APP_READ", EndTimeoutTruncated: "TIMEOUT_TRUNCATED",
		EndConflictTruncated: "CONFLICT_TRUNCATED", EndBoundary: "BOUNDARY",
	}
	StageNames = map[int]string{
		StageEntry: "ENTRY", StageClassify: "CLASSIFY", StageQdiscEnq: "QDISC_ENQ", StageQdiscEnqRet: "QDISC_ENQ_RET",
		StageQdiscDeq: "QDISC_DEQ", StageBypassDirect: "BYPASS_DIRECT", StageRequeueGSO: "REQUEUE_GSO",
		StageRequeueBadTxq: "REQUEUE_BAD_TXQ", StageXmitStart: "XMIT_START", StageXmitRet: "XMIT_RET",
		StageDeliverSock: "DELIVER_SOCK", StageDrop: "DROP", StageConsume: "CONSUME", StageHandoffLayer: "HANDOFF_LAYER",
	}
	RelTypeNames = map[int]string{
		RelClone: "CLONE", RelCopy: "COPY", RelReplace: "REPLACE", RelSegment: "SEGMENT",
		RelMerge: "MERGE", RelHandoff: "HANDOFF", RelSpanMap: "SPAN_MAP",
	}
	QStateOpNames = map[int]string{QStateTxqStop: "TXQ_STOP", QStateTxqWake: "TXQ_WAKE", QStateBQLLimit: "BQL_LIMIT"}
	QualKindNames = map[int]string{
		QualMissedDelta: "MISSED_DELTA", QualRbDropDelta: "RB_DROP_DELTA", QualEpochSwitch: "EPOCH_SWITCH",
		QualRetUnmatched: "RET_UNMATCHED", QualIdentityConflict: "IDENTITY_CONFLICT",
		QualRingEvictedPrefix: "RING_EVICTED_PREFIX", QualTopoDesync: "TOPO_DESYNC",
	}
	EvidenceNames    = map[int]string{1: "DIRECT", 2: "CONTRACT_DERIVED", 3: "ANNOTATION", 4: "GAP"}
	EvidenceLabelsZH = map[int]string{1: "直接观测", 2: "契约推导", 3: "辅助旁注", 4: "缺口/未知"}
)
