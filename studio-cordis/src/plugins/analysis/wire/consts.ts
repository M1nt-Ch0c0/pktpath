// Pure TypeScript port of studio/pkg/wire/consts.go (erasableSyntaxOnly).

export const BLOCK_MAGIC = 0x42544b50 // "PKTB" little-endian
export const WIRE_MAJOR = 1
export const WIRE_MINOR = 0
export const MAX_PAYLOAD_LEN = 16 * 1024 * 1024
export const TLV_MUST_UNDERSTAND = 0x8000
export const USERSPACE_CPU = 0xffffffff

export const BLOCK_HDR_SIZE = 64
export const EVENT_HDR_SIZE = 40
export const TLV_HDR_SIZE = 4
export const CRC32_SIZE = 4

export const BLOCK_FLAG_ZSTD = 1 << 0

// Block types
export const BLOCK_EVENT_BATCH = 1
export const BLOCK_QUALITY_CHECKPOINT = 2
export const BLOCK_DICT_DELTA = 3
export const BLOCK_END_MARKER = 4

// Producer types
export const PROD_KERNEL_BPF = 1
export const PROD_RTNETLINK = 2
export const PROD_USERSPACE_APP = 3
export const PROD_CONTROLLER = 4

// Event kinds
export const KIND_OBJECT = 1
export const KIND_STEP = 2
export const KIND_RELATION = 3
export const KIND_SUMMARY = 4
export const KIND_QSTATE = 5
export const KIND_QUALITY = 6

// Object types
export const OBJ_SKB = 1
export const OBJ_XDP_FRAME = 2
export const OBJ_SOCK_SPAN = 3
export const OBJ_APP_MSG = 4
export const OBJ_HW_DESC = 5

// Evidence levels
export const EVIDENCE_DIRECT = 1
export const EVIDENCE_CONTRACT_DERIVED = 2
export const EVIDENCE_ANNOTATION = 3
export const EVIDENCE_GAP = 4

// Event flags
export const EV_FLAG_IN_TASK = 1 << 0
export const EV_FLAG_NONLINEAR_TRUNC = 1 << 1
export const EV_FLAG_PARTIAL_COVERAGE = 1 << 2

// OBJECT end reasons
export const END_OPEN = 0
export const END_TX_OK = 1
export const END_DROP = 2
export const END_CONSUME = 3
export const END_SOCK_ENQUEUE = 4
export const END_APP_READ = 5
export const END_TIMEOUT_TRUNCATED = 6
export const END_CONFLICT_TRUNCATED = 7
export const END_BOUNDARY = 8

// Directions
export const DIR_RX = 0
export const DIR_TX = 1
export const DIR_FWD = 2

// STEP stages
export const STAGE_ENTRY = 1
export const STAGE_CLASSIFY = 2
export const STAGE_QDISC_ENQ = 3
export const STAGE_QDISC_ENQ_RET = 4
export const STAGE_QDISC_DEQ = 5
export const STAGE_BYPASS_DIRECT = 6
export const STAGE_REQUEUE_GSO = 7
export const STAGE_REQUEUE_BAD_TXQ = 8
export const STAGE_XMIT_START = 9
export const STAGE_XMIT_RET = 10
export const STAGE_DELIVER_SOCK = 11
export const STAGE_DROP = 12
export const STAGE_CONSUME = 13
export const STAGE_HANDOFF_LAYER = 14

// RELATION types
export const REL_CLONE = 1
export const REL_COPY = 2
export const REL_REPLACE = 3
export const REL_SEGMENT = 4
export const REL_MERGE = 5
export const REL_HANDOFF = 6
export const REL_SPAN_MAP = 7

// RELATION flags
export const REL_FLAG_SUCCESSOR_TRUNCATED = 1 << 0
export const REL_FLAG_UNKNOWN_PREDECESSORS = 1 << 1

// Link types
export const LINK_TYPE_ETHERNET = 1
export const LINK_TYPE_RAW_IP = 101

// QSTATE ops
export const QSTATE_TXQ_STOP = 1
export const QSTATE_TXQ_WAKE = 2
export const QSTATE_BQL_LIMIT = 3

// QUALITY kinds
export const QUAL_MISSED_DELTA = 1
export const QUAL_RB_DROP_DELTA = 2
export const QUAL_EPOCH_SWITCH = 3
export const QUAL_RET_UNMATCHED = 4
export const QUAL_IDENTITY_CONFLICT = 5
export const QUAL_RING_EVICTED_PREFIX = 6
export const QUAL_TOPO_DESYNC = 7

// Canonical TLV tags
export const TLV_OBJ_SAMPLE_ID = 0x0001
export const TLV_OBJ_END_REASON = 0x0002
export const TLV_OBJ_DROP_REASON = 0x0003

export const TLV_STEP_VISIT_ID = 0x0101
export const TLV_STEP_CALL_ID = 0x0102
export const TLV_STEP_NETNS_INUM = 0x0103
export const TLV_STEP_DEV_GEN = 0x0104
export const TLV_STEP_IFINDEX = 0x0105
export const TLV_STEP_DIR = 0x0106
export const TLV_STEP_STAGE = 0x0107
export const TLV_STEP_QUEUE_GEN = 0x0108
export const TLV_STEP_QDISC_HANDLE = 0x0109
export const TLV_STEP_QDISC_PARENT = 0x010a
export const TLV_STEP_CLASSID = 0x010b
export const TLV_STEP_BUCKET = 0x010c
export const TLV_STEP_TXQ = 0x010d
export const TLV_STEP_RAW_RET = 0x010e
export const TLV_STEP_CTX_TID = 0x010f
export const TLV_STEP_TCP_SEQ = 0x0110
export const TLV_STEP_SND_CWND = 0x0111
export const TLV_STEP_SRTT_US = 0x0112

export const TLV_REL_OP_ID = 0x0201
export const TLV_REL_TYPE = 0x0202
export const TLV_REL_SRC_OBJECT_ID = 0x0203
export const TLV_REL_DST_OBJECT_ID = 0x0204
export const TLV_REL_FLAGS = 0x0205
export const TLV_REL_STREAM_OFFSET = 0x0206
export const TLV_REL_SPAN_LEN = 0x0207

export const TLV_SUM_PKT_LEN = 0x0301
export const TLV_SUM_LINEAR_LEN = 0x0302
export const TLV_SUM_IFINDEX = 0x0303
export const TLV_SUM_DIR = 0x0304
export const TLV_SUM_IP_VERSION = 0x0305
export const TLV_SUM_L4_PROTO = 0x0306
export const TLV_SUM_SRC_IP = 0x0307
export const TLV_SUM_DST_IP = 0x0308
export const TLV_SUM_SRC_PORT = 0x0309
export const TLV_SUM_DST_PORT = 0x030a
export const TLV_SUM_TCP_SEQ = 0x030b
export const TLV_SUM_TCP_SEQ_END = 0x030c
export const TLV_SUM_TCP_FLAGS = 0x030d
export const TLV_SUM_IP_ID = 0x030e
export const TLV_SUM_FRAG_FLAGS = 0x030f
export const TLV_SUM_SKB_HASH = 0x0310
export const TLV_SUM_SKB_MARK = 0x0311
export const TLV_SUM_SKB_PRIORITY = 0x0312
export const TLV_SUM_UID = 0x0313
export const TLV_SUM_TGID = 0x0314
export const TLV_SUM_COMM = 0x0315
export const TLV_SUM_ENQUEUE_TID = 0x0316
export const TLV_SUM_SKB_CREATE_TS = 0x0317
export const TLV_SUM_HDR_BYTES = 0x0319
export const TLV_SUM_LINKTYPE = 0x031a
export const TLV_SUM_PLUGIN_VAL0 = 0x0320
export const TLV_SUM_PLUGIN_VAL1 = 0x0321
export const TLV_SUM_PLUGIN_VAL2 = 0x0322
export const TLV_SUM_PLUGIN_VAL3 = 0x0323
export const TLV_SUM_PLUGIN_VAL4 = 0x0324
export const TLV_SUM_PLUGIN_VAL5 = 0x0325
export const TLV_SUM_PLUGIN_VAL6 = 0x0326
export const TLV_SUM_PLUGIN_VAL7 = 0x0327
export const TLV_SUM_PLUGIN_VAL8 = 0x0328
export const TLV_SUM_PLUGIN_VAL9 = 0x0329
export const TLV_SUM_PLUGIN_VAL10 = 0x032a
export const TLV_SUM_PLUGIN_VAL11 = 0x032b
export const TLV_SUM_PLUGIN_VAL12 = 0x032c
export const TLV_SUM_PLUGIN_VAL13 = 0x032d
export const TLV_SUM_PLUGIN_VAL14 = 0x032e
export const TLV_SUM_PLUGIN_VAL15 = 0x032f

export const TLV_QS_QUEUE_GEN = 0x0401
export const TLV_QS_IFINDEX = 0x0402
export const TLV_QS_TXQ = 0x0403
export const TLV_QS_STATE_OP = 0x0404
export const TLV_QS_VALUE = 0x0405

export const TLV_QUAL_KIND = 0x0501
export const TLV_QUAL_SITE_DICT_IDX = 0x0502
export const TLV_QUAL_WIN_START_NS = 0x0503
export const TLV_QUAL_WIN_END_NS = 0x0504
export const TLV_QUAL_COUNT = 0x0505

export type TlvCodec = 'u8' | 'u16' | 'u32' | 's32' | 'u64' | 'ip' | 'comm' | 'bytes'

export interface TlvSpec {
  readonly name: string
  readonly codec: TlvCodec
}

export const KNOWN_TLVS: ReadonlyMap<number, TlvSpec> = new Map<number, TlvSpec>([
  [TLV_OBJ_SAMPLE_ID, { name: 'sample_id', codec: 'u64' }],
  [TLV_OBJ_END_REASON, { name: 'end_reason', codec: 'u16' }],
  [TLV_OBJ_DROP_REASON, { name: 'drop_reason', codec: 'u32' }],

  [TLV_STEP_VISIT_ID, { name: 'visit_id', codec: 'u64' }],
  [TLV_STEP_CALL_ID, { name: 'call_id', codec: 'u64' }],
  [TLV_STEP_NETNS_INUM, { name: 'netns_inum', codec: 'u32' }],
  [TLV_STEP_DEV_GEN, { name: 'dev_gen', codec: 'u32' }],
  [TLV_STEP_IFINDEX, { name: 'ifindex', codec: 'u32' }],
  [TLV_STEP_DIR, { name: 'dir', codec: 'u8' }],
  [TLV_STEP_STAGE, { name: 'stage', codec: 'u8' }],
  [TLV_STEP_QUEUE_GEN, { name: 'queue_gen', codec: 'u64' }],
  [TLV_STEP_QDISC_HANDLE, { name: 'qdisc_handle', codec: 'u32' }],
  [TLV_STEP_QDISC_PARENT, { name: 'qdisc_parent', codec: 'u32' }],
  [TLV_STEP_CLASSID, { name: 'classid', codec: 'u32' }],
  [TLV_STEP_BUCKET, { name: 'bucket', codec: 'u32' }],
  [TLV_STEP_TXQ, { name: 'txq', codec: 'u16' }],
  [TLV_STEP_RAW_RET, { name: 'raw_ret', codec: 's32' }],
  [TLV_STEP_CTX_TID, { name: 'ctx_tid', codec: 'u32' }],
  [TLV_STEP_TCP_SEQ, { name: 'tcp_seq', codec: 'u32' }],
  [TLV_STEP_SND_CWND, { name: 'snd_cwnd', codec: 'u32' }],
  [TLV_STEP_SRTT_US, { name: 'srtt_us', codec: 'u32' }],

  [TLV_REL_OP_ID, { name: 'op_id', codec: 'u64' }],
  [TLV_REL_TYPE, { name: 'rel_type', codec: 'u8' }],
  [TLV_REL_SRC_OBJECT_ID, { name: 'src_object_id', codec: 'u64' }],
  [TLV_REL_DST_OBJECT_ID, { name: 'dst_object_id', codec: 'u64' }],
  [TLV_REL_FLAGS, { name: 'rel_flags', codec: 'u8' }],
  [TLV_REL_STREAM_OFFSET, { name: 'stream_offset', codec: 'u64' }],
  [TLV_REL_SPAN_LEN, { name: 'span_len', codec: 'u32' }],

  [TLV_SUM_PKT_LEN, { name: 'pkt_len', codec: 'u32' }],
  [TLV_SUM_LINEAR_LEN, { name: 'linear_len', codec: 'u32' }],
  [TLV_SUM_IFINDEX, { name: 'ifindex', codec: 'u32' }],
  [TLV_SUM_DIR, { name: 'dir', codec: 'u8' }],
  [TLV_SUM_IP_VERSION, { name: 'ip_version', codec: 'u8' }],
  [TLV_SUM_L4_PROTO, { name: 'l4_proto', codec: 'u8' }],
  [TLV_SUM_SRC_IP, { name: 'src_ip', codec: 'ip' }],
  [TLV_SUM_DST_IP, { name: 'dst_ip', codec: 'ip' }],
  [TLV_SUM_SRC_PORT, { name: 'src_port', codec: 'u16' }],
  [TLV_SUM_DST_PORT, { name: 'dst_port', codec: 'u16' }],
  [TLV_SUM_TCP_SEQ, { name: 'tcp_seq', codec: 'u32' }],
  [TLV_SUM_TCP_SEQ_END, { name: 'tcp_seq_end', codec: 'u32' }],
  [TLV_SUM_TCP_FLAGS, { name: 'tcp_flags', codec: 'u8' }],
  [TLV_SUM_IP_ID, { name: 'ip_id', codec: 'u16' }],
  [TLV_SUM_FRAG_FLAGS, { name: 'frag_flags', codec: 'u8' }],
  [TLV_SUM_SKB_HASH, { name: 'skb_hash', codec: 'u32' }],
  [TLV_SUM_SKB_MARK, { name: 'skb_mark', codec: 'u32' }],
  [TLV_SUM_SKB_PRIORITY, { name: 'skb_priority', codec: 'u32' }],
  [TLV_SUM_UID, { name: 'uid', codec: 'u32' }],
  [TLV_SUM_TGID, { name: 'tgid', codec: 'u32' }],
  [TLV_SUM_COMM, { name: 'comm', codec: 'comm' }],
  [TLV_SUM_ENQUEUE_TID, { name: 'enqueue_tid', codec: 'u32' }],
  [TLV_SUM_SKB_CREATE_TS, { name: 'skb_create_ts', codec: 'u64' }],
  [TLV_SUM_HDR_BYTES, { name: 'hdr_bytes', codec: 'bytes' }],
  [TLV_SUM_LINKTYPE, { name: 'linktype', codec: 'u16' }],
  [TLV_SUM_PLUGIN_VAL0, { name: 'plugin_val0', codec: 'u64' }],
  [TLV_SUM_PLUGIN_VAL1, { name: 'plugin_val1', codec: 'u64' }],
  [TLV_SUM_PLUGIN_VAL2, { name: 'plugin_val2', codec: 'u64' }],
  [TLV_SUM_PLUGIN_VAL3, { name: 'plugin_val3', codec: 'u64' }],
  [TLV_SUM_PLUGIN_VAL4, { name: 'plugin_val4', codec: 'u64' }],
  [TLV_SUM_PLUGIN_VAL5, { name: 'plugin_val5', codec: 'u64' }],
  [TLV_SUM_PLUGIN_VAL6, { name: 'plugin_val6', codec: 'u64' }],
  [TLV_SUM_PLUGIN_VAL7, { name: 'plugin_val7', codec: 'u64' }],
  [TLV_SUM_PLUGIN_VAL8, { name: 'plugin_val8', codec: 'u64' }],
  [TLV_SUM_PLUGIN_VAL9, { name: 'plugin_val9', codec: 'u64' }],
  [TLV_SUM_PLUGIN_VAL10, { name: 'plugin_val10', codec: 'u64' }],
  [TLV_SUM_PLUGIN_VAL11, { name: 'plugin_val11', codec: 'u64' }],
  [TLV_SUM_PLUGIN_VAL12, { name: 'plugin_val12', codec: 'u64' }],
  [TLV_SUM_PLUGIN_VAL13, { name: 'plugin_val13', codec: 'u64' }],
  [TLV_SUM_PLUGIN_VAL14, { name: 'plugin_val14', codec: 'u64' }],
  [TLV_SUM_PLUGIN_VAL15, { name: 'plugin_val15', codec: 'u64' }],

  [TLV_QS_QUEUE_GEN, { name: 'queue_gen', codec: 'u64' }],
  [TLV_QS_IFINDEX, { name: 'ifindex', codec: 'u32' }],
  [TLV_QS_TXQ, { name: 'txq', codec: 'u16' }],
  [TLV_QS_STATE_OP, { name: 'state_op', codec: 'u8' }],
  [TLV_QS_VALUE, { name: 'value', codec: 'u32' }],

  [TLV_QUAL_KIND, { name: 'qual_kind', codec: 'u8' }],
  [TLV_QUAL_SITE_DICT_IDX, { name: 'qual_site_dict_idx', codec: 'u16' }],
  [TLV_QUAL_WIN_START_NS, { name: 'win_start_ns', codec: 'u64' }],
  [TLV_QUAL_WIN_END_NS, { name: 'win_end_ns', codec: 'u64' }],
  [TLV_QUAL_COUNT, { name: 'count', codec: 'u64' }],
])

export const END_REASON_NAMES: Record<number, string> = {
  [END_OPEN]: 'OPEN',
  [END_TX_OK]: 'TX_OK',
  [END_DROP]: 'DROP',
  [END_CONSUME]: 'CONSUME',
  [END_SOCK_ENQUEUE]: 'SOCK_ENQUEUE',
  [END_APP_READ]: 'APP_READ',
  [END_TIMEOUT_TRUNCATED]: 'TIMEOUT_TRUNCATED',
  [END_CONFLICT_TRUNCATED]: 'CONFLICT_TRUNCATED',
  [END_BOUNDARY]: 'BOUNDARY',
}

export const STAGE_NAMES: Record<number, string> = {
  [STAGE_ENTRY]: 'ENTRY',
  [STAGE_CLASSIFY]: 'CLASSIFY',
  [STAGE_QDISC_ENQ]: 'QDISC_ENQ',
  [STAGE_QDISC_ENQ_RET]: 'QDISC_ENQ_RET',
  [STAGE_QDISC_DEQ]: 'QDISC_DEQ',
  [STAGE_BYPASS_DIRECT]: 'BYPASS_DIRECT',
  [STAGE_REQUEUE_GSO]: 'REQUEUE_GSO',
  [STAGE_REQUEUE_BAD_TXQ]: 'REQUEUE_BAD_TXQ',
  [STAGE_XMIT_START]: 'XMIT_START',
  [STAGE_XMIT_RET]: 'XMIT_RET',
  [STAGE_DELIVER_SOCK]: 'DELIVER_SOCK',
  [STAGE_DROP]: 'DROP',
  [STAGE_CONSUME]: 'CONSUME',
  [STAGE_HANDOFF_LAYER]: 'HANDOFF_LAYER',
}

export const REL_TYPE_NAMES: Record<number, string> = {
  [REL_CLONE]: 'CLONE',
  [REL_COPY]: 'COPY',
  [REL_REPLACE]: 'REPLACE',
  [REL_SEGMENT]: 'SEGMENT',
  [REL_MERGE]: 'MERGE',
  [REL_HANDOFF]: 'HANDOFF',
  [REL_SPAN_MAP]: 'SPAN_MAP',
}

export const QSTATE_OP_NAMES: Record<number, string> = {
  [QSTATE_TXQ_STOP]: 'TXQ_STOP',
  [QSTATE_TXQ_WAKE]: 'TXQ_WAKE',
  [QSTATE_BQL_LIMIT]: 'BQL_LIMIT',
}

export const QUAL_KIND_NAMES: Record<number, string> = {
  [QUAL_MISSED_DELTA]: 'MISSED_DELTA',
  [QUAL_RB_DROP_DELTA]: 'RB_DROP_DELTA',
  [QUAL_EPOCH_SWITCH]: 'EPOCH_SWITCH',
  [QUAL_RET_UNMATCHED]: 'RET_UNMATCHED',
  [QUAL_IDENTITY_CONFLICT]: 'IDENTITY_CONFLICT',
  [QUAL_RING_EVICTED_PREFIX]: 'RING_EVICTED_PREFIX',
  [QUAL_TOPO_DESYNC]: 'TOPO_DESYNC',
}

export const EVIDENCE_NAMES: Record<number, string> = {
  1: 'DIRECT',
  2: 'CONTRACT_DERIVED',
  3: 'ANNOTATION',
  4: 'GAP',
}

export const EVIDENCE_LABELS_ZH: Record<number, string> = {
  1: '直接观测',
  2: '契约推导',
  3: '辅助旁注',
  4: '缺口/未知',
}
