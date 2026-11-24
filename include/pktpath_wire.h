#ifndef PKTPATH_WIRE_H
#define PKTPATH_WIRE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * pktpath v1.0 Canonical Offline Wire Format
 * Little-endian integers, 8-byte natural alignment on block & event headers,
 * unpadded packed TLVs following pkt_event_hdr_v1.
 * ========================================================================== */

#define PKTPATH_WIRE_MAGIC           0x42544B50U /* "PKTB" in little-endian */
#define PKTPATH_WIRE_MAJOR           1U
#define PKTPATH_WIRE_MINOR           0U
#define PKTPATH_MAX_PAYLOAD_LEN      16777216U   /* 16 MiB hard cap */
#define PKTPATH_TLV_MUST_UNDERSTAND  0x8000U
#define PKTPATH_USERSPACE_CPU        0xFFFFFFFFU

/* Block types (pkt_block_hdr_v1.block_type) */
enum pkt_block_type {
    PKT_BLOCK_EVENT_BATCH        = 1,
    PKT_BLOCK_QUALITY_CHECKPOINT = 2,
    PKT_BLOCK_DICT_DELTA         = 3,
    PKT_BLOCK_END_MARKER         = 4,
};

/* Producer types (pkt_block_hdr_v1.producer_type) */
enum pkt_producer_type {
    PKT_PROD_KERNEL_BPF    = 1,
    PKT_PROD_RTNETLINK     = 2,
    PKT_PROD_USERSPACE_APP = 3,
    PKT_PROD_CONTROLLER    = 4,
};

/* Block flags (pkt_block_hdr_v1.flags) */
enum pkt_block_flags {
    PKT_BLOCK_F_ZSTD = (1U << 0),
};

/* Event kinds (pkt_event_hdr_v1.kind) */
#ifndef PKTPATH_BPF_H
enum pkt_event_kind {
    PKT_EV_OBJECT   = 1,
    PKT_EV_STEP     = 2,
    PKT_EV_RELATION = 3,
    PKT_EV_SUMMARY  = 4,
    PKT_EV_QSTATE   = 5,
    PKT_EV_QUALITY  = 6,
};

/* Object types (pkt_event_hdr_v1.object_type) */
enum pkt_object_type {
    PKT_OBJ_SKB       = 1,
    PKT_OBJ_XDP_FRAME = 2,
    PKT_OBJ_SOCK_SPAN = 3,
    PKT_OBJ_APP_MSG   = 4,
    PKT_OBJ_HW_DESC   = 5,
};
#endif /* !PKTPATH_BPF_H */

/* Evidence levels (pkt_event_hdr_v1.evidence_level) */
enum pkt_evidence_level {
    PKT_EVIDENCE_DIRECT           = 1,
    PKT_EVIDENCE_CONTRACT_DERIVED = 2,
    PKT_EVIDENCE_ANNOTATION       = 3,
    PKT_EVIDENCE_GAP              = 4,
};

/* Event flags (pkt_event_hdr_v1.flags) */
enum pkt_event_flags {
    PKT_EV_F_IN_TASK          = (1U << 0),
    PKT_EV_F_NONLINEAR_TRUNC  = (1U << 1),
    PKT_EV_F_PARTIAL_COVERAGE = (1U << 2),
};

#ifndef PKTPATH_BPF_H
/* OBJECT end_reason values (TLV 0x0002, u16) */
enum pkt_obj_end_reason {
    PKT_END_OPEN               = 0,
    PKT_END_TX_OK              = 1,
    PKT_END_DROP               = 2,
    PKT_END_CONSUME            = 3,
    PKT_END_SOCK_ENQUEUE       = 4,
    PKT_END_APP_READ           = 5,
    PKT_END_TIMEOUT_TRUNCATED  = 6,
    PKT_END_CONFLICT_TRUNCATED = 7,
    PKT_END_BOUNDARY           = 8,
};

/* Direction values (STEP TLV 0x0106 / SUMMARY TLV 0x0304, u8) */
enum pkt_dir {
    PKT_DIR_RX  = 0,
    PKT_DIR_TX  = 1,
    PKT_DIR_FWD = 2,
};

/* STEP stage values (TLV 0x0107, u8) */
enum pkt_step_stage {
    PKT_STAGE_ENTRY           = 1,
    PKT_STAGE_CLASSIFY        = 2,
    PKT_STAGE_QDISC_ENQ       = 3,
    PKT_STAGE_QDISC_ENQ_RET   = 4,
    PKT_STAGE_QDISC_DEQ       = 5,
    PKT_STAGE_BYPASS_DIRECT   = 6,
    PKT_STAGE_REQUEUE_GSO     = 7,
    PKT_STAGE_REQUEUE_BAD_TXQ = 8,
    PKT_STAGE_XMIT_START      = 9,
    PKT_STAGE_XMIT_RET        = 10,
    PKT_STAGE_DELIVER_SOCK    = 11,
    PKT_STAGE_DROP            = 12,
    PKT_STAGE_CONSUME         = 13,
    PKT_STAGE_HANDOFF_LAYER   = 14,
};

/* RELATION rel_type values (TLV 0x0202, u8) */
enum pkt_rel_type {
    PKT_REL_CLONE    = 1,
    PKT_REL_COPY     = 2,
    PKT_REL_REPLACE  = 3,
    PKT_REL_SEGMENT  = 4,
    PKT_REL_MERGE    = 5,
    PKT_REL_HANDOFF  = 6,
    PKT_REL_SPAN_MAP = 7,
};

/* RELATION rel_flags bits (TLV 0x0205, u8) */
enum pkt_rel_flags {
    PKT_REL_F_SUCCESSOR_TRUNCATED  = (1U << 0),
    PKT_REL_F_UNKNOWN_PREDECESSORS = (1U << 1),
};

/* SUMMARY linktype values (TLV 0x031A, u16 — pcap/pcapng LINKTYPE_*) */
enum pkt_linktype {
    PKT_LINKTYPE_ETHERNET = 1,
    PKT_LINKTYPE_RAW_IP   = 101,
};

/* QSTATE state_op values (TLV 0x0404, u8) */
enum pkt_qstate_op {
    PKT_QSTATE_TXQ_STOP  = 1,
    PKT_QSTATE_TXQ_WAKE  = 2,
    PKT_QSTATE_BQL_LIMIT = 3,
};

/* QUALITY qual_kind values (TLV 0x0501, u8) */
enum pkt_qual_kind {
    PKT_QUAL_MISSED_DELTA        = 1,
    PKT_QUAL_RB_DROP_DELTA       = 2,
    PKT_QUAL_EPOCH_SWITCH        = 3,
    PKT_QUAL_RET_UNMATCHED       = 4,
    PKT_QUAL_IDENTITY_CONFLICT   = 5,
    PKT_QUAL_RING_EVICTED_PREFIX = 6,
    PKT_QUAL_TOPO_DESYNC         = 7,
};
#else
#define PKT_REL_F_SUCCESSOR_TRUNCATED  PKT_RELF_SUCCESSOR_TRUNCATED
#define PKT_REL_F_UNKNOWN_PREDECESSORS PKT_RELF_UNKNOWN_PREDECESSORS
#define PKT_LINKTYPE_ETHERNET          PKT_LINKTYPE_ETH
#endif /* !PKTPATH_BPF_H */

/* ==========================================================================
 * Canonical TLV Tags (v1.0)
 * ========================================================================== */

/* OBJECT (kind = 1) */
#define PKT_TLV_OBJ_SAMPLE_ID        0x0001U /* u64 */
#define PKT_TLV_OBJ_END_REASON       0x0002U /* u16 */
#define PKT_TLV_OBJ_DROP_REASON      0x0003U /* u32 */

/* STEP (kind = 2) */
#define PKT_TLV_STEP_VISIT_ID        0x0101U /* u64 */
#define PKT_TLV_STEP_CALL_ID         0x0102U /* u64 */
#define PKT_TLV_STEP_NETNS_INUM      0x0103U /* u32 */
#define PKT_TLV_STEP_DEV_GEN         0x0104U /* u32 */
#define PKT_TLV_STEP_IFINDEX         0x0105U /* u32 */
#define PKT_TLV_STEP_DIR             0x0106U /* u8  */
#define PKT_TLV_STEP_STAGE           0x0107U /* u8  */
#define PKT_TLV_STEP_QUEUE_GEN       0x0108U /* u64 */
#define PKT_TLV_STEP_QDISC_HANDLE    0x0109U /* u32 */
#define PKT_TLV_STEP_QDISC_PARENT    0x010AU /* u32 */
#define PKT_TLV_STEP_CLASSID         0x010BU /* u32 */
#define PKT_TLV_STEP_BUCKET          0x010CU /* u32 */
#define PKT_TLV_STEP_TXQ             0x010DU /* u16 */
#define PKT_TLV_STEP_RAW_RET         0x010EU /* s32 */
#define PKT_TLV_STEP_CTX_TID         0x010FU /* u32 */

/* RELATION (kind = 3) */
#define PKT_TLV_REL_OP_ID            0x0201U /* u64 */
#define PKT_TLV_REL_TYPE             0x0202U /* u8  */
#define PKT_TLV_REL_SRC_OBJECT_ID    0x0203U /* u64 */
#define PKT_TLV_REL_DST_OBJECT_ID    0x0204U /* u64 */
#define PKT_TLV_REL_FLAGS            0x0205U /* u8  */
#define PKT_TLV_REL_STREAM_OFFSET    0x0206U /* u64 */
#define PKT_TLV_REL_SPAN_LEN         0x0207U /* u32 */

/* SUMMARY (kind = 4) */
#define PKT_TLV_SUM_PKT_LEN          0x0301U /* u32 */
#define PKT_TLV_SUM_LINEAR_LEN       0x0302U /* u32 */
#define PKT_TLV_SUM_IFINDEX          0x0303U /* u32 */
#define PKT_TLV_SUM_DIR              0x0304U /* u8  */
#define PKT_TLV_SUM_IP_VERSION       0x0305U /* u8  */
#define PKT_TLV_SUM_L4_PROTO         0x0306U /* u8  */
#define PKT_TLV_SUM_SRC_IP           0x0307U /* 4B or 16B */
#define PKT_TLV_SUM_DST_IP           0x0308U /* 4B or 16B */
#define PKT_TLV_SUM_SRC_PORT         0x0309U /* u16 */
#define PKT_TLV_SUM_DST_PORT         0x030AU /* u16 */
#define PKT_TLV_SUM_TCP_SEQ          0x030BU /* u32 */
#define PKT_TLV_SUM_TCP_SEQ_END      0x030CU /* u32 */
#define PKT_TLV_SUM_TCP_FLAGS        0x030DU /* u8  */
#define PKT_TLV_SUM_IP_ID            0x030EU /* u16 */
#define PKT_TLV_SUM_FRAG_FLAGS       0x030FU /* u8  */
#define PKT_TLV_SUM_SKB_HASH         0x0310U /* u32 */
#define PKT_TLV_SUM_SKB_MARK         0x0311U /* u32 */
#define PKT_TLV_SUM_SKB_PRIORITY     0x0312U /* u32 */
#define PKT_TLV_SUM_UID              0x0313U /* u32 */
#define PKT_TLV_SUM_TGID             0x0314U /* u32 */
#define PKT_TLV_SUM_COMM             0x0315U /* 16B */
#define PKT_TLV_SUM_ENQUEUE_TID      0x0316U /* u32 */
#define PKT_TLV_SUM_SKB_CREATE_TS    0x0317U /* u64 */
#define PKT_TLV_SUM_HDR_BYTES        0x0319U /* variable bytes */
#define PKT_TLV_SUM_LINKTYPE         0x031AU /* u16 (1=ETH, 101=RAW_IP) */
#define PKT_TLV_SUM_PLUGIN_VAL0      0x0320U /* u64: custom sock plugin slot 0 */
#define PKT_TLV_SUM_PLUGIN_VAL1      0x0321U /* u64: custom sock plugin slot 1 */
#define PKT_TLV_SUM_PLUGIN_VAL2      0x0322U /* u64: custom sock plugin slot 2 */
#define PKT_TLV_SUM_PLUGIN_VAL3      0x0323U /* u64: custom sock plugin slot 3 */

/* QSTATE (kind = 5) */
#define PKT_TLV_QS_QUEUE_GEN         0x0401U /* u64 */
#define PKT_TLV_QS_IFINDEX           0x0402U /* u32 */
#define PKT_TLV_QS_TXQ               0x0403U /* u16 */
#define PKT_TLV_QS_STATE_OP          0x0404U /* u8  */
#define PKT_TLV_QS_VALUE             0x0405U /* u32 */

/* QUALITY (kind = 6) */
#define PKT_TLV_QUAL_KIND            0x0501U /* u8  */
#define PKT_TLV_QUAL_SITE_DICT_IDX   0x0502U /* u16 */
#define PKT_TLV_QUAL_WIN_START_NS    0x0503U /* u64 */
#define PKT_TLV_QUAL_WIN_END_NS      0x0504U /* u64 */
#define PKT_TLV_QUAL_COUNT           0x0505U /* u64 */

/* ==========================================================================
 * Fixed Binary Headers
 * ========================================================================== */

struct pkt_block_hdr_v1 {
    uint32_t magic;           /* PKTPATH_WIRE_MAGIC (0x42544B50) */
    uint16_t major;           /* 1 */
    uint16_t minor;           /* 0 */
    uint16_t block_type;      /* enum pkt_block_type */
    uint16_t producer_type;   /* enum pkt_producer_type */
    uint32_t flags;           /* enum pkt_block_flags */
    uint32_t payload_len;     /* <= PKTPATH_MAX_PAYLOAD_LEN */
    uint32_t epoch;           /* topology/session epoch */
    uint32_t block_no;        /* monotonic block sequence number */
    uint32_t reserved;        /* must be 0 */
    uint8_t  session_uuid[16];/* 128-bit session identifier */
    uint64_t min_ts_ns;       /* CLOCK_BOOTTIME min event ts in block */
    uint64_t max_ts_ns;       /* CLOCK_BOOTTIME max event ts in block */
};

struct pkt_event_hdr_v1 {
    uint16_t total_len;       /* sizeof(pkt_event_hdr_v1) + TLV bytes */
    uint16_t kind;            /* enum pkt_event_kind */
    uint8_t  object_type;     /* enum pkt_object_type */
    uint8_t  evidence_level;  /* enum pkt_evidence_level */
    uint16_t site_dict_idx;   /* index into dict.json sites[] */
    uint32_t cpu;             /* CPU id or PKTPATH_USERSPACE_CPU */
    uint32_t flags;           /* enum pkt_event_flags */
    uint64_t seq;             /* per-(producer, cpu) monotonic sequence */
    uint64_t ts_ns;           /* CLOCK_BOOTTIME ns */
    uint64_t object_id;       /* tracked object id (0 for non-object events) */
};

struct __attribute__((packed)) pkt_tlv_hdr {
    uint16_t tag;
    uint16_t len;
};

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct pkt_block_hdr_v1) == 64, "pkt_block_hdr_v1 must be 64 bytes");
_Static_assert(sizeof(struct pkt_event_hdr_v1) == 40, "pkt_event_hdr_v1 must be 40 bytes");
_Static_assert(sizeof(struct pkt_tlv_hdr) == 4, "pkt_tlv_hdr must be 4 bytes");
#endif

#ifdef __cplusplus
}
#endif

#endif /* PKTPATH_WIRE_H */
