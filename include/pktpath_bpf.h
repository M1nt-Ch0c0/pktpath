#ifndef PKTPATH_BPF_H
#define PKTPATH_BPF_H

/*
 * pktpath v3 — Kernel eBPF <-> Device Controller Shared Contract
 *
 * Zero libbpf / compiler dependency on target Android / Linux devices.
 * Works across kernel builds (e.g. Android 14 6.1.157, Android 16 6.12.69,
 * standard Linux 5.15+) via runtime BTF offset table (PKT_MAP_BTF_OFF).
 */

#ifdef __BPF__
typedef unsigned char      uint8_t;
typedef signed char        int8_t;
typedef unsigned short     uint16_t;
typedef signed short       int16_t;
typedef unsigned int       uint32_t;
typedef signed int         int32_t;
typedef unsigned long long uint64_t;
typedef signed long long   int64_t;
#else
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ==================== 1. Limits & Constants ==================== */

#define PKT_MAX_CPUS            16U
#define PKT_MAX_SNAP_LEN        128U
#define PKT_MAX_PROG_RELOCS     64U
#define PKT_ACTIVE_SLOTS_CNT    2U

#define PKT_DEFAULT_MAX_ACTIVE  16384U
#define PKT_SENDMSG_MAX_ACTIVE  65536U
#define PKT_DEFAULT_MAX_CALLS   4096U
#define PKT_DEFAULT_MAX_SOCKS   16384U
#define PKT_DEFAULT_RINGBUF_SZ  (4U * 1024U * 1024U)

/* 100 ms SLUB hot-address conflict quarantine cooldown (never lock whole epoch) */
#define PKT_QUARANTINE_NS       100000000ULL

/* Filter sentinel values */
#define PKT_FILTER_UID_ANY      0xFFFFFFFFU

/* Linux bpf_prog_type constants (matching <linux/bpf.h>) */
#define PKT_BPF_PROG_TYPE_KPROBE     2U
#define PKT_BPF_PROG_TYPE_TRACEPOINT 5U

/*
 * SOFTIRQ_OFFSET (0x100) | HARDIRQ_MASK | NMI_MASK.
 * Excludes PREEMPT_MASK (0xFF) and BH rcu_read_lock_bh (0x200) so is_in_task()
 * matches Linux kernel in_task() inside __dev_queue_xmit.
 */
#define PKT_PREEMPT_IRQ_MASK    0x00FF0100U

/* ==================== 2. Exact Map Relocation Order ==================== */

/*
 * Shared map index order between probe_core.bpf.c, build_bpf.py, and device/:
 *   0: active_slots (BPF_MAP_TYPE_ARRAY_OF_MAPS, max_entries=2;
 *                    inner: BPF_MAP_TYPE_HASH, key=uint64_t skb_ptr, val=struct bpf_active_val)
 *   1: control      (BPF_MAP_TYPE_ARRAY, max_entries=1, val=struct bpf_ctrl_cfg)
 *   2: calls        (BPF_MAP_TYPE_HASH, key=struct bpf_call_key, val=struct bpf_call_val)
 *   3: rb           (BPF_MAP_TYPE_RINGBUF)
 *   4: socks        (BPF_MAP_TYPE_HASH, key=uint64_t sk_ptr, val=struct bpf_sock_owner)
 *   5: cpu_seq      (BPF_MAP_TYPE_ARRAY, max_entries=16, val=uint64_t)
 *   6: btf_off      (BPF_MAP_TYPE_ARRAY, max_entries=1, val=struct bpf_btf_offsets)
 */
enum pkt_map_idx {
    PKT_MAP_ACTIVE_SLOTS = 0,
    PKT_MAP_CONTROL      = 1,
    PKT_MAP_CALLS        = 2,
    PKT_MAP_RB           = 3,
    PKT_MAP_SOCKS        = 4,
    PKT_MAP_CPU_SEQ      = 5,
    PKT_MAP_BTF_OFF      = 6,
    PKT_MAP_PLUGIN_CFG   = 7, /* read-only BPF_MAP_FREEZE config for external .bpf.o */
    PKT_MAP_COUNT        = 8
};

/* ==================== 3. Protocol Enums (Matching Wire v1.0) ==================== */

#ifndef PKTPATH_WIRE_H
/* Event kinds (pkt_event_hdr_v1.kind / bpf_ev_common.kind) */
enum pkt_ev_kind {
    PKT_EV_OBJECT   = 1,
    PKT_EV_STEP     = 2,
    PKT_EV_RELATION = 3,
    PKT_EV_SUMMARY  = 4,
    PKT_EV_QSTATE   = 5,
    PKT_EV_QUALITY  = 6
};

/* Object types (object_type) */
enum pkt_obj_type {
    PKT_OBJ_SKB       = 1,
    PKT_OBJ_XDP_FRAME = 2,
    PKT_OBJ_SOCK_SPAN = 3,
    PKT_OBJ_APP_MSG   = 4,
    PKT_OBJ_HW_DESC   = 5
};
#endif /* !PKTPATH_WIRE_H */

/* Four-tier evidence levels (evidence_level) */
enum pkt_evid_level {
    PKT_EVID_DIRECT           = 1,
    PKT_EVID_CONTRACT_DERIVED = 2,
    PKT_EVID_ANNOTATION       = 3,
    PKT_EVID_GAP              = 4
};

/* Event header flags (bpf_ev_common.flags / pkt_event_hdr_v1.flags) */
enum pkt_ev_flags {
    PKT_EVF_IN_TASK          = (1U << 0),
    PKT_EVF_NONLINEAR_TRUNC  = (1U << 1),
    PKT_EVF_PARTIAL_COVERAGE = (1U << 2)
};

/* Active skb lifecycle states (详细设计 §3.3) */
enum pkt_lifecycle_state {
    PKT_STATE_ACTIVE_PIPELINE  = 1,
    PKT_STATE_IN_QUEUE         = 2,
    PKT_STATE_HANDED_OFF_LAYER = 3,
    PKT_STATE_QUARANTINED      = 4
};

#ifndef PKTPATH_WIRE_H
/* OBJECT end_reason (TLV 0x0002) */
enum pkt_end_reason {
    PKT_END_OPEN               = 0,
    PKT_END_TX_OK              = 1,
    PKT_END_DROP               = 2,
    PKT_END_CONSUME            = 3,
    PKT_END_SOCK_ENQUEUE       = 4,
    PKT_END_APP_READ           = 5,
    PKT_END_TIMEOUT_TRUNCATED  = 6,
    PKT_END_CONFLICT_TRUNCATED = 7,
    PKT_END_BOUNDARY           = 8
};

/* Packet direction (STEP TLV 0x0106 / SUMMARY TLV 0x0304) */
enum pkt_dir {
    PKT_DIR_RX  = 0,
    PKT_DIR_TX  = 1,
    PKT_DIR_FWD = 2
};

/* STEP stage (TLV 0x0107) */
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
    PKT_STAGE_HANDOFF_LAYER   = 14
};

/* RELATION rel_type (TLV 0x0202) */
enum pkt_rel_type {
    PKT_REL_CLONE    = 1,
    PKT_REL_COPY     = 2,
    PKT_REL_REPLACE  = 3,
    PKT_REL_SEGMENT  = 4,
    PKT_REL_MERGE    = 5,
    PKT_REL_HANDOFF  = 6,
    PKT_REL_SPAN_MAP = 7
};

/* RELATION rel_flags (TLV 0x0205) */
enum pkt_rel_flags {
    PKT_RELF_SUCCESSOR_TRUNCATED  = (1U << 0),
    PKT_RELF_UNKNOWN_PREDECESSORS = (1U << 1)
};

/* QSTATE state_op (TLV 0x0404) */
enum pkt_qstate_op {
    PKT_QSTATE_TXQ_STOP  = 1,
    PKT_QSTATE_TXQ_WAKE  = 2,
    PKT_QSTATE_BQL_LIMIT = 3
};

/* QUALITY qual_kind (TLV 0x0501) */
enum pkt_qual_kind {
    PKT_QUAL_MISSED_DELTA        = 1,
    PKT_QUAL_RB_DROP_DELTA       = 2,
    PKT_QUAL_EPOCH_SWITCH        = 3,
    PKT_QUAL_RET_UNMATCHED       = 4,
    PKT_QUAL_IDENTITY_CONFLICT   = 5,
    PKT_QUAL_RING_EVICTED_PREFIX = 6,
    PKT_QUAL_TOPO_DESYNC         = 7
};

/* SUMMARY linktype (TLV 0x031A) */
enum pkt_linktype {
    PKT_LINKTYPE_ETH    = 1,
    PKT_LINKTYPE_RAW_IP = 101
};
#else
#define PKT_RELF_SUCCESSOR_TRUNCATED  PKT_REL_F_SUCCESSOR_TRUNCATED
#define PKT_RELF_UNKNOWN_PREDECESSORS PKT_REL_F_UNKNOWN_PREDECESSORS
#define PKT_LINKTYPE_ETH              PKT_LINKTYPE_ETHERNET
#endif /* !PKTPATH_WIRE_H */

/* SUMMARY valid_flags bitmask in struct bpf_ev_summary */
enum pkt_summary_valid_flags {
    PKT_SUM_F_L3          = (1U << 0),
    PKT_SUM_F_L4          = (1U << 1),
    PKT_SUM_F_TCP         = (1U << 2),
    PKT_SUM_F_UID         = (1U << 3),
    PKT_SUM_F_TGID        = (1U << 4),
    PKT_SUM_F_COMM        = (1U << 5),
    PKT_SUM_F_TID         = (1U << 6),
    PKT_SUM_F_CREATE_TS   = (1U << 7),
    PKT_SUM_F_PLUGIN_VALS = (1U << 8),
    PKT_SUM_F_HDR_BYTES   = (1U << 9)
};

/* Dynamic runtime socket-field extensions (expanded to 16 concurrent fields) */
#define PKT_MAX_SOCK_PLUGINS 16U

/* Dynamic runtime BPF probe cloning sentinels (patched per-qdisc at load time) */
#define PKT_SITE_DYN_ENQ_SENTINEL 0x5A01U
#define PKT_SITE_DYN_RET_SENTINEL 0x5A02U
#define PKT_SITE_DYN_BASE         100U

/* Wave 3 external .bpf.o plugin ABI v1 */
#define PKT_PLUGIN_ABI_VERSION    1U
#define PKT_SITE_EXT_MIN          0x2000U
#define PKT_SITE_EXT_MAX          0xFFFEU
#define PKT_SITE_EXT_SENTINEL     0x7E00U

struct bpf_plugin_cfg {
    uint32_t abi_version;
    uint32_t target_ifindex;
    uint32_t filter_uid;
    uint32_t flags;
    uint32_t extra_off[32];
};

enum pkt_sock_plugin_role {
    PKT_SOCK_PLUG_NONE          = 0,
    PKT_SOCK_PLUG_TAG           = 1, /* emit value as TLV 0x0320 + slot */
    PKT_SOCK_PLUG_TGID_FALLBACK = 2  /* fallback tgid when sock_owner_map missed */
};

struct bpf_sock_field_spec {
    uint32_t offset; /* runtime BTF offset in struct sock (0 = disabled) */
    uint8_t  size;   /* 1, 2, 4, or 8 bytes */
    uint8_t  role;   /* enum pkt_sock_plugin_role */
    uint16_t pad;
};

/* SUMMARY frag_flags bitmask (TLV 0x030F) */
enum pkt_frag_flags {
    PKT_FRAG_F_MORE      = (1U << 0),
    PKT_FRAG_F_DONT      = (1U << 1),
    PKT_FRAG_F_NON_FIRST = (1U << 2)
};

/* ==================== 4. Probe Section / Site Catalogue ==================== */

/*
 * Canonical probe indices in generated_progs.h `pkt_bpf_progs[]` (0..45)
 * and 1-based site dictionary IDs `site_dict_idx` (1..46).
 *
 * L1 Attribution Probes (7):
 *   tp_sock_create    : kprobe     security_socket_post_create
 *   kp_tcp_v4_conn    : kprobe     tcp_v4_connect
 *   kp_tcp_v6_conn    : kprobe     tcp_v6_connect
 *   kr_inet_accept    : kretprobe  inet_csk_accept
 *   kp_sk_destruct    : kprobe     sk_destruct
 *   kp_tcp_sendmsg    : kprobe     tcp_sendmsg_locked  (--profile sendmsg)
 *   kp_udp_sendmsg    : kprobe     udp_sendmsg         (--profile sendmsg)
 *
 * L2 Upstream Linux Datapath & Qdisc Probes (31):
 *   tp_net_dev_queue  : tracepoint net:net_dev_queue
 *   kp_htb_enq        : kprobe     htb_enqueue
 *   kp_fq_codel_enq   : kprobe     fq_codel_enqueue
 *   kr_fq_codel_enq   : kretprobe  fq_codel_enqueue
 *   kr_fq_codel_deq   : kretprobe  fq_codel_dequeue
 *   kp_pfifo_enq      : kprobe     pfifo_fast_enqueue
 *   kr_pfifo_enq      : kretprobe  pfifo_fast_enqueue
 *   kr_pfifo_deq      : kretprobe  pfifo_fast_dequeue
 *   kp_sch_direct_xmit: kprobe     sch_direct_xmit
 *   kp_dev_requeue    : kprobe     dev_requeue_skb
 *   tp_start_xmit     : tracepoint net:net_dev_start_xmit
 *   tp_xmit_ret       : tracepoint net:net_dev_xmit
 *   tp_kfree_skb      : tracepoint skb:kfree_skb
 *   tp_consume_skb    : tracepoint skb:consume_skb
 *   kp_skb_clone      : kprobe     skb_clone
 *   kr_skb_clone      : kretprobe  skb_clone
 *   kp_pskb_expand    : kprobe     pskb_expand_head
 *   kp_txq_stop       : kprobe     netif_tx_stop_queue
 *   kp_txq_wake       : kprobe     netif_tx_wake_queue
 *   kp_fifo_enq       : kprobe     pfifo_enqueue
 *   kr_fifo_enq       : kretprobe  pfifo_enqueue
 *   kp_bfifo_enq      : kprobe     bfifo_enqueue
 *   kr_bfifo_enq      : kretprobe  bfifo_enqueue
 *   kp_ptail_enq      : kprobe     pfifo_tail_enqueue
 *   kr_ptail_enq      : kretprobe  pfifo_tail_enqueue
 *   kr_fifo_deq       : kretprobe  qdisc_dequeue_head
 *   kp_sfq_enq        : kprobe     sfq_enqueue
 *   kr_sfq_enq        : kretprobe  sfq_enqueue
 *   kr_sfq_deq        : kretprobe  sfq_dequeue
 *   kp_tcf_classify   : kprobe     tcf_classify
 *   kr_tcf_classify   : kretprobe  tcf_classify
 *
 * L2 Dynamic Qdisc Plugin Slots (8 — bound at runtime via --plugin):
 *   kp_plug_cls0_enq  : kprobe     <plugin classful slot 0 enqueue>
 *   kp_plug_cls1_enq  : kprobe     <plugin classful slot 1 enqueue>
 *   kp_plug_leaf0_enq : kprobe     <plugin leaf slot 0 enqueue>
 *   kr_plug_leaf0_enq : kretprobe  <plugin leaf slot 0 enqueue>
 *   kr_plug_leaf0_deq : kretprobe  <plugin leaf slot 0 dequeue>
 *   kp_plug_leaf1_enq : kprobe     <plugin leaf slot 1 enqueue>
 *   kr_plug_leaf1_enq : kretprobe  <plugin leaf slot 1 enqueue>
 *   kr_plug_leaf1_deq : kretprobe  <plugin leaf slot 1 dequeue>
 */
enum pkt_site_id {
    /* L1 */
    PKT_SITE_TP_SOCK_CREATE     = 1,
    PKT_SITE_KP_TCP_V4_CONN     = 2,
    PKT_SITE_KP_TCP_V6_CONN     = 3,
    PKT_SITE_KR_INET_ACCEPT     = 4,
    PKT_SITE_KP_SK_DESTRUCT     = 5,
    PKT_SITE_KP_TCP_SENDMSG     = 6,
    PKT_SITE_KP_UDP_SENDMSG     = 7,
    /* L2 built-in upstream Linux */
    PKT_SITE_TP_NET_DEV_QUEUE   = 8,
    PKT_SITE_KP_HTB_ENQ         = 9,
    PKT_SITE_KP_FQ_CODEL_ENQ    = 10,
    PKT_SITE_KR_FQ_CODEL_ENQ    = 11,
    PKT_SITE_KR_FQ_CODEL_DEQ    = 12,
    PKT_SITE_KP_PFIFO_ENQ       = 13,
    PKT_SITE_KR_PFIFO_ENQ       = 14,
    PKT_SITE_KR_PFIFO_DEQ       = 15,
    PKT_SITE_KP_SCH_DIRECT_XMIT = 16,
    PKT_SITE_KP_DEV_REQUEUE     = 17,
    PKT_SITE_TP_START_XMIT      = 18,
    PKT_SITE_TP_XMIT_RET        = 19,
    PKT_SITE_TP_KFREE_SKB       = 20,
    PKT_SITE_TP_CONSUME_SKB     = 21,
    PKT_SITE_KP_SKB_CLONE       = 22,
    PKT_SITE_KR_SKB_CLONE       = 23,
    PKT_SITE_KP_PSKB_EXPAND     = 24,
    PKT_SITE_KP_TXQ_STOP        = 25,
    PKT_SITE_KP_TXQ_WAKE        = 26,
    PKT_SITE_KP_FIFO_ENQ        = 27,
    PKT_SITE_KR_FIFO_ENQ        = 28,
    PKT_SITE_KP_BFIFO_ENQ       = 29,
    PKT_SITE_KR_BFIFO_ENQ       = 30,
    PKT_SITE_KP_PTAIL_ENQ       = 31,
    PKT_SITE_KR_PTAIL_ENQ       = 32,
    PKT_SITE_KR_FIFO_DEQ        = 33,
    PKT_SITE_KP_SFQ_ENQ         = 34,
    PKT_SITE_KR_SFQ_ENQ         = 35,
    PKT_SITE_KR_SFQ_DEQ         = 36,
    PKT_SITE_KP_TCF_CLASSIFY    = 37,
    PKT_SITE_KR_TCF_CLASSIFY    = 38,
    /* L2 reusable dynamic qdisc probe templates (cloned & patched at runtime) */
    PKT_SITE_TMPL_PLUG_CLS_ENQ  = 39,
    PKT_SITE_TMPL_PLUG_LEAF_ENQ = 40,
    PKT_SITE_TMPL_PLUG_LEAF_RET = 41,
    PKT_SITE_TMPL_PLUG_LEAF_DEQ = 42,
    PKT_SITE_MAX                = 42
};

/* ==================== 5. BPF Map Value Structs ==================== */

/*
 * Map 6 (`btf_off`): Runtime BTF offsets populated from `/sys/kernel/btf/vmlinux`
 * by `device/btf_parse.c` plus optional socket-field plugin descriptors from
 * `device/plugin_loader.c`.
 */
struct bpf_btf_offsets {
    /* struct sk_buff */
    uint32_t skb_dev;               /* default: 16 */
    uint32_t skb_sk;                /* default: 24 */
    uint32_t skb_len;               /* default: 112 */
    uint32_t skb_data_len;          /* default: 116 */
    uint32_t skb_head;              /* default: 216 */
    uint32_t skb_data;              /* default: 224 */
    uint32_t skb_network_header;    /* default: 196 */
    uint32_t skb_transport_header;  /* default: 194 */
    uint32_t skb_mac_header;        /* default: 198 */
    uint32_t skb_protocol;          /* default: 192 */
    uint32_t skb_pkt_type;          /* default: 128 (__pkt_type_offset byte) */
    uint32_t skb_hash;              /* default: 164 */
    uint32_t skb_mark;              /* default: 168 */
    uint32_t skb_priority;          /* default: 156 */
    uint32_t skb_cb;                /* default: 40 */

    /* struct net_device & struct net */
    uint32_t dev_ifindex;           /* default: 216 */
    uint32_t dev_nd_net;            /* default: 1280 */
    uint32_t net_ns_inum;           /* default: 136 */

    /* struct sock & struct socket */
    uint32_t sk_state;              /* default: 18 (__sk_common.skc_state) */
    uint32_t sk_cookie;             /* default: 88 (__sk_common.skc_cookie) */
    uint32_t sk_uid;                /* default: 576 (sk_uid.val) */
    uint32_t socket_sk;             /* default: 24 */

    /* struct Qdisc */
    uint32_t qdisc_handle;          /* default: 56 */
    uint32_t qdisc_parent;          /* default: 60 */

    /* struct task_struct */
    uint32_t task_preempt_count;    /* default: 16 (arm64 thread_info.preempt.count) */

    /* Optional tracepoint / netdev_queue / TC classify helpers (0 = auto fallback) */
    uint32_t tp_kfree_skb_reason;   /* trace_event_raw_kfree_skb.reason */
    uint32_t dev_tx_queues;         /* struct net_device._tx offset (optional for QSTATE txq) */
    uint32_t netdev_queue_sz;       /* sizeof(struct netdev_queue) (optional for QSTATE txq) */
    uint32_t tcf_res_classid;       /* struct tcf_result.classid (default: 8) */

    /* Runtime-loaded custom struct sock field plugins (offset == 0 means disabled) */
    uint32_t sock_plugin_count;      /* 0..PKT_MAX_SOCK_PLUGINS */
    uint32_t sock_plugin_valid_mask; /* bitmask of resolved slots */
    struct bpf_sock_field_spec sock_plugins[PKT_MAX_SOCK_PLUGINS];
};

/* bpf_ctrl_cfg.flags bits */
enum pkt_ctrl_flags {
    PKT_CTRL_F_BYPASS       = (1U << 0), /* L0 active_tracked_count == 0 fast bypass */
    PKT_CTRL_F_RINGBUF      = (1U << 1), /* Emit events to ringbuf */
    PKT_CTRL_F_L1_ATTR      = (1U << 2), /* Standard Linux L1 uid/pid/comm/tid */
    PKT_CTRL_F_SENDMSG      = (1U << 3), /* --profile sendmsg (exact tid + skb_create_ts) */
    PKT_CTRL_F_SOCK_PLUGINS = (1U << 4), /* Runtime sock_fields plugins enabled */
    PKT_CTRL_F_CAPTURE_HDR  = (1U << 5), /* --capture-hdr enabled */
    PKT_CTRL_F_PARTIAL_COV  = (1U << 6), /* Mark emitted events with PARTIAL_COVERAGE */
    PKT_CTRL_F_ADMIT_OFF    = (1U << 7), /* Explicitly gate new admissions during drain */
    PKT_CTRL_F_NO_BYPASS    = (1U << 8), /* Benchmark override: disable L0 bypass */
    PKT_CTRL_F_NO_RINGBUF   = (1U << 9), /* Benchmark override: suppress ringbuf submit */
    PKT_CTRL_F_NO_L1_ATTR   = (1U << 10) /* Benchmark override: disable L1 attribution */
};

#define PKT_CTRL_DEFAULT_FLAGS \
    (PKT_CTRL_F_BYPASS | PKT_CTRL_F_RINGBUF | PKT_CTRL_F_L1_ATTR)

/*
 * Map 1 (`control`): Single-entry runtime configuration, filter, epoch state,
 * and atomic counters.
 *
 * Note on filter conventions:
 *   - `sample_stride`: 0 = admission closed (miss), 1 = 100% full, N = 1/N
 *   - `filter_uid`   : PKT_FILTER_UID_ANY (0xFFFFFFFFU) = any; 0 = root UID 0
 *   - `filter_src_ip4` / `filter_src_ip4_mask`, `filter_dst_ip4` / `filter_dst_ip4_mask`:
 *     network byte order (matching `inet_pton(AF_INET, ...)` and wire IPv4 header);
 *     mask == 0 means any.
 *   - `filter_src_port`, `filter_dst_port`: host byte order (0 = any).
 */
struct bpf_ctrl_cfg {
    /* Fast-path bypass & A/B epoch rotation */
    uint32_t active_tracked_count;  /* atomic count of live entries across active_slots */
    uint32_t in_xmit_count;         /* atomic count of in-flight start_xmit -> xmit_ret */
    uint32_t active_slot;           /* current write/primary slot in active_slots: 0 or 1 */
    uint32_t draining_slot_active;  /* 1 while (1 - active_slot) is draining on epoch switch */
    uint32_t epoch;                 /* current session/daemon epoch (>= 1) */
    uint32_t flags;                 /* PKT_CTRL_F_* (0 defaults to BYPASS|RINGBUF|L1_ATTR) */
    uint32_t capture_hdr_len;       /* 0 = metadata only; 1..128 = packet header snaplen */
    uint32_t sample_stride;         /* 0 = miss/closed, 1 = full, N = 1/N */
    uint32_t sample_by_flow;        /* 0 = per-packet counter, 1 = 5-tuple flow hash */

    /* Structured entry filters */
    uint32_t filter_ifindex;        /* 0 = any */
    uint32_t filter_netns;          /* 0 = any */
    uint8_t  filter_proto;          /* 0 = any, e.g. 6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6 */
    uint8_t  filter_ip_ver;         /* 0 = any, 4 = IPv4, 6 = IPv6 */
    uint16_t filter_src_port;       /* 0 = any (host byte order) */
    uint16_t filter_dst_port;       /* 0 = any (host byte order) */
    uint16_t filter_pad0;
    uint32_t filter_src_ip4;        /* network byte order */
    uint32_t filter_src_ip4_mask;   /* network byte order (0 = any) */
    uint32_t filter_dst_ip4;        /* network byte order */
    uint32_t filter_dst_ip4_mask;   /* network byte order (0 = any) */
    uint32_t filter_mark;           /* skb->mark match value */
    uint32_t filter_mark_mask;      /* 0 = any */
    uint32_t filter_uid;            /* PKT_FILTER_UID_ANY (0xFFFFFFFFU) = any */
    uint32_t filter_tgid;           /* 0 = any */
    uint8_t  filter_src_ip6[16];    /* optional IPv6 filter (network byte order) */
    uint8_t  filter_src_ip6_mask[16];
    uint8_t  filter_dst_ip6[16];
    uint8_t  filter_dst_ip6_mask[16];

    /* Monotonic IDs & four-level admission / loss counters */
    uint64_t filter_unknown;        /* truncated header / non-first frag / missing sk */
    uint64_t admission_matched;     /* matched structured filter */
    uint64_t admission_selected;    /* selected by sampling policy */
    uint64_t admission_created;     /* inserted into active_slots[active_slot] */
    uint64_t admission_rejected;    /* rejected due to active hash full / quarantine */
    uint64_t rb_drops;              /* ringbuf reserve failures */
    uint64_t ret_unmatched;         /* kretprobe / xmit_ret missing call entry */
    uint64_t identity_conflicts;    /* unexpected same-(netns,ifindex,dir) re-hits */
    uint64_t pkt_seen_seq;          /* packet counter for sample_by_flow == 0 */
    uint64_t next_obj_id;           /* monotonic object_id generator */
    uint64_t next_sample_id;        /* monotonic sample_id generator */
    uint64_t next_call_id;          /* monotonic call_id generator */
    uint64_t last_idle_exit_ns;     /* boottime ns of last 0->1 active_tracked_count transition */
};

/*
 * Map 0 inner (`active_slots[0..1]`): Tracked sk_buff state (64 bytes).
 */
struct bpf_active_val {
    uint64_t object_id;             /* globally unique skb object identity */
    uint64_t sample_id;             /* root sample identity (shared across CLONE/GSO) */
    uint64_t open_visit_id;         /* >0 while lifecycle_state == PKT_STATE_IN_QUEUE */
    uint64_t next_visit_id;         /* per-object monotonic visit counter */
    uint64_t quarantine_until_ns;   /* cooldown deadline when PKT_STATE_QUARANTINED */
    uint32_t lifecycle_state;       /* enum pkt_lifecycle_state (1..4) */
    uint32_t last_netns;            /* last observed netns_inum */
    uint32_t last_ifindex;          /* last observed dev->ifindex */
    uint32_t qdisc_handle;          /* handle of currently queued leaf Qdisc */
    uint32_t qdisc_parent;          /* parent of currently queued leaf Qdisc */
    uint8_t  last_dir;              /* enum pkt_dir */
    uint8_t  saw_qdisc_enq;         /* 1 if qdisc->enqueue hit in current pipeline */
    uint8_t  requeued;              /* 1 if queued in q->gso_skb via dev_requeue_skb */
    uint8_t  slot_hint;             /* 0 or 1: inner slot index */
};

/*
 * Map 2 (`calls`): kprobe/kretprobe & start_xmit/xmit_ret pairing key (24 bytes)
 * and value (112 bytes).
 */
struct bpf_call_key {
    uint64_t ctx_id;                /* task pid_tgid or (1ULL<<63 | irq_bits | cpu) */
    uint64_t sp;                    /* arm64 regs[31] (or skb^cpu for start_xmit tp) */
    uint32_t site_id;               /* entry enum pkt_site_id */
    uint32_t pad;
};

struct bpf_call_val {
    uint64_t call_id;               /* monotonic call_id */
    uint64_t object_id;             /* 0 = sentinel for untracked call while active > 0 */
    uint64_t sample_id;
    uint64_t visit_id;
    uint64_t skb;                   /* raw skb pointer value (never deref on xmit_ret!) */
    uint64_t entry_ts_ns;
    uint32_t netns_inum;
    uint32_t ifindex;
    uint32_t qdisc_handle;
    uint32_t qdisc_parent;
    uint16_t txq;
    uint8_t  dir;
    uint8_t  reopen_on_busy;        /* 1 for tp_start_xmit rollback on NETDEV_TX_BUSY */
    uint32_t pad;
    /* Snapshot for NETDEV_TX_BUSY rollback without touching skb memory */
    uint64_t saved_next_visit_id;
    uint32_t saved_qdisc_handle;
    uint32_t saved_qdisc_parent;
};

/* bpf_sock_owner.flags bits */
enum pkt_sock_owner_flags {
    PKT_SOCK_F_HAS_OWNER   = (1U << 0),
    PKT_SOCK_F_HAS_SENDMSG = (1U << 1),
    PKT_SOCK_F_HAS_PLUGINS = (1U << 2)
};

/*
 * Map 4 (`socks`): Socket ownership + optional `--profile sendmsg` & sock_fields
 * plugin state keyed by `uint64_t sk_ptr` (88 bytes).
 */
struct bpf_sock_owner {
    uint64_t cookie;                /* skc_cookie to defeat struct sock * SLAB reuse */
    uint64_t last_send_ts_ns;       /* populated by kp_tcp_sendmsg / kp_udp_sendmsg */
    uint64_t plugin_vals[PKT_MAX_SOCK_PLUGINS]; /* optional sock plugin values */
    uint32_t tgid;                  /* process PID (tgid) */
    uint32_t uid;                   /* socket UID */
    uint32_t last_send_tid;         /* exact sender tid from sendmsg profile */
    uint32_t plugin_tgid;           /* optional plugin tgid fallback */
    uint32_t plugin_mask;           /* bitmask of valid plugin_vals[0..3] */
    uint32_t flags;                 /* PKT_SOCK_F_* */
    char     comm[16];              /* task comm */
};

/* ==================== 6. Fixed-Size Kernel -> Ringbuf Event Structs ==================== */

/* Common 32-byte header (matches 详细设计.md Appendix B byte-for-byte) */
struct bpf_ev_common {              /* 32 bytes */
    uint16_t kind;                  /* enum pkt_ev_kind (1..6) */
    uint8_t  object_type;           /* enum pkt_obj_type (1=SKB) */
    uint8_t  evidence_level;        /* enum pkt_evid_level (1..4) */
    uint16_t site_dict_idx;         /* enum pkt_site_id */
    uint16_t flags;                 /* PKT_EVF_* */
    uint32_t cpu;
    uint32_t reserved;
    uint64_t seq;                   /* per-CPU monotonic attempt sequence */
    uint64_t ts_ns;                 /* bpf_ktime_get_boot_ns() */
};

/* kind = 1 (PKT_EV_OBJECT): 56 bytes */
struct bpf_ev_object {              /* 56 bytes */
    struct bpf_ev_common h;         /* 32 B */
    uint64_t object_id;             /* 8 B */
    uint64_t sample_id;             /* 8 B */
    uint32_t drop_reason;           /* 4 B */
    uint16_t end_reason;            /* 2 B: enum pkt_end_reason */
    uint16_t reserved;              /* 2 B */
};

/*
 * kind = 2 (PKT_EV_STEP): 80 bytes (matches 详细设计.md Appendix B byte-for-byte).
 * Note: `visit_or_call_id` carries `call_id` (TLV 0x0102) when `stage` is
 * PKT_STAGE_XMIT_START (9) or PKT_STAGE_XMIT_RET (10), and carries `visit_id`
 * (TLV 0x0101) on queue/drop stages (QDISC_ENQ, QDISC_ENQ_RET, QDISC_DEQ,
 * REQUEUE_GSO, REQUEUE_BAD_TXQ, DROP, CONSUME).
 */
struct bpf_ev_step {                /* 80 bytes */
    struct bpf_ev_common h;         /* 32 B */
    uint64_t object_id;             /* 8 B */
    uint64_t visit_or_call_id;      /* 8 B */
    uint32_t netns_inum;            /* 4 B */
    uint32_t ifindex;               /* 4 B */
    uint32_t qdisc_handle;          /* 4 B */
    uint32_t qdisc_parent;          /* 4 B */
    uint32_t classid;               /* 4 B */
    int32_t  raw_ret;               /* 4 B */
    uint32_t ctx_tid;               /* 4 B: 0 if not in_task() */
    uint16_t txq;                   /* 2 B */
    uint8_t  dir;                   /* 1 B: enum pkt_dir */
    uint8_t  stage;                 /* 1 B: enum pkt_step_stage */
};

/* kind = 3 (PKT_EV_RELATION): 72 bytes */
struct bpf_ev_rel {                 /* 72 bytes */
    struct bpf_ev_common h;         /* 32 B */
    uint64_t op_id;                 /* 8 B */
    uint64_t src_object_id;         /* 8 B */
    uint64_t dst_object_id;         /* 8 B */
    uint64_t stream_offset;         /* 8 B */
    uint32_t span_len;              /* 4 B */
    uint8_t  rel_type;              /* 1 B: enum pkt_rel_type */
    uint8_t  rel_flags;             /* 1 B: PKT_RELF_* */
    uint16_t reserved;              /* 2 B */
};

/*
 * kind = 4 (PKT_EV_SUMMARY): 328 bytes (200 B metadata + 128 B snaplen buffer).
 * Reserved directly inside `rb` via `bpf_ringbuf_reserve` so 0 bytes touch the BPF stack.
 * Ports, tcp_seq, tcp_seq_end, and ip_id are in HOST byte order; src_ip/dst_ip
 * are in NETWORK byte order (IPv4 in [0..3], IPv6 in [0..15]).
 */
struct bpf_ev_summary {             /* 328 bytes */
    struct bpf_ev_common h;         /* 32 B */
    uint64_t object_id;             /* 8 B */
    uint64_t skb_create_ts;         /* 8 B */
    uint64_t plugin_vals[PKT_MAX_SOCK_PLUGINS]; /* 32 B: custom sock_fields plugin slots */
    uint32_t netns_inum;            /* 4 B */
    uint32_t ifindex;               /* 4 B */
    uint32_t pkt_len;               /* 4 B */
    uint32_t linear_len;            /* 4 B */
    uint32_t valid_flags;           /* 4 B: PKT_SUM_F_* */
    uint32_t skb_hash;              /* 4 B */
    uint32_t skb_mark;              /* 4 B */
    uint32_t skb_priority;          /* 4 B */
    uint32_t uid;                   /* 4 B */
    uint32_t tgid;                  /* 4 B */
    uint32_t enqueue_tid;           /* 4 B */
    uint32_t plugin_mask;           /* 4 B: bitmask of valid plugin_vals[0..3] */
    uint32_t tcp_seq;               /* 4 B (host byte order) */
    uint32_t tcp_seq_end;           /* 4 B (host byte order) */
    uint16_t src_port;              /* 2 B (host byte order) */
    uint16_t dst_port;              /* 2 B (host byte order) */
    uint16_t ip_id;                 /* 2 B (host byte order) */
    uint16_t linktype;              /* 2 B: 1=ETH, 101=RAW_IP */
    uint8_t  dir;                   /* 1 B: enum pkt_dir */
    uint8_t  ip_version;            /* 1 B: 4, 6, or 0 */
    uint8_t  l4_proto;              /* 1 B */
    uint8_t  tcp_flags;             /* 1 B */
    uint8_t  frag_flags;            /* 1 B: PKT_FRAG_F_* */
    uint8_t  hdr_cap_len;           /* 1 B: 0..128 bytes valid in hdr_bytes[] */
    uint16_t reserved2;             /* 2 B */
    uint8_t  src_ip[16];            /* 16 B (network byte order) */
    uint8_t  dst_ip[16];            /* 16 B (network byte order) */
    char     comm[16];              /* 16 B */
    uint8_t  hdr_bytes[PKT_MAX_SNAP_LEN]; /* 128 B */
};

/* kind = 5 (PKT_EV_QSTATE): 56 bytes (matches 详细设计.md Appendix B byte-for-byte) */
struct bpf_ev_qstate {              /* 56 bytes */
    struct bpf_ev_common h;         /* 32 B */
    uint64_t queue_gen;             /* 8 B */
    uint32_t netns_inum;            /* 4 B */
    uint32_t ifindex;               /* 4 B */
    uint32_t value;                 /* 4 B */
    uint16_t txq;                   /* 2 B */
    uint8_t  state_op;              /* 1 B: enum pkt_qstate_op */
    uint8_t  reserved2;             /* 1 B */
};

/* kind = 6 (PKT_EV_QUALITY): 72 bytes */
struct bpf_ev_quality {             /* 72 bytes */
    struct bpf_ev_common h;         /* 32 B */
    uint64_t object_id;             /* 8 B (0 unless tied to a specific object) */
    uint64_t win_start_ns;          /* 8 B */
    uint64_t win_end_ns;            /* 8 B */
    uint64_t count;                 /* 8 B */
    uint16_t qual_site_idx;         /* 2 B */
    uint8_t  qual_kind;             /* 1 B: enum pkt_qual_kind */
    uint8_t  reserved2;             /* 1 B */
    uint32_t reserved3;             /* 4 B */
};

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct bpf_ev_common)  == 32,  "bpf_ev_common must be 32 B");
_Static_assert(sizeof(struct bpf_ev_object)  == 56,  "bpf_ev_object must be 56 B");
_Static_assert(sizeof(struct bpf_ev_step)    == 80,  "bpf_ev_step must be 80 B");
_Static_assert(sizeof(struct bpf_ev_rel)     == 72,  "bpf_ev_rel must be 72 B");
_Static_assert(sizeof(struct bpf_ev_summary) == 424, "bpf_ev_summary must be 424 B");
_Static_assert(sizeof(struct bpf_ev_qstate)  == 56,  "bpf_ev_qstate must be 56 B");
_Static_assert(sizeof(struct bpf_ev_quality) == 72,  "bpf_ev_quality must be 72 B");
_Static_assert(sizeof(struct bpf_active_val) == 64,  "bpf_active_val must be 64 B");
_Static_assert(sizeof(struct bpf_call_key)   == 24,  "bpf_call_key must be 24 B");
_Static_assert(sizeof(struct bpf_sock_owner) == 184, "bpf_sock_owner must be 184 B");
#endif

/* ==================== 7. Precompiled BPF Program Image Descriptor ==================== */

struct bpf_map_reloc {
    uint32_t insn_idx;              /* 8-byte instruction index in insns */
    uint32_t map_idx;               /* enum pkt_map_idx (0..6) */
};

struct bpf_prog_img {
    const char          *sec_name;     /* ELF section name (e.g. "tp_net_dev_queue") */
    const char          *attach_group; /* tracepoint group ("net"/"skb") or NULL for kprobe */
    const char          *attach_name;  /* tracepoint event or kernel symbol name */
    uint32_t             prog_type;    /* PKT_BPF_PROG_TYPE_TRACEPOINT (5) or KPROBE (2) */
    uint8_t              is_retprobe;  /* 1 = kretprobe, 0 = kprobe / tracepoint */
    uint8_t              layer;        /* 1 = L1 attribution, 2 = L2 datapath */
    uint16_t             site_id;      /* enum pkt_site_id (1..30) */
    unsigned char       *insns;        /* mutable 8B-aligned raw BPF instructions */
    uint32_t             insn_cnt;     /* instruction count (byte_len / 8) */
    uint32_t             reloc_cnt;    /* number of entries in relocs[] */
    struct bpf_map_reloc relocs[PKT_MAX_PROG_RELOCS];
};

#ifdef __cplusplus
}
#endif

#endif /* PKTPATH_BPF_H */
