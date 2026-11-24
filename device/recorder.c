#define _GNU_SOURCE
#include "../include/pktpath_bpf.h"
#include "device_common.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#ifndef BPF_MAP_TYPE_ARRAY_OF_MAPS
#define BPF_MAP_TYPE_ARRAY_OF_MAPS 12
#endif
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif
#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U << 10)
#endif
#ifndef BPF_PSEUDO_MAP_FD
#define BPF_PSEUDO_MAP_FD 1
#endif

#include "../bpf/generated_progs.h"

#ifndef PKT_BPF_PROG_COUNT
#define PKT_BPF_PROG_COUNT (sizeof(pkt_bpf_progs) / sizeof(pkt_bpf_progs[0]))
#endif

/* ==========================================================================
 * 1. Clock, UUID, IEEE CRC32 & Filesystem Utilities
 * ========================================================================== */

uint64_t now_boottime_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0)
        clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t now_realtime_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void sample_clock_calibration(struct clock_calibration *cal) {
    uint64_t b1 = now_boottime_ns();
    uint64_t r  = now_realtime_ns();
    uint64_t b2 = now_boottime_ns();
    cal->boottime_ns = b1 + ((b2 >= b1) ? (b2 - b1) / 2ULL : 0ULL);
    cal->realtime_ns = r;
    cal->err_ns      = (b2 >= b1) ? (b2 - b1) : 0ULL;
}

const char *scope_to_str(enum dev_scope s) {
    switch (s) {
    case SCOPE_TC_EGRESS: return "tc-egress";
    case SCOPE_IP_TX:     return "ip-tx";
    case SCOPE_SOCK_TX:   return "sock-tx";
    case SCOPE_RX_SOCK:   return "rx-sock";
    case SCOPE_FWD:       return "fwd";
    default:              return "tc-egress";
    }
}

const char *mode_to_str(enum dev_mode m) {
    return (m == MODE_DAEMON) ? "daemon" : "oneshot";
}

static void generate_session_uuid(uint8_t uuid[16], char uuid_str[37]) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    ssize_t got = 0;
    if (fd >= 0) {
        got = read(fd, uuid, 16);
        close(fd);
    }
    if (got != 16) {
        uint64_t t1 = now_realtime_ns() ^ ((uint64_t)getpid() << 32);
        uint64_t t2 = now_boottime_ns() ^ 0x504B545041544833ULL;
        memcpy(uuid, &t1, 8);
        memcpy(uuid + 8, &t2, 8);
    }
    /* RFC 4122 v4 variant bits */
    uuid[6] = (uint8_t)((uuid[6] & 0x0FU) | 0x40U);
    uuid[8] = (uint8_t)((uuid[8] & 0x3FU) | 0x80U);

    snprintf(uuid_str, 37,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid[0], uuid[1], uuid[2], uuid[3],
             uuid[4], uuid[5], uuid[6], uuid[7],
             uuid[8], uuid[9], uuid[10], uuid[11],
             uuid[12], uuid[13], uuid[14], uuid[15]);
}

static uint32_t g_crc32_tbl[256];
static bool g_crc32_ready = false;

static void crc32_init_once(void) {
    if (g_crc32_ready) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1U) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
        g_crc32_tbl[i] = c;
    }
    g_crc32_ready = true;
}

static uint32_t crc32_update(uint32_t crc, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    crc = ~crc;
    for (size_t i = 0; i < len; i++)
        crc = g_crc32_tbl[(crc ^ p[i]) & 0xFFU] ^ (crc >> 8);
    return ~crc;
}

static int mkdir_p(const char *dir) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", dir);
    size_t len = strlen(tmp);
    if (len == 0) return -1;
    if (len > 1 && tmp[len - 1] == '/') tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int write_all_fd(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static void json_write_escaped(FILE *fp, const char *s) {
    fputc('"', fp);
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            if (*p == '"' || *p == '\\') {
                fputc('\\', fp);
                fputc((int)*p, fp);
            } else if (*p == '\n') {
                fputs("\\n", fp);
            } else if (*p == '\r') {
                fputs("\\r", fp);
            } else if (*p == '\t') {
                fputs("\\t", fp);
            } else if (*p >= 0x20 && *p < 0x7F) {
                fputc((int)*p, fp);
            }
        }
    }
    fputc('"', fp);
}

/* ==========================================================================
 * 2. Signal Handling
 * ========================================================================== */

static volatile sig_atomic_t g_sig_stop = 0;
static volatile sig_atomic_t g_sig_flush = 0;

static void on_sig_stop(int sig) {
    (void)sig;
    g_sig_stop = 1;
}

static void on_sig_usr1(int sig) {
    (void)sig;
    g_sig_flush = 1;
}

static void install_signal_handlers(void) {
    g_sig_stop = 0;
    g_sig_flush = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sig_stop;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sig_usr1;
    sigaction(SIGUSR1, &sa, NULL);
}

/* ==========================================================================
 * 3. Kernel Syscall Wrappers (BPF & Perf)
 * ========================================================================== */

static int bpf_sys(int cmd, union bpf_attr *attr, size_t sz) {
    return (int)syscall(__NR_bpf, cmd, attr, sz);
}

static int bpf_create_map_ext(uint32_t map_type, uint32_t key_sz, uint32_t val_sz,
                              uint32_t max_entries, uint32_t map_flags, int inner_fd) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_type    = map_type;
    a.key_size    = key_sz;
    a.value_size  = val_sz;
    a.max_entries = max_entries;
    a.map_flags   = map_flags;
    if (inner_fd >= 0)
        a.inner_map_fd = (uint32_t)inner_fd;
    return bpf_sys(BPF_MAP_CREATE, &a, sizeof(a));
}

static int bpf_map_lookup(int fd, const void *key, void *val) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_fd = (uint32_t)fd;
    a.key    = (uintptr_t)key;
    a.value  = (uintptr_t)val;
    return bpf_sys(BPF_MAP_LOOKUP_ELEM, &a, sizeof(a));
}

static int bpf_map_update(int fd, const void *key, const void *val, uint64_t flags) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_fd = (uint32_t)fd;
    a.key    = (uintptr_t)key;
    a.value  = (uintptr_t)val;
    a.flags  = flags;
    return bpf_sys(BPF_MAP_UPDATE_ELEM, &a, sizeof(a));
}

static int bpf_map_delete(int fd, const void *key) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_fd = (uint32_t)fd;
    a.key    = (uintptr_t)key;
    return bpf_sys(BPF_MAP_DELETE_ELEM, &a, sizeof(a));
}

static int bpf_map_get_next_key(int fd, const void *key, void *next_key) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_fd   = (uint32_t)fd;
    a.key      = (uintptr_t)key;
    a.next_key = (uintptr_t)next_key;
    return bpf_sys(BPF_MAP_GET_NEXT_KEY, &a, sizeof(a));
}

static int bpf_read_recursion_misses(int prog_fd, uint64_t *misses_out) {
    struct bpf_prog_info info;
    memset(&info, 0, sizeof(info));
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.info.bpf_fd   = (uint32_t)prog_fd;
    a.info.info_len = sizeof(info);
    a.info.info     = (uintptr_t)&info;
    if (bpf_sys(BPF_OBJ_GET_INFO_BY_FD, &a, sizeof(a)) < 0)
        return -1;
    if (a.info.info_len < offsetof(struct bpf_prog_info, recursion_misses) + 8U)
        return -1;
    *misses_out = info.recursion_misses;
    return 0;
}

/* ==========================================================================
 * 4. Adapter & Site Metadata Catalogue
 * ========================================================================== */

struct adapter_plan {
    char        adapter_id[64];
    char        name[96];
    bool        required;
    bool        enabled;
    bool        is_plugin;
    char        missing_reason[128];
    char        missed_source[64];
};

struct site_plan {
    uint16_t    site_id;
    int         prog_idx;         /* index into pkt_bpf_progs[] or -1 */
    int         adapter_idx;      /* index into plan->adapters[] */
    uint8_t     stage;            /* enum pkt_step_stage (0 for non-step) */
    bool        desired;
    bool        available;
    bool        attached;
    uint16_t    dyn_patch_enq_site; /* runtime BPF imm patch for PKT_SITE_DYN_ENQ_SENTINEL */
    uint16_t    dyn_patch_ret_site; /* runtime BPF imm patch for PKT_SITE_DYN_RET_SENTINEL */
    char        site_name[96];    /* custom display name for cloned dynamic sites */
    char        target_sym[128];  /* override symbol for dynamic plugin slots */
    char        qdisc_kind[32];   /* optional qdisc kind hint for dict.json / topo */
    char        resolved_sym[128];
    char        kp_event_name[96];
    char        missing_reason[128];
    int         prog_fd;
    int         num_perf_fds;
    int         perf_fds[DEV_MAX_CPUS];
    uint64_t    last_kp_missed;
    uint64_t    last_rec_missed;
};

enum adapter_idx {
    ADAPT_L2_CORE        = 0,
    ADAPT_L2_REQUEUE     = 1,
    ADAPT_L2_HTB         = 2,
    ADAPT_L2_FQ_CODEL    = 3,
    ADAPT_L2_PFIFO       = 4,
    ADAPT_L2_FIFO        = 5,
    ADAPT_L2_SFQ         = 6,
    ADAPT_L2_TC_CLASSIFY = 7,
    ADAPT_L2_TRANSFORMS  = 8,
    ADAPT_L2_QSTATE      = 9,
    ADAPT_L1_SOCK_BASE   = 10,
    ADAPT_L1_SENDMSG     = 11,
    ADAPT_BUILTIN_COUNT  = 12,
};

static uint8_t default_stage_for_site(uint16_t site_id) {
    switch (site_id) {
    case PKT_SITE_TP_NET_DEV_QUEUE:   return PKT_STAGE_ENTRY;
    case PKT_SITE_KP_HTB_ENQ:         return PKT_STAGE_CLASSIFY;
    case PKT_SITE_KP_FQ_CODEL_ENQ:    return PKT_STAGE_QDISC_ENQ;
    case PKT_SITE_KR_FQ_CODEL_ENQ:    return PKT_STAGE_QDISC_ENQ_RET;
    case PKT_SITE_KR_FQ_CODEL_DEQ:    return PKT_STAGE_QDISC_DEQ;
    case PKT_SITE_KP_PFIFO_ENQ:       return PKT_STAGE_QDISC_ENQ;
    case PKT_SITE_KR_PFIFO_ENQ:       return PKT_STAGE_QDISC_ENQ_RET;
    case PKT_SITE_KR_PFIFO_DEQ:       return PKT_STAGE_QDISC_DEQ;
    case PKT_SITE_KP_FIFO_ENQ:        return PKT_STAGE_QDISC_ENQ;
    case PKT_SITE_KR_FIFO_ENQ:        return PKT_STAGE_QDISC_ENQ_RET;
    case PKT_SITE_KP_BFIFO_ENQ:       return PKT_STAGE_QDISC_ENQ;
    case PKT_SITE_KR_BFIFO_ENQ:       return PKT_STAGE_QDISC_ENQ_RET;
    case PKT_SITE_KP_PTAIL_ENQ:       return PKT_STAGE_QDISC_ENQ;
    case PKT_SITE_KR_PTAIL_ENQ:       return PKT_STAGE_QDISC_ENQ_RET;
    case PKT_SITE_KR_FIFO_DEQ:        return PKT_STAGE_QDISC_DEQ;
    case PKT_SITE_KP_SFQ_ENQ:         return PKT_STAGE_QDISC_ENQ;
    case PKT_SITE_KR_SFQ_ENQ:         return PKT_STAGE_QDISC_ENQ_RET;
    case PKT_SITE_KR_SFQ_DEQ:         return PKT_STAGE_QDISC_DEQ;
    case PKT_SITE_KP_TCF_CLASSIFY:    return PKT_STAGE_CLASSIFY;
    case PKT_SITE_KR_TCF_CLASSIFY:    return PKT_STAGE_CLASSIFY;
    case PKT_SITE_KP_SCH_DIRECT_XMIT: return PKT_STAGE_BYPASS_DIRECT;
    case PKT_SITE_KP_DEV_REQUEUE:     return PKT_STAGE_REQUEUE_GSO;
    case PKT_SITE_TP_START_XMIT:      return PKT_STAGE_XMIT_START;
    case PKT_SITE_TP_XMIT_RET:        return PKT_STAGE_XMIT_RET;
    case PKT_SITE_TP_KFREE_SKB:       return PKT_STAGE_DROP;
    case PKT_SITE_TP_CONSUME_SKB:     return PKT_STAGE_CONSUME;
    case PKT_SITE_TMPL_PLUG_CLS_ENQ:  return PKT_STAGE_CLASSIFY;
    case PKT_SITE_TMPL_PLUG_LEAF_ENQ: return PKT_STAGE_QDISC_ENQ;
    case PKT_SITE_TMPL_PLUG_LEAF_RET: return PKT_STAGE_QDISC_ENQ_RET;
    case PKT_SITE_TMPL_PLUG_LEAF_DEQ: return PKT_STAGE_QDISC_DEQ;
    default:                          return 0;
    }
}

static const char *inferred_qdisc_kind_for_site(uint16_t site_id) {
    switch (site_id) {
    case PKT_SITE_KP_HTB_ENQ:
        return "htb";
    case PKT_SITE_KP_FQ_CODEL_ENQ:
    case PKT_SITE_KR_FQ_CODEL_ENQ:
    case PKT_SITE_KR_FQ_CODEL_DEQ:
        return "fq_codel";
    case PKT_SITE_KP_PFIFO_ENQ:
    case PKT_SITE_KR_PFIFO_ENQ:
    case PKT_SITE_KR_PFIFO_DEQ:
        return "pfifo_fast";
    case PKT_SITE_KP_FIFO_ENQ:
    case PKT_SITE_KR_FIFO_ENQ:
    case PKT_SITE_KR_FIFO_DEQ:
        return "pfifo";
    case PKT_SITE_KP_BFIFO_ENQ:
    case PKT_SITE_KR_BFIFO_ENQ:
        return "bfifo";
    case PKT_SITE_KP_PTAIL_ENQ:
    case PKT_SITE_KR_PTAIL_ENQ:
        return "pfifo_head_drop";
    case PKT_SITE_KP_SFQ_ENQ:
    case PKT_SITE_KR_SFQ_ENQ:
    case PKT_SITE_KR_SFQ_DEQ:
        return "sfq";
    default:
        return "";
    }
}

static int adapter_for_site(uint16_t site_id) {
    switch (site_id) {
    case PKT_SITE_TP_SOCK_CREATE:
    case PKT_SITE_KP_TCP_V4_CONN:
    case PKT_SITE_KP_TCP_V6_CONN:
    case PKT_SITE_KR_INET_ACCEPT:
    case PKT_SITE_KP_SK_DESTRUCT:
        return ADAPT_L1_SOCK_BASE;
    case PKT_SITE_KP_TCP_SENDMSG:
    case PKT_SITE_KP_UDP_SENDMSG:
        return ADAPT_L1_SENDMSG;
    case PKT_SITE_TP_NET_DEV_QUEUE:
    case PKT_SITE_KP_SCH_DIRECT_XMIT:
    case PKT_SITE_TP_START_XMIT:
    case PKT_SITE_TP_XMIT_RET:
    case PKT_SITE_TP_KFREE_SKB:
    case PKT_SITE_TP_CONSUME_SKB:
        return ADAPT_L2_CORE;
    case PKT_SITE_KP_DEV_REQUEUE:
        return ADAPT_L2_REQUEUE;
    case PKT_SITE_KP_HTB_ENQ:
        return ADAPT_L2_HTB;
    case PKT_SITE_KP_FQ_CODEL_ENQ:
    case PKT_SITE_KR_FQ_CODEL_ENQ:
    case PKT_SITE_KR_FQ_CODEL_DEQ:
        return ADAPT_L2_FQ_CODEL;
    case PKT_SITE_KP_PFIFO_ENQ:
    case PKT_SITE_KR_PFIFO_ENQ:
    case PKT_SITE_KR_PFIFO_DEQ:
        return ADAPT_L2_PFIFO;
    case PKT_SITE_KP_FIFO_ENQ:
    case PKT_SITE_KR_FIFO_ENQ:
    case PKT_SITE_KP_BFIFO_ENQ:
    case PKT_SITE_KR_BFIFO_ENQ:
    case PKT_SITE_KP_PTAIL_ENQ:
    case PKT_SITE_KR_PTAIL_ENQ:
    case PKT_SITE_KR_FIFO_DEQ:
        return ADAPT_L2_FIFO;
    case PKT_SITE_KP_SFQ_ENQ:
    case PKT_SITE_KR_SFQ_ENQ:
    case PKT_SITE_KR_SFQ_DEQ:
        return ADAPT_L2_SFQ;
    case PKT_SITE_KP_TCF_CLASSIFY:
    case PKT_SITE_KR_TCF_CLASSIFY:
        return ADAPT_L2_TC_CLASSIFY;
    case PKT_SITE_KP_SKB_CLONE:
    case PKT_SITE_KR_SKB_CLONE:
    case PKT_SITE_KP_PSKB_EXPAND:
        return ADAPT_L2_TRANSFORMS;
    case PKT_SITE_KP_TXQ_STOP:
    case PKT_SITE_KP_TXQ_WAKE:
        return ADAPT_L2_QSTATE;
    default:
        return -1; /* dynamic plugin slot */
    }
}

struct probe_plan {
    struct utsname            uts;
    char                      boot_id[64];
    struct dev_btf_resolved   btf;
    struct dev_plugin_registry plugins;
    bool                      sock_plugins_active;
    bool                      has_kprobe_profile;
    bool                      has_rec_misses;
    bool                      partial_coverage;
    uint32_t                  target_ifindex;
    int                       num_adapters;
    struct adapter_plan       adapters[DEV_MAX_ADAPTERS];
    uint32_t                  num_sites;
    struct site_plan          sites[DEV_MAX_SITES];
};

static bool check_recursion_misses_support(void) {
    struct bpf_insn insns[2] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
        {.code = BPF_JMP | BPF_EXIT},
    };
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    a.insns     = (uintptr_t)insns;
    a.insn_cnt  = 2;
    a.license   = (uintptr_t)"GPL";
    int fd = bpf_sys(BPF_PROG_LOAD, &a, offsetof(union bpf_attr, kern_version) + 4U);
    if (fd < 0) return true; /* assume supported on 5.12+ if socket_filter restricted */
    uint64_t dummy = 0;
    bool ok = (bpf_read_recursion_misses(fd, &dummy) == 0);
    close(fd);
    return ok;
}

static void populate_bpf_btf_offsets(const struct probe_plan *plan,
                                     struct bpf_btf_offsets *bo) {
    const struct dev_btf_resolved *r = &plan->btf;
    memset(bo, 0, sizeof(*bo));
    bo->skb_dev              = r->skb_dev;
    bo->skb_sk               = r->skb_sk;
    bo->skb_len              = r->skb_len;
    bo->skb_data_len         = r->skb_data_len;
    bo->skb_head             = r->skb_head;
    bo->skb_data             = r->skb_data;
    bo->skb_network_header   = r->skb_network_header;
    bo->skb_transport_header = r->skb_transport_header;
    bo->skb_mac_header       = r->skb_mac_header;
    bo->skb_protocol         = r->skb_protocol;
    bo->skb_pkt_type         = r->skb_pkt_type;
    bo->skb_hash             = r->skb_hash;
    bo->skb_mark             = r->skb_mark;
    bo->skb_priority         = r->skb_priority;
    bo->skb_cb               = r->skb_cb;
    bo->dev_ifindex          = r->dev_ifindex;
    bo->dev_nd_net           = r->dev_nd_net;
    bo->net_ns_inum          = r->net_ns_inum;
    bo->sk_state             = r->sk_state;
    bo->sk_cookie            = r->sk_cookie;
    bo->sk_uid               = r->sk_uid;
    bo->socket_sk            = r->socket_sk;
    bo->qdisc_handle         = r->qdisc_handle;
    bo->qdisc_parent         = r->qdisc_parent;
    bo->task_preempt_count   = r->task_preempt_count;
    bo->tp_kfree_skb_reason  = r->tp_kfree_skb_reason;
    bo->dev_tx_queues        = r->dev_tx_queues;
    bo->netdev_queue_sz      = r->netdev_queue_sz;
    bo->tcf_res_classid      = r->tcf_res_classid;
    uint32_t max_slot = 0, valid_mask = 0;
    for (int i = 0; i < plan->plugins.num_sock_fields && i < (int)PKT_MAX_SOCK_PLUGINS; i++) {
        const struct dev_plugin_sock_field *sf = &plan->plugins.sock_fields[i];
        if (sf->resolved && sf->resolved_offset > 0) {
            bo->sock_plugins[i].offset = sf->resolved_offset;
            bo->sock_plugins[i].size   = sf->size;
            bo->sock_plugins[i].role   = sf->role;
            valid_mask |= (1U << i);
            max_slot = (uint32_t)(i + 1);
        }
    }
    bo->sock_plugin_count      = max_slot;
    bo->sock_plugin_valid_mask = valid_mask;
}

static const char *site_qdisc_kind(const struct probe_plan *plan, uint16_t site_id) {
    if (plan) {
        for (uint32_t i = 0; i < plan->num_sites; i++) {
            if (plan->sites[i].site_id == site_id && plan->sites[i].qdisc_kind[0])
                return plan->sites[i].qdisc_kind;
        }
    }
    return inferred_qdisc_kind_for_site(site_id);
}

static int build_probe_plan(const struct dev_cli_opts *opts,
                            const struct topo_mgr *topo,
                            struct probe_plan *plan,
                            char *err_buf, size_t err_cap) {
    memset(plan, 0, sizeof(*plan));
    uname(&plan->uts);
    if (read_boot_id(plan->boot_id, sizeof(plan->boot_id)) != 0)
        snprintf(plan->boot_id, sizeof(plan->boot_id), "unknown");

    /* 1. Resolve target device in topology (also support '--dev any') */
    const struct topo_dev_entry *tdev = NULL;
    if (strcmp(opts->dev_name, "any") == 0) {
        plan->target_ifindex = 0;
    } else {
        tdev = topo_find_dev_by_name(topo, opts->dev_name);
        if (!tdev) {
            if (err_buf && err_cap)
                snprintf(err_buf, err_cap, "network interface '%s' not found in current netns", opts->dev_name);
            return -1;
        }
        plan->target_ifindex = tdev->ifindex;
    }

    /* 2. Fail-closed BTF resolution + runtime JSON plugin loading */
    char btf_err[256] = "";
    struct btf_db *bdb = btf_db_load("/sys/kernel/btf/vmlinux", btf_err, sizeof(btf_err));
    if (!bdb) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "BTF load failed: %s", btf_err);
        return -1;
    }
    if (btf_resolve_all_offsets(bdb, &plan->btf) != 0) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "BTF verification failed: %s", plan->btf.error);
        btf_db_free(bdb);
        return -1;
    }
    if (plugin_registry_load(opts, bdb, &plan->plugins, err_buf, err_cap) != 0) {
        btf_db_free(bdb);
        return -1;
    }
    btf_db_free(bdb);

    /* 3. Scope check */
    if (opts->scope == SCOPE_RX_SOCK) {
        if (!opts->allow_partial) {
            if (err_buf && err_cap)
                snprintf(err_buf, err_cap,
                         "scope 'rx-sock' requires RX socket adapter (pass --allow-partial to degrade)");
            return -1;
        }
        plan->partial_coverage = true;
    }

    /* 4. Kallsyms & missed_source capability check */
    char ksym_err[256] = "";
    struct ksym_db *kdb = ksym_db_load("/proc/kallsyms", ksym_err, sizeof(ksym_err));
    if (!kdb) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "kallsyms load failed: %s", ksym_err);
        return -1;
    }

    char kp_prof_path[256];
    snprintf(kp_prof_path, sizeof(kp_prof_path), "%s/kprobe_profile", tracefs_root());
    plan->has_kprobe_profile = (access(kp_prof_path, R_OK) == 0);
    plan->has_rec_misses     = check_recursion_misses_support();

    const char *tp_missed_src = plan->has_rec_misses ? "recursion_misses" : "none";
    const char *kp_missed_src = (plan->has_kprobe_profile && plan->has_rec_misses)
                                    ? "kprobe_profile+recursion_misses"
                                    : (plan->has_kprobe_profile ? "kprobe_profile"
                                       : (plan->has_rec_misses ? "recursion_misses" : "none"));

    /* 5. Initialize built-in upstream Linux adapters */
    static const struct {
        const char *id;
        const char *name;
        bool        is_tp_primary;
    } k_adap_defs[ADAPT_BUILTIN_COUNT] = {
        [ADAPT_L2_CORE]        = {"l2_tc_egress_core",  "TC/Qdisc & Driver Egress Core", true},
        [ADAPT_L2_REQUEUE]     = {"l2_qdisc_requeue",   "Driver BUSY Requeue Adapter",   false},
        [ADAPT_L2_HTB]         = {"l2_qdisc_htb",       "HTB Classful Qdisc Adapter",    false},
        [ADAPT_L2_FQ_CODEL]    = {"l2_qdisc_fq_codel",  "fq_codel Leaf Qdisc Adapter",   false},
        [ADAPT_L2_PFIFO]       = {"l2_qdisc_pfifo",     "pfifo_fast Leaf Adapter",       false},
        [ADAPT_L2_FIFO]        = {"l2_qdisc_fifo",      "pfifo/bfifo HTB Leaf Adapter",  false},
        [ADAPT_L2_SFQ]         = {"l2_qdisc_sfq",       "SFQ Leaf Qdisc Adapter",        false},
        [ADAPT_L2_TC_CLASSIFY] = {"l2_tc_classify",     "TC Filter & Class Attribution", false},
        [ADAPT_L2_TRANSFORMS]  = {"l2_skb_transforms",  "SKB Clone & Head Expand",       false},
        [ADAPT_L2_QSTATE]      = {"l2_txq_qstate",      "TXQ Stop/Wake Backpressure",    false},
        [ADAPT_L1_SOCK_BASE]   = {"l1_sock_attribution","Standard Linux Socket Owner",   false},
        [ADAPT_L1_SENDMSG]     = {"l1_sendmsg_profile", "Exact sendmsg TID & Create TS", false},
    };
    plan->num_adapters = ADAPT_BUILTIN_COUNT;
    for (int i = 0; i < ADAPT_BUILTIN_COUNT; i++) {
        snprintf(plan->adapters[i].adapter_id, sizeof(plan->adapters[i].adapter_id), "%s", k_adap_defs[i].id);
        snprintf(plan->adapters[i].name, sizeof(plan->adapters[i].name), "%s", k_adap_defs[i].name);
        plan->adapters[i].enabled = false;
        snprintf(plan->adapters[i].missed_source, sizeof(plan->adapters[i].missed_source),
                 "%s", k_adap_defs[i].is_tp_primary ? tp_missed_src : kp_missed_src);
    }

    bool dev_uses_pfifo = topo_dev_has_qdisc_kind(topo, plan->target_ifindex, "pfifo_fast");
    bool dev_uses_fifo  = (plan->target_ifindex == 0) ||
                          topo_dev_has_qdisc_kind(topo, plan->target_ifindex, "htb") ||
                          topo_dev_has_qdisc_kind(topo, plan->target_ifindex, "pfifo") ||
                          topo_dev_has_qdisc_kind(topo, plan->target_ifindex, "bfifo") ||
                          topo_dev_has_qdisc_kind(topo, plan->target_ifindex, "pfifo_head_drop");
    bool dev_uses_sfq   = (plan->target_ifindex == 0) ||
                          topo_dev_has_qdisc_kind(topo, plan->target_ifindex, "sfq");

    plan->adapters[ADAPT_L2_CORE].required      = true;
    plan->adapters[ADAPT_L1_SOCK_BASE].required = true;
    plan->adapters[ADAPT_L1_SENDMSG].required   = opts->profile_sendmsg;

    if (!opts->profile_sendmsg) {
        snprintf(plan->adapters[ADAPT_L1_SENDMSG].missing_reason,
                 sizeof(plan->adapters[0].missing_reason), "disabled (default profile)");
    }

    /* 5b. Register dynamic runtime sock_fields plugin adapter (if loaded via --plugin) */
    int sock_plug_adapt_idx = -1;
    if (plan->plugins.num_sock_fields > 0 && plan->num_adapters < DEV_MAX_ADAPTERS) {
        sock_plug_adapt_idx = plan->num_adapters++;
        struct adapter_plan *ad = &plan->adapters[sock_plug_adapt_idx];
        snprintf(ad->adapter_id, sizeof(ad->adapter_id), "l1_sock_plugins");
        snprintf(ad->name, sizeof(ad->name), "Custom Socket Field Plugins");
        ad->is_plugin = true;
        ad->required = false;
        snprintf(ad->missed_source, sizeof(ad->missed_source), "%s", tp_missed_src);
        int resolved_cnt = 0;
        const char *first_sf_err = NULL;
        for (int i = 0; i < plan->plugins.num_sock_fields; i++) {
            if (plan->plugins.sock_fields[i].resolved) resolved_cnt++;
            else if (!first_sf_err) first_sf_err = plan->plugins.sock_fields[i].error;
        }
        if (resolved_cnt > 0) {
            ad->enabled = true;
            plan->sock_plugins_active = true;
            if (resolved_cnt < plan->plugins.num_sock_fields) {
                snprintf(ad->missing_reason, sizeof(ad->missing_reason),
                         "partial (%d/%d; %s)", resolved_cnt, plan->plugins.num_sock_fields,
                         first_sf_err ? first_sf_err : "field absent");
            }
        } else {
            ad->enabled = false;
            snprintf(ad->missing_reason, sizeof(ad->missing_reason),
                     "%s", first_sf_err ? first_sf_err : "no plugin sock fields resolved");
        }
    }

    /* 5c. Register dynamic runtime qdisc plugin adapters */
    int qdisc_plug_adapt_idx[DEV_MAX_PLUGIN_QDISCS];
    for (int i = 0; i < DEV_MAX_PLUGIN_QDISCS; i++) qdisc_plug_adapt_idx[i] = -1;
    for (int q = 0; q < plan->plugins.num_qdiscs && plan->num_adapters < DEV_MAX_ADAPTERS; q++) {
        const struct dev_plugin_qdisc *pq = &plan->plugins.qdiscs[q];
        int aidx = plan->num_adapters++;
        qdisc_plug_adapt_idx[q] = aidx;
        struct adapter_plan *ad = &plan->adapters[aidx];
        snprintf(ad->adapter_id, sizeof(ad->adapter_id), "%s", pq->adapter_id);
        snprintf(ad->name, sizeof(ad->name), "%s", pq->name);
        ad->is_plugin = true;
        ad->required = topo_dev_has_qdisc_kind(topo, plan->target_ifindex, pq->kind);
        snprintf(ad->missed_source, sizeof(ad->missed_source), "%s", kp_missed_src);
    }

    /* 6. Resolve compiled BPF programs (built-in probes + dynamically cloned plugin templates) */
    int tmpl_cls_idx = -1, tmpl_leaf_enq_idx = -1, tmpl_leaf_ret_idx = -1, tmpl_leaf_deq_idx = -1;
    uint32_t nprogs = (uint32_t)PKT_BPF_PROG_COUNT;
    for (uint32_t i = 0; i < nprogs; i++) {
        const struct bpf_prog_img *im = &pkt_bpf_progs[i];
        if (im->site_id == PKT_SITE_TMPL_PLUG_CLS_ENQ)  { tmpl_cls_idx      = (int)i; continue; }
        if (im->site_id == PKT_SITE_TMPL_PLUG_LEAF_ENQ) { tmpl_leaf_enq_idx = (int)i; continue; }
        if (im->site_id == PKT_SITE_TMPL_PLUG_LEAF_RET) { tmpl_leaf_ret_idx = (int)i; continue; }
        if (im->site_id == PKT_SITE_TMPL_PLUG_LEAF_DEQ) { tmpl_leaf_deq_idx = (int)i; continue; }
        if (plan->num_sites >= DEV_MAX_SITES) break;

        int aidx = adapter_for_site(im->site_id);
        if (aidx < 0) continue;
        const char *sym_name = im->attach_name;
        const char *qkind_hint = inferred_qdisc_kind_for_site(im->site_id);
        bool desired = true;

        if (aidx == ADAPT_L1_SENDMSG && !opts->profile_sendmsg) desired = false;
        if (aidx == ADAPT_L2_PFIFO && !dev_uses_pfifo) desired = false;
        if (aidx == ADAPT_L2_FIFO && !dev_uses_fifo) desired = false;
        if (aidx == ADAPT_L2_SFQ && !dev_uses_sfq) desired = false;

        struct site_plan *sp = &plan->sites[plan->num_sites++];
        memset(sp, 0, sizeof(*sp));
        sp->site_id     = im->site_id;
        sp->prog_idx    = (int)i;
        sp->adapter_idx = aidx;
        sp->stage       = default_stage_for_site(im->site_id);
        sp->prog_fd     = -1;
        sp->desired     = desired;
        if (sym_name) snprintf(sp->target_sym, sizeof(sp->target_sym), "%s", sym_name);
        if (qkind_hint && qkind_hint[0]) snprintf(sp->qdisc_kind, sizeof(sp->qdisc_kind), "%s", qkind_hint);

        if (im->prog_type == PKT_BPF_PROG_TYPE_TRACEPOINT) {
            const char *grp = im->attach_group ? im->attach_group : "net";
            if (tracefs_event_exists(grp, sym_name)) {
                sp->available = true;
                snprintf(sp->resolved_sym, sizeof(sp->resolved_sym), "%s:%s", grp, sym_name);
            } else {
                sp->available = false;
                snprintf(sp->missing_reason, sizeof(sp->missing_reason),
                         "tracepoint %s:%s absent", grp, sym_name);
            }
        } else {
            int rc = ksym_resolve(kdb, sym_name, sp->resolved_sym, sizeof(sp->resolved_sym));
            if (rc == 0) {
                sp->available = true;
            } else if (rc == -2) {
                sp->available = false;
                snprintf(sp->missing_reason, sizeof(sp->missing_reason),
                         "ambiguous ThinLTO symbol '%s'", sym_name);
            } else {
                sp->available = false;
                snprintf(sp->missing_reason, sizeof(sp->missing_reason),
                         "symbol '%s' absent/inlined", sym_name);
            }
        }
    }

    /* 6b. Dynamically clone BPF template programs for every loaded plugin qdisc (no 2-slot cap!) */
    uint16_t next_dyn_site = PKT_SITE_DYN_BASE;
    for (int q = 0; q < plan->plugins.num_qdiscs; q++) {
        const struct dev_plugin_qdisc *pq = &plan->plugins.qdiscs[q];
        int aidx = qdisc_plug_adapt_idx[q];
        if (aidx < 0) continue;
        bool desired = (plan->target_ifindex == 0) ||
                       topo_dev_has_qdisc_kind(topo, plan->target_ifindex, pq->kind);

        if (!pq->is_leaf) {
            if (tmpl_cls_idx < 0 || !pq->enqueue_sym[0] || plan->num_sites >= DEV_MAX_SITES)
                continue;
            uint16_t s_enq = next_dyn_site++;
            struct site_plan *sp = &plan->sites[plan->num_sites++];
            memset(sp, 0, sizeof(*sp));
            sp->site_id            = s_enq;
            sp->prog_idx           = tmpl_cls_idx;
            sp->adapter_idx        = aidx;
            sp->stage              = PKT_STAGE_CLASSIFY;
            sp->prog_fd            = -1;
            sp->desired            = desired;
            sp->dyn_patch_enq_site = s_enq;
            snprintf(sp->site_name, sizeof(sp->site_name), "kp_plug_%s_enq", pq->kind);
            snprintf(sp->target_sym, sizeof(sp->target_sym), "%s", pq->enqueue_sym);
            snprintf(sp->qdisc_kind, sizeof(sp->qdisc_kind), "%s", pq->kind);

            int rc = ksym_resolve(kdb, pq->enqueue_sym, sp->resolved_sym, sizeof(sp->resolved_sym));
            if (rc == 0) {
                sp->available = true;
            } else if (rc == -2) {
                snprintf(sp->missing_reason, sizeof(sp->missing_reason),
                         "ambiguous ThinLTO symbol '%s'", pq->enqueue_sym);
            } else {
                snprintf(sp->missing_reason, sizeof(sp->missing_reason),
                         "symbol '%s' absent/inlined", pq->enqueue_sym);
            }
        } else {
            if (tmpl_leaf_enq_idx < 0 || tmpl_leaf_ret_idx < 0 || tmpl_leaf_deq_idx < 0)
                continue;
            if (!pq->enqueue_sym[0] || !pq->dequeue_sym[0] || plan->num_sites + 3U > DEV_MAX_SITES)
                continue;
            uint16_t s_enq = next_dyn_site++;
            uint16_t s_ret = next_dyn_site++;
            uint16_t s_deq = next_dyn_site++;

            const struct {
                uint16_t    sid;
                int         pidx;
                uint8_t     stage;
                uint16_t    patch_enq;
                uint16_t    patch_ret;
                const char *sym;
                const char *suffix;
            } legs[3] = {
                {s_enq, tmpl_leaf_enq_idx, PKT_STAGE_QDISC_ENQ,     s_enq, 0,     pq->enqueue_sym, "enq"},
                {s_ret, tmpl_leaf_ret_idx, PKT_STAGE_QDISC_ENQ_RET, s_enq, s_ret, pq->enqueue_sym, "enq_ret"},
                {s_deq, tmpl_leaf_deq_idx, PKT_STAGE_QDISC_DEQ,     s_deq, 0,     pq->dequeue_sym, "deq"},
            };

            for (int leg = 0; leg < 3; leg++) {
                struct site_plan *sp = &plan->sites[plan->num_sites++];
                memset(sp, 0, sizeof(*sp));
                sp->site_id            = legs[leg].sid;
                sp->prog_idx           = legs[leg].pidx;
                sp->adapter_idx        = aidx;
                sp->stage              = legs[leg].stage;
                sp->prog_fd            = -1;
                sp->desired            = desired;
                sp->dyn_patch_enq_site = legs[leg].patch_enq;
                sp->dyn_patch_ret_site = legs[leg].patch_ret;
                snprintf(sp->site_name, sizeof(sp->site_name), "plug_%s_%s", pq->kind, legs[leg].suffix);
                snprintf(sp->target_sym, sizeof(sp->target_sym), "%s", legs[leg].sym);
                snprintf(sp->qdisc_kind, sizeof(sp->qdisc_kind), "%s", pq->kind);

                int rc = ksym_resolve(kdb, legs[leg].sym, sp->resolved_sym, sizeof(sp->resolved_sym));
                if (rc == 0) {
                    sp->available = true;
                } else if (rc == -2) {
                    snprintf(sp->missing_reason, sizeof(sp->missing_reason),
                             "ambiguous ThinLTO symbol '%s'", legs[leg].sym);
                } else {
                    snprintf(sp->missing_reason, sizeof(sp->missing_reason),
                             "symbol '%s' absent/inlined", legs[leg].sym);
                }
            }
        }
    }
    ksym_db_free(kdb);

    /* 7. Roll up adapter enabled / missing_reason status */
    for (int a = 0; a < plan->num_adapters; a++) {
        if (a == sock_plug_adapt_idx) continue;
        int desired_cnt = 0, avail_cnt = 0;
        const char *first_err = NULL;
        for (uint32_t s = 0; s < plan->num_sites; s++) {
            const struct site_plan *sp = &plan->sites[s];
            if (sp->adapter_idx != a) continue;
            if (!sp->desired) continue;
            desired_cnt++;
            if (sp->available) avail_cnt++;
            else if (!first_err) first_err = sp->missing_reason;
        }
        if (desired_cnt == 0) {
            plan->adapters[a].enabled = false;
            if (!plan->adapters[a].missing_reason[0]) {
                bool unused_qdisc = (a == ADAPT_L2_PFIFO || a == ADAPT_L2_FIFO ||
                                     a == ADAPT_L2_SFQ || plan->adapters[a].is_plugin);
                snprintf(plan->adapters[a].missing_reason, sizeof(plan->adapters[a].missing_reason),
                         unused_qdisc ? "not used on target device" : "disabled");
            }
        } else if (avail_cnt == desired_cnt) {
            plan->adapters[a].enabled = true;
        } else if (a == ADAPT_L2_FIFO) {
            bool has_pfifo_enq = false, has_pfifo_ret = false, has_fifo_deq = false;
            for (uint32_t s = 0; s < plan->num_sites; s++) {
                const struct site_plan *sp = &plan->sites[s];
                if (!sp->available) continue;
                if (sp->site_id == PKT_SITE_KP_FIFO_ENQ) has_pfifo_enq = true;
                else if (sp->site_id == PKT_SITE_KR_FIFO_ENQ) has_pfifo_ret = true;
                else if (sp->site_id == PKT_SITE_KR_FIFO_DEQ) has_fifo_deq = true;
            }
            if (has_pfifo_enq && has_pfifo_ret && has_fifo_deq) {
                plan->adapters[a].enabled = true;
                snprintf(plan->adapters[a].missing_reason, sizeof(plan->adapters[a].missing_reason),
                         "partial (%d/%d; %s)", avail_cnt, desired_cnt,
                         first_err ? first_err : "variant absent");
            } else {
                plan->adapters[a].enabled = false;
                snprintf(plan->adapters[a].missing_reason, sizeof(plan->adapters[a].missing_reason),
                         "%s", first_err ? first_err : "pfifo/qdisc_dequeue_head absent");
            }
        } else if (avail_cnt > 0 && (a == ADAPT_L1_SOCK_BASE ||
                                     a == ADAPT_L2_TRANSFORMS ||
                                     a == ADAPT_L2_QSTATE)) {
            plan->adapters[a].enabled = true;
            snprintf(plan->adapters[a].missing_reason, sizeof(plan->adapters[a].missing_reason),
                     "partial (%d/%d; %s)", avail_cnt, desired_cnt,
                     first_err ? first_err : "helper inlined");
        } else {
            if (plan->adapters[a].required && !opts->allow_partial) {
                if (err_buf && err_cap)
                    snprintf(err_buf, err_cap, "required adapter '%s' unavailable: %s",
                             plan->adapters[a].adapter_id, first_err ? first_err : "missing probe");
                return -1;
            }
            plan->adapters[a].enabled = (avail_cnt > 0 && a == ADAPT_L2_CORE);
            snprintf(plan->adapters[a].missing_reason, sizeof(plan->adapters[a].missing_reason),
                     "%s", first_err ? first_err : "probe symbol absent");
            if (plan->adapters[a].required)
                plan->partial_coverage = true;
        }
    }

    return 0;
}

/* ==========================================================================
 * 5. `pktpath inspect` Implementation (Human-readable + `--json`)
 * ========================================================================== */

int run_inspect(const struct dev_cli_opts *opts) {
    int reaped = tracefs_reap_stale_groups();

    char err[256] = "";
    struct topo_mgr topo;
    if (topo_mgr_init(&topo, err, sizeof(err)) != 0) {
        fprintf(stderr, "inspect error: %s\n", err);
        return 1;
    }

    struct probe_plan plan;
    if (build_probe_plan(opts, &topo, &plan, err, sizeof(err)) != 0) {
        fprintf(stderr, "inspect error: %s\n", err);
        topo_mgr_destroy(&topo);
        return 1;
    }

    const struct topo_dev_entry *tdev = topo_find_dev_by_ifindex(&topo, plan.target_ifindex);
    uint32_t max_active = opts->profile_sendmsg ? PKT_SENDMSG_MAX_ACTIVE : PKT_DEFAULT_MAX_ACTIVE;
    uint64_t est_bpf_mem = (uint64_t)PKT_DEFAULT_RINGBUF_SZ +
                           2ULL * max_active * sizeof(struct bpf_active_val) +
                           (uint64_t)PKT_DEFAULT_MAX_SOCKS * sizeof(struct bpf_sock_owner) +
                           (uint64_t)PKT_DEFAULT_MAX_CALLS * sizeof(struct bpf_call_val);

    if (opts->json_output) {
        FILE *fp = stdout;
        fprintf(fp, "{\n");
        fprintf(fp, "  \"schema_version\": \"1.0\",\n");
        fprintf(fp, "  \"kernel_release\": "); json_write_escaped(fp, plan.uts.release); fprintf(fp, ",\n");
        fprintf(fp, "  \"arch\": "); json_write_escaped(fp, plan.uts.machine); fprintf(fp, ",\n");
        fprintf(fp, "  \"boot_id\": "); json_write_escaped(fp, plan.boot_id); fprintf(fp, ",\n");
        fprintf(fp, "  \"scope\": "); json_write_escaped(fp, scope_to_str(opts->scope)); fprintf(fp, ",\n");
        fprintf(fp, "  \"dev\": "); json_write_escaped(fp, opts->dev_name); fprintf(fp, ",\n");
        fprintf(fp, "  \"ifindex\": %u,\n", tdev ? tdev->ifindex : 0U);
        fprintf(fp, "  \"linktype\": %u,\n", tdev ? tdev->linktype : 1U);
        fprintf(fp, "  \"netns_inum\": %u,\n", topo.netns_inum);
        fprintf(fp, "  \"reaped_stale_groups\": %d,\n", reaped);
        fprintf(fp, "  \"partial_coverage\": %s,\n", plan.partial_coverage ? "true" : "false");
        fprintf(fp, "  \"budgets\": {\n");
        fprintf(fp, "    \"estimated_bpf_bytes\": %llu,\n", (unsigned long long)est_bpf_mem);
        fprintf(fp, "    \"mem_budget_bytes\": %llu,\n", (unsigned long long)opts->mem_budget_bytes);
        fprintf(fp, "    \"disk_budget_bytes\": %llu\n", (unsigned long long)opts->disk_budget_bytes);
        fprintf(fp, "  },\n");
        fprintf(fp, "  \"btf_offsets\": {\n");
        fprintf(fp, "    \"sk_buff.dev\": %u,\n", plan.btf.skb_dev);
        fprintf(fp, "    \"sk_buff.sk\": %u,\n", plan.btf.skb_sk);
        fprintf(fp, "    \"sk_buff.len\": %u,\n", plan.btf.skb_len);
        fprintf(fp, "    \"sk_buff.data_len\": %u,\n", plan.btf.skb_data_len);
        fprintf(fp, "    \"sk_buff.head\": %u,\n", plan.btf.skb_head);
        fprintf(fp, "    \"sk_buff.data\": %u,\n", plan.btf.skb_data);
        fprintf(fp, "    \"net_device.ifindex\": %u,\n", plan.btf.dev_ifindex);
        fprintf(fp, "    \"net_device.nd_net\": %u,\n", plan.btf.dev_nd_net);
        fprintf(fp, "    \"net.ns.inum\": %u,\n", plan.btf.net_ns_inum);
        fprintf(fp, "    \"sock.skc_state\": %u,\n", plan.btf.sk_state);
        fprintf(fp, "    \"sock.skc_cookie\": %u,\n", plan.btf.sk_cookie);
        fprintf(fp, "    \"sock.sk_uid\": %u,\n", plan.btf.sk_uid);
        fprintf(fp, "    \"socket.sk\": %u,\n", plan.btf.socket_sk);
        fprintf(fp, "    \"Qdisc.handle\": %u,\n", plan.btf.qdisc_handle);
        fprintf(fp, "    \"Qdisc.parent\": %u,\n", plan.btf.qdisc_parent);
        fprintf(fp, "    \"task_struct.preempt_count\": %u,\n", plan.btf.task_preempt_count);
        fprintf(fp, "    \"tp_kfree_skb.reason\": %u,\n", plan.btf.tp_kfree_skb_reason);
        fprintf(fp, "    \"tcf_result.classid\": %u\n", plan.btf.tcf_res_classid);
        fprintf(fp, "  },\n");
        fprintf(fp, "  \"qdiscs\": [\n");
        bool first_q = true;
        for (uint32_t i = 0; i < topo.num_qdiscs; i++) {
            const struct topo_qdisc_entry *q = &topo.qdiscs[i];
            if (!q->present) continue;
            if (plan.target_ifindex != 0 && q->ifindex != plan.target_ifindex) continue;
            if (!first_q) fprintf(fp, ",\n");
            first_q = false;
            fprintf(fp, "    {\"kind\": "); json_write_escaped(fp, q->kind);
            fprintf(fp, ", \"handle\": %u, \"parent\": %u, \"queue_gen\": %llu, "
                        "\"bytes\": %llu, \"packets\": %u, \"drops\": %u, \"overlimits\": %u}",
                    q->handle, q->parent, (unsigned long long)q->queue_gen,
                    (unsigned long long)q->bytes, q->packets, q->drops, q->overlimits);
        }
        fprintf(fp, "\n  ],\n");
        fprintf(fp, "  \"classes\": [\n");
        bool first_c = true;
        for (uint32_t i = 0; i < topo.num_classes; i++) {
            const struct topo_class_entry *c = &topo.classes[i];
            if (!c->present) continue;
            if (plan.target_ifindex != 0 && c->ifindex != plan.target_ifindex) continue;
            if (!first_c) fprintf(fp, ",\n");
            first_c = false;
            fprintf(fp, "    {\"kind\": "); json_write_escaped(fp, c->kind);
            fprintf(fp, ", \"handle\": %u, \"parent\": %u, \"leaf\": %u, "
                        "\"prio\": %u, \"quantum\": %u, \"rate_bps\": %llu, \"ceil_bps\": %llu, "
                        "\"bytes\": %llu, \"packets\": %u, \"drops\": %u, \"overlimits\": %u}",
                    c->handle, c->parent, c->leaf, c->prio, c->quantum,
                    (unsigned long long)c->rate_bps, (unsigned long long)c->ceil_bps,
                    (unsigned long long)c->bytes, c->packets, c->drops, c->overlimits);
        }
        fprintf(fp, "\n  ],\n");
        fprintf(fp, "  \"adapters\": [\n");
        for (int i = 0; i < plan.num_adapters; i++) {
            const struct adapter_plan *ad = &plan.adapters[i];
            fprintf(fp, "    {\"adapter_id\": "); json_write_escaped(fp, ad->adapter_id);
            fprintf(fp, ", \"name\": "); json_write_escaped(fp, ad->name);
            fprintf(fp, ", \"version\": \"1.0\", \"plugin\": %s, \"enabled\": %s, \"missing_reason\": ",
                    ad->is_plugin ? "true" : "false",
                    ad->enabled ? "true" : "false");
            json_write_escaped(fp, ad->missing_reason);
            fprintf(fp, ", \"missed_source\": "); json_write_escaped(fp, ad->missed_source);
            fprintf(fp, "}%s\n", (i + 1 < plan.num_adapters) ? "," : "");
        }
        fprintf(fp, "  ],\n");
        fprintf(fp, "  \"plugins\": [\n");
        for (int i = 0; i < plan.plugins.num_plugins; i++) {
            fprintf(fp, "    {\"id\": "); json_write_escaped(fp, plan.plugins.plugin_ids[i]);
            fprintf(fp, ", \"name\": "); json_write_escaped(fp, plan.plugins.plugin_names[i]);
            fprintf(fp, "}%s\n", (i + 1 < plan.plugins.num_plugins) ? "," : "");
        }
        fprintf(fp, "  ],\n");
        fprintf(fp, "  \"plugin_fields\": [\n");
        for (int i = 0; i < plan.plugins.num_sock_fields; i++) {
            const struct dev_plugin_sock_field *sf = &plan.plugins.sock_fields[i];
            fprintf(fp, "    {\"slot\": %d, \"plugin_id\": ", i);
            json_write_escaped(fp, sf->plugin_id);
            fprintf(fp, ", \"struct\": "); json_write_escaped(fp, sf->struct_name);
            fprintf(fp, ", \"field\": "); json_write_escaped(fp, sf->field_path);
            fprintf(fp, ", \"label\": "); json_write_escaped(fp, sf->label);
            fprintf(fp, ", \"size\": %u, \"role\": %s, \"offset\": %u, \"resolved\": %s}%s\n",
                    sf->size,
                    sf->role == PKT_SOCK_PLUG_TGID_FALLBACK ? "\"tgid_fallback\"" : "\"tag\"",
                    sf->resolved_offset, sf->resolved ? "true" : "false",
                    (i + 1 < plan.plugins.num_sock_fields) ? "," : "");
        }
        fprintf(fp, "  ]\n}\n");
    } else {
        printf("pktpath inspect (v3 / wire 1.0)\n");
        printf("  Kernel       : %s (%s)\n", plan.uts.release, plan.uts.machine);
        printf("  Boot ID      : %s\n", plan.boot_id);
        printf("  Target Dev   : %s (ifindex=%u, dev_gen=%u, linktype=%u, netns=%u)\n",
               opts->dev_name, tdev ? tdev->ifindex : 0U,
               tdev ? tdev->dev_gen : 0U, tdev ? tdev->linktype : 1U, topo.netns_inum);
        printf("  Scope        : %s (partial_coverage=%s)\n",
               scope_to_str(opts->scope), plan.partial_coverage ? "true" : "false");
        if (reaped > 0)
            printf("  Cleanup      : reaped %d stale tracefs kprobe entry/group(s)\n", reaped);
        printf("  BTF Offsets  : sk_buff.dev=%u sk_buff.sk=%u sk_buff.len=%u sk_buff.data=%u\n",
               plan.btf.skb_dev, plan.btf.skb_sk, plan.btf.skb_len, plan.btf.skb_data);
        printf("                 net_device.ifindex=%u net_device.nd_net=%u net.ns.inum=%u\n",
               plan.btf.dev_ifindex, plan.btf.dev_nd_net, plan.btf.net_ns_inum);
        printf("                 sock.skc_state=%u sock.skc_cookie=%u sock.sk_uid=%u socket.sk=%u\n",
               plan.btf.sk_state, plan.btf.sk_cookie, plan.btf.sk_uid, plan.btf.socket_sk);
        printf("                 Qdisc.handle=%u Qdisc.parent=%u task.preempt_count=%u kfree.reason=%u tcf.classid=%u\n",
               plan.btf.qdisc_handle, plan.btf.qdisc_parent,
               plan.btf.task_preempt_count, plan.btf.tp_kfree_skb_reason,
               plan.btf.tcf_res_classid);
        printf("  TC Topology  :\n");
        int qcnt = 0;
        for (uint32_t i = 0; i < topo.num_qdiscs; i++) {
            const struct topo_qdisc_entry *q = &topo.qdiscs[i];
            if (!q->present) continue;
            if (plan.target_ifindex != 0 && q->ifindex != plan.target_ifindex) continue;
            printf("    - qdisc %-12s handle=%x:%x parent=%x:%x (queue_gen=%llu pkts=%u drops=%u)\n",
                   q->kind, q->handle >> 16, q->handle & 0xFFFFU,
                   q->parent >> 16, q->parent & 0xFFFFU,
                   (unsigned long long)q->queue_gen, q->packets, q->drops);
            qcnt++;
        }
        if (qcnt == 0) printf("    - (no qdiscs reported on %s)\n", opts->dev_name);
        int ccnt = 0;
        for (uint32_t i = 0; i < topo.num_classes; i++) {
            const struct topo_class_entry *c = &topo.classes[i];
            if (!c->present) continue;
            if (plan.target_ifindex != 0 && c->ifindex != plan.target_ifindex) continue;
            printf("    - class %-12s handle=%x:%x parent=%x:%x leaf=%x:%x prio=%u rate_bps=%llu ceil_bps=%llu pkts=%u drops=%u\n",
                   c->kind, c->handle >> 16, c->handle & 0xFFFFU,
                   c->parent >> 16, c->parent & 0xFFFFU,
                   c->leaf >> 16, c->leaf & 0xFFFFU,
                   c->prio, (unsigned long long)c->rate_bps, (unsigned long long)c->ceil_bps,
                   c->packets, c->drops);
            ccnt++;
        }
        (void)ccnt;
        printf("  Adapters     :\n");
        for (int i = 0; i < plan.num_adapters; i++) {
            const struct adapter_plan *ad = &plan.adapters[i];
            printf("    - %-22s [%s] missed_src=%s%s%s\n",
                   ad->adapter_id, ad->enabled ? "ENABLED " : "DISABLED",
                   ad->missed_source,
                   ad->missing_reason[0] ? " reason=" : "",
                   ad->missing_reason);
        }
        printf("  Budgets      : est_bpf=%.2f MiB, mem_budget=%.2f MiB, disk_budget=%.2f MiB\n",
               (double)est_bpf_mem / (1024.0 * 1024.0),
               (double)opts->mem_budget_bytes / (1024.0 * 1024.0),
               (double)opts->disk_budget_bytes / (1024.0 * 1024.0));
    }

    topo_mgr_destroy(&topo);
    return 0;
}

/* ==========================================================================
 * 6. Recorder Session State, Block Writer, Daemon Ring & TLV Transcoder
 * ========================================================================== */

#define REC_BLOCK_PAY_CAP   65536U
#define OPEN_VISIT_SLOTS    16384U
#define DROP_WIN_CAP        512U

struct open_visit_slot {
    uint64_t object_id;
    uint64_t visit_id;
    uint64_t queue_gen;
    uint64_t entry_ts_ns;
    uint32_t ifindex;
    uint32_t dev_gen;
    uint32_t qdisc_handle;
    uint32_t qdisc_parent;
    uint32_t classid;
};

struct mem_ring_block {
    struct pkt_block_hdr_v1 hdr;
    uint8_t                 payload[REC_BLOCK_PAY_CAP];
    uint32_t                crc32;
    bool                    valid;
};

struct recorder_ctx {
    const struct dev_cli_opts *opts;
    struct topo_mgr            topo;
    struct probe_plan          plan;
    char                       kp_group[64];

    /* Session identity & clocks */
    uint8_t                    session_uuid[16];
    char                       session_uuid_str[37];
    uint32_t                   num_calibrations;
    struct clock_calibration   calibrations[DEV_MAX_CALIBRATIONS];

    /* BPF map FDs */
    int                        slot_fds[PKT_ACTIVE_SLOTS_CNT];
    int                        map_fds[PKT_MAP_COUNT];
    uint32_t                   max_active_entries;
    size_t                     rb_sz;
    size_t                     rb_page_sz;
    size_t                     rb_mask;
    void                      *rb_cons_map;
    void                      *rb_prod_map;
    unsigned long             *rb_cons_pos;
    unsigned long             *rb_prod_pos;
    const uint8_t             *rb_data;

    /* Optional mmap'd control map for race-free atomic field updates */
    struct bpf_ctrl_cfg       *ctrl_shm;
    size_t                     ctrl_shm_sz;

    /* Epoch & A/B rotation state */
    uint32_t                   cur_epoch;
    uint32_t                   cur_slot;
    bool                       slot_draining;
    uint64_t                   drain_started_ns;
    uint64_t                   last_epoch_rot_ns;

    /* Periodic loss tracking */
    uint64_t                   last_health_ts_ns;
    uint64_t                   last_rb_drops;
    uint64_t                   ctrl_seq;

    /* Open queue visit cache for (object_id, visit_id) -> queue_gen */
    struct open_visit_slot    *visit_cache;

    /* Block buffering (oneshot + daemon) */
    uint8_t                    cur_payload[REC_BLOCK_PAY_CAP];
    uint32_t                   cur_pay_len;
    uint64_t                   cur_min_ts_ns;
    uint64_t                   cur_max_ts_ns;
    uint32_t                   next_block_no;
    uint64_t                   disk_bytes_used;
    bool                       disk_budget_hit;
    bool                       disk_enospc;
    int                        enospc_errno;

    /* Daemon memory ring & triggers */
    uint32_t                   ring_cap;
    uint64_t                   ring_write_seq;
    uint64_t                   evicted_blocks;
    uint64_t                   evicted_first_ts_ns;
    uint64_t                   evicted_last_ts_ns;
    struct mem_ring_block     *mem_ring;
    bool                       trigger_armed;
    uint64_t                   trigger_ts_ns;
    uint64_t                   flush_deadline_ns;
    uint32_t                   flush_count;
    uint64_t                   drop_ts_ring[DROP_WIN_CAP];
    uint32_t                   drop_ts_head;
};

static inline void tlv_put(uint8_t *dst, uint32_t *off, uint16_t tag,
                           const void *val, uint16_t len) {
    memcpy(dst + *off, &tag, 2);
    *off += 2;
    memcpy(dst + *off, &len, 2);
    *off += 2;
    if (len > 0) {
        memcpy(dst + *off, val, len);
        *off += len;
    }
}

static inline void tlv_put_u8(uint8_t *d, uint32_t *o, uint16_t tag, uint8_t v) {
    tlv_put(d, o, tag, &v, 1);
}
static inline void tlv_put_u16(uint8_t *d, uint32_t *o, uint16_t tag, uint16_t v) {
    tlv_put(d, o, tag, &v, 2);
}
static inline void tlv_put_u32(uint8_t *d, uint32_t *o, uint16_t tag, uint32_t v) {
    tlv_put(d, o, tag, &v, 4);
}
static inline void tlv_put_s32(uint8_t *d, uint32_t *o, uint16_t tag, int32_t v) {
    tlv_put(d, o, tag, &v, 4);
}
static inline void tlv_put_u64(uint8_t *d, uint32_t *o, uint16_t tag, uint64_t v) {
    tlv_put(d, o, tag, &v, 8);
}

static int write_atomic_block_file(struct recorder_ctx *rec,
                                   uint16_t block_type,
                                   uint16_t producer_type,
                                   uint32_t epoch,
                                   uint64_t min_ts,
                                   uint64_t max_ts,
                                   const uint8_t *payload,
                                   uint32_t payload_len) {
    uint64_t total_sz = sizeof(struct pkt_block_hdr_v1) + (uint64_t)payload_len + 4ULL;
    if (rec->opts->disk_budget_bytes > 0 &&
        rec->disk_bytes_used + total_sz > rec->opts->disk_budget_bytes) {
        rec->disk_budget_hit = true;
        return -2;
    }

    uint32_t bno = ++rec->next_block_no;
    struct pkt_block_hdr_v1 hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic         = PKTPATH_WIRE_MAGIC;
    hdr.major         = PKTPATH_WIRE_MAJOR;
    hdr.minor         = PKTPATH_WIRE_MINOR;
    hdr.block_type    = block_type;
    hdr.producer_type = producer_type;
    hdr.flags         = 0;
    hdr.payload_len   = payload_len;
    hdr.epoch         = epoch;
    hdr.block_no      = bno;
    hdr.reserved      = 0;
    memcpy(hdr.session_uuid, rec->session_uuid, 16);
    hdr.min_ts_ns     = min_ts;
    hdr.max_ts_ns     = max_ts;

    uint32_t crc = crc32_update(0, &hdr, sizeof(hdr));
    if (payload_len > 0 && payload)
        crc = crc32_update(crc, payload, payload_len);

    char tmp_path[600], final_path[600];
    snprintf(tmp_path, sizeof(tmp_path), "%s/block_%06u.pktb.tmp", rec->opts->out_dir, bno);
    snprintf(final_path, sizeof(final_path), "%s/block_%06u.pktb", rec->opts->out_dir, bno);

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        rec->disk_enospc = true;
        rec->enospc_errno = errno;
        rec->next_block_no--;
        return -1;
    }

    if (write_all_fd(fd, &hdr, sizeof(hdr)) < 0 ||
        (payload_len > 0 && write_all_fd(fd, payload, payload_len) < 0) ||
        write_all_fd(fd, &crc, sizeof(crc)) < 0) {
        int saved = errno;
        close(fd);
        (void)unlink(tmp_path);
        rec->disk_enospc = true;
        rec->enospc_errno = saved;
        rec->next_block_no--;
        return -1;
    }

    if (close(fd) < 0) {
        int saved = errno;
        (void)unlink(tmp_path);
        rec->disk_enospc = true;
        rec->enospc_errno = saved;
        rec->next_block_no--;
        return -1;
    }

    if (rename(tmp_path, final_path) < 0) {
        int saved = errno;
        (void)unlink(tmp_path);
        rec->disk_enospc = true;
        rec->enospc_errno = saved;
        rec->next_block_no--;
        return -1;
    }

    rec->disk_bytes_used += total_sz;
    return 0;
}

static void seal_current_batch(struct recorder_ctx *rec) {
    if (rec->cur_pay_len == 0) return;

    if (rec->opts->mode == MODE_ONESHOT) {
        (void)write_atomic_block_file(rec, PKT_BLOCK_EVENT_BATCH, PKT_PROD_KERNEL_BPF,
                                      rec->cur_epoch, rec->cur_min_ts_ns, rec->cur_max_ts_ns,
                                      rec->cur_payload, rec->cur_pay_len);
    } else if (rec->mem_ring && rec->ring_cap > 0) {
        uint32_t idx = (uint32_t)(rec->ring_write_seq % rec->ring_cap);
        struct mem_ring_block *mb = &rec->mem_ring[idx];
        if (mb->valid) {
            if (rec->evicted_blocks == 0)
                rec->evicted_first_ts_ns = mb->hdr.min_ts_ns;
            rec->evicted_last_ts_ns = mb->hdr.max_ts_ns;
            rec->evicted_blocks++;
        }
        memset(&mb->hdr, 0, sizeof(mb->hdr));
        mb->hdr.magic         = PKTPATH_WIRE_MAGIC;
        mb->hdr.major         = PKTPATH_WIRE_MAJOR;
        mb->hdr.minor         = PKTPATH_WIRE_MINOR;
        mb->hdr.block_type    = PKT_BLOCK_EVENT_BATCH;
        mb->hdr.producer_type = PKT_PROD_KERNEL_BPF;
        mb->hdr.flags         = 0;
        mb->hdr.payload_len   = rec->cur_pay_len;
        mb->hdr.epoch         = rec->cur_epoch;
        mb->hdr.block_no      = (uint32_t)(rec->ring_write_seq + 1ULL);
        memcpy(mb->hdr.session_uuid, rec->session_uuid, 16);
        mb->hdr.min_ts_ns     = rec->cur_min_ts_ns;
        mb->hdr.max_ts_ns     = rec->cur_max_ts_ns;
        memcpy(mb->payload, rec->cur_payload, rec->cur_pay_len);
        uint32_t crc = crc32_update(0, &mb->hdr, sizeof(mb->hdr));
        crc = crc32_update(crc, mb->payload, rec->cur_pay_len);
        mb->crc32 = crc;
        mb->valid = true;
        rec->ring_write_seq++;
    }

    rec->cur_pay_len = 0;
    rec->cur_min_ts_ns = 0;
    rec->cur_max_ts_ns = 0;
}

static void append_wire_event(struct recorder_ctx *rec, const uint8_t *ev_buf,
                              uint32_t ev_len, uint64_t ts_ns) {
    if (rec->disk_enospc || (rec->opts->mode == MODE_ONESHOT && rec->disk_budget_hit))
        return;
    if (ev_len > REC_BLOCK_PAY_CAP)
        return;
    if (rec->cur_pay_len + ev_len > REC_BLOCK_PAY_CAP) {
        seal_current_batch(rec);
        if (rec->disk_enospc || (rec->opts->mode == MODE_ONESHOT && rec->disk_budget_hit))
            return;
    }
    memcpy(rec->cur_payload + rec->cur_pay_len, ev_buf, ev_len);
    rec->cur_pay_len += ev_len;
    if (ts_ns > 0) {
        if (rec->cur_min_ts_ns == 0 || ts_ns < rec->cur_min_ts_ns)
            rec->cur_min_ts_ns = ts_ns;
        if (ts_ns > rec->cur_max_ts_ns)
            rec->cur_max_ts_ns = ts_ns;
    }
}

static uint32_t build_ctrl_quality_event(struct recorder_ctx *rec, uint8_t qual_kind,
                                         uint16_t site_idx, uint64_t win_start,
                                         uint64_t win_end, uint64_t count,
                                         uint8_t *dst) {
    struct pkt_event_hdr_v1 eh;
    memset(&eh, 0, sizeof(eh));
    eh.kind           = PKT_EV_QUALITY;
    eh.object_type    = PKT_OBJ_SKB;
    eh.evidence_level = PKT_EVIDENCE_DIRECT;
    eh.site_dict_idx  = site_idx;
    eh.cpu            = PKTPATH_USERSPACE_CPU;
    eh.flags          = rec->plan.partial_coverage ? PKT_EV_F_PARTIAL_COVERAGE : 0U;
    eh.seq            = ++rec->ctrl_seq;
    eh.ts_ns          = win_end;
    eh.object_id      = 0;

    uint32_t off = sizeof(eh);
    tlv_put_u8(dst,  &off, PKT_TLV_QUAL_KIND, qual_kind);
    tlv_put_u16(dst, &off, PKT_TLV_QUAL_SITE_DICT_IDX, site_idx);
    tlv_put_u64(dst, &off, PKT_TLV_QUAL_WIN_START_NS, win_start);
    tlv_put_u64(dst, &off, PKT_TLV_QUAL_WIN_END_NS, win_end);
    tlv_put_u64(dst, &off, PKT_TLV_QUAL_COUNT, count);
    eh.total_len = (uint16_t)off;
    memcpy(dst, &eh, sizeof(eh));
    return off;
}

static uint32_t build_ctrl_truncated_obj_event(struct recorder_ctx *rec,
                                               uint64_t object_id, uint64_t sample_id,
                                               uint64_t ts_ns, uint8_t *dst) {
    struct pkt_event_hdr_v1 eh;
    memset(&eh, 0, sizeof(eh));
    eh.kind           = PKT_EV_OBJECT;
    eh.object_type    = PKT_OBJ_SKB;
    eh.evidence_level = PKT_EVIDENCE_DIRECT;
    eh.site_dict_idx  = 0;
    eh.cpu            = PKTPATH_USERSPACE_CPU;
    eh.flags          = rec->plan.partial_coverage ? PKT_EV_F_PARTIAL_COVERAGE : 0U;
    eh.seq            = ++rec->ctrl_seq;
    eh.ts_ns          = ts_ns;
    eh.object_id      = object_id;

    uint32_t off = sizeof(eh);
    tlv_put_u64(dst, &off, PKT_TLV_OBJ_SAMPLE_ID, sample_id ? sample_id : object_id);
    tlv_put_u16(dst, &off, PKT_TLV_OBJ_END_REASON, PKT_END_TIMEOUT_TRUNCATED);
    eh.total_len = (uint16_t)off;
    memcpy(dst, &eh, sizeof(eh));
    return off;
}

static void arm_daemon_trigger(struct recorder_ctx *rec, uint64_t ts_ns) {
    if (rec->opts->mode != MODE_DAEMON || rec->trigger_armed)
        return;
    rec->trigger_armed = true;
    rec->trigger_ts_ns = ts_ns ? ts_ns : now_boottime_ns();
    rec->flush_deadline_ns = rec->trigger_ts_ns +
                             (uint64_t)rec->opts->post_window_sec * 1000000000ULL;
}

static void note_drop_for_trigger(struct recorder_ctx *rec, uint64_t ts_ns) {
    if (rec->opts->mode != MODE_DAEMON || rec->opts->trigger_drop_burst == 0)
        return;
    rec->drop_ts_ring[rec->drop_ts_head % DROP_WIN_CAP] = ts_ns;
    rec->drop_ts_head++;

    /* Count drops within trailing 1 second window */
    uint64_t cutoff = (ts_ns > 1000000000ULL) ? (ts_ns - 1000000000ULL) : 0ULL;
    uint32_t n = rec->drop_ts_head < DROP_WIN_CAP ? rec->drop_ts_head : DROP_WIN_CAP;
    uint32_t burst = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t t = rec->drop_ts_ring[(rec->drop_ts_head - 1U - i) % DROP_WIN_CAP];
        if (t >= cutoff) burst++;
        else break;
    }
    if (burst > rec->opts->trigger_drop_burst)
        arm_daemon_trigger(rec, ts_ns);
}

static struct open_visit_slot *visit_cache_slot(struct recorder_ctx *rec,
                                                uint64_t object_id, uint64_t visit_id) {
    if (!rec->visit_cache || object_id == 0 || visit_id == 0) return NULL;
    uint64_t h = (object_id * 11400714819323198485ULL) ^ (visit_id * 14029467366897019727ULL);
    return &rec->visit_cache[(h >> 32) & (OPEN_VISIT_SLOTS - 1U)];
}

static void transcode_bpf_record(struct recorder_ctx *rec, const uint8_t *raw, uint32_t raw_len) {
    if (raw_len < sizeof(struct bpf_ev_common))
        return;
    const struct bpf_ev_common *h = (const struct bpf_ev_common *)raw;

    uint8_t out[1024];
    struct pkt_event_hdr_v1 eh;
    memset(&eh, 0, sizeof(eh));
    eh.kind           = h->kind;
    eh.object_type    = h->object_type;
    eh.evidence_level = h->evidence_level;
    eh.site_dict_idx  = h->site_dict_idx;
    eh.cpu            = h->cpu;
    eh.flags          = (uint32_t)h->flags |
                        (rec->plan.partial_coverage ? PKT_EV_F_PARTIAL_COVERAGE : 0U);
    eh.seq            = h->seq;
    eh.ts_ns          = h->ts_ns;

    uint32_t off = sizeof(eh);

    switch (h->kind) {
    case PKT_EV_OBJECT: {
        if (raw_len < sizeof(struct bpf_ev_object)) return;
        const struct bpf_ev_object *ob = (const struct bpf_ev_object *)raw;
        eh.object_id = ob->object_id;
        tlv_put_u64(out, &off, PKT_TLV_OBJ_SAMPLE_ID, ob->sample_id ? ob->sample_id : ob->object_id);
        tlv_put_u16(out, &off, PKT_TLV_OBJ_END_REASON, ob->end_reason);
        if (ob->end_reason == PKT_END_DROP || ob->drop_reason != 0)
            tlv_put_u32(out, &off, PKT_TLV_OBJ_DROP_REASON, ob->drop_reason);
        if (ob->end_reason == PKT_END_DROP)
            note_drop_for_trigger(rec, h->ts_ns);
        break;
    }

    case PKT_EV_STEP: {
        if (raw_len < sizeof(struct bpf_ev_step)) return;
        const struct bpf_ev_step *st = (const struct bpf_ev_step *)raw;
        eh.object_id = st->object_id;

        uint32_t netns = st->netns_inum ? st->netns_inum : rec->topo.netns_inum;
        uint32_t ifidx = st->ifindex;
        uint32_t qh    = st->qdisc_handle;
        uint32_t qp    = st->qdisc_parent;
        uint32_t cls   = st->classid;
        uint64_t qgen  = 0;
        uint32_t dgen  = 0;

        if (ifidx != 0) {
            const struct topo_dev_entry *td = topo_find_dev_by_ifindex(&rec->topo, ifidx);
            dgen = td ? td->dev_gen : 1U;
        }

        if (st->stage == PKT_STAGE_XMIT_START || st->stage == PKT_STAGE_XMIT_RET) {
            if (st->visit_or_call_id != 0)
                tlv_put_u64(out, &off, PKT_TLV_STEP_CALL_ID, st->visit_or_call_id);
        } else if (st->visit_or_call_id != 0) {
            uint64_t vid = st->visit_or_call_id;
            tlv_put_u64(out, &off, PKT_TLV_STEP_VISIT_ID, vid);

            struct open_visit_slot *vs = visit_cache_slot(rec, st->object_id, vid);
            if (st->stage == PKT_STAGE_QDISC_ENQ) {
                qgen = topo_ensure_queue_gen(&rec->topo, ifidx, qh, qp,
                                             site_qdisc_kind(&rec->plan, h->site_dict_idx));
                if (vs) {
                    vs->object_id    = st->object_id;
                    vs->visit_id     = vid;
                    vs->queue_gen    = qgen;
                    vs->entry_ts_ns  = h->ts_ns;
                    vs->ifindex      = ifidx;
                    vs->dev_gen      = dgen;
                    vs->qdisc_handle = qh;
                    vs->qdisc_parent = qp;
                    vs->classid      = cls;
                }
            } else if (st->stage == PKT_STAGE_REQUEUE_GSO ||
                       st->stage == PKT_STAGE_REQUEUE_BAD_TXQ) {
                qgen = 0x8000000000000000ULL | ((uint64_t)(dgen ? dgen : 1U) << 8) | st->stage;
                if (vs) {
                    vs->object_id    = st->object_id;
                    vs->visit_id     = vid;
                    vs->queue_gen    = qgen;
                    vs->entry_ts_ns  = h->ts_ns;
                    vs->ifindex      = ifidx;
                    vs->dev_gen      = dgen;
                    vs->qdisc_handle = qh;
                    vs->qdisc_parent = qp;
                    vs->classid      = cls;
                }
            } else if (vs && vs->object_id == st->object_id && vs->visit_id == vid) {
                qgen = vs->queue_gen;
                if (ifidx == 0) {
                    ifidx = vs->ifindex;
                    dgen  = vs->dev_gen;
                }
                if (qh == 0 && qp == 0) {
                    qh = vs->qdisc_handle;
                    qp = vs->qdisc_parent;
                }
                if (cls == 0)
                    cls = vs->classid;
                if (st->stage == PKT_STAGE_QDISC_DEQ) {
                    if (rec->opts->trigger_sojourn_us > 0 && h->ts_ns >= vs->entry_ts_ns) {
                        uint64_t soj_us = (h->ts_ns - vs->entry_ts_ns) / 1000ULL;
                        if (soj_us > rec->opts->trigger_sojourn_us)
                            arm_daemon_trigger(rec, h->ts_ns);
                    }
                    vs->object_id = 0;
                } else if (st->stage == PKT_STAGE_DROP) {
                    vs->object_id = 0;
                }
            }
            if (qgen == 0 && (qh != 0 || qp != 0))
                qgen = topo_ensure_queue_gen(&rec->topo, ifidx, qh, qp,
                                             site_qdisc_kind(&rec->plan, h->site_dict_idx));
        } else if (qh != 0 || qp != 0) {
            qgen = topo_lookup_queue_gen(&rec->topo, ifidx, qh, qp);
        }

        if (netns != 0) tlv_put_u32(out, &off, PKT_TLV_STEP_NETNS_INUM, netns);
        if (dgen != 0)  tlv_put_u32(out, &off, PKT_TLV_STEP_DEV_GEN, dgen);
        if (ifidx != 0) tlv_put_u32(out, &off, PKT_TLV_STEP_IFINDEX, ifidx);
        tlv_put_u8(out, &off, PKT_TLV_STEP_DIR, st->dir);
        tlv_put_u8(out, &off, PKT_TLV_STEP_STAGE, st->stage);
        if (qgen != 0)  tlv_put_u64(out, &off, PKT_TLV_STEP_QUEUE_GEN, qgen);
        if (qh != 0)    tlv_put_u32(out, &off, PKT_TLV_STEP_QDISC_HANDLE, qh);
        if (qp != 0)    tlv_put_u32(out, &off, PKT_TLV_STEP_QDISC_PARENT, qp);
        if (cls != 0)   tlv_put_u32(out, &off, PKT_TLV_STEP_CLASSID, cls);
        if (st->stage == PKT_STAGE_XMIT_START || st->txq != 0)
            tlv_put_u16(out, &off, PKT_TLV_STEP_TXQ, st->txq);
        if (st->stage == PKT_STAGE_QDISC_ENQ_RET || st->stage == PKT_STAGE_XMIT_RET || st->raw_ret != 0)
            tlv_put_s32(out, &off, PKT_TLV_STEP_RAW_RET, st->raw_ret);
        if (st->stage == PKT_STAGE_ENTRY || st->stage == PKT_STAGE_XMIT_START || st->ctx_tid != 0)
            tlv_put_u32(out, &off, PKT_TLV_STEP_CTX_TID, st->ctx_tid);
        break;
    }

    case PKT_EV_RELATION: {
        if (raw_len < sizeof(struct bpf_ev_rel)) return;
        const struct bpf_ev_rel *rl = (const struct bpf_ev_rel *)raw;
        eh.object_id = rl->src_object_id;
        tlv_put_u64(out, &off, PKT_TLV_REL_OP_ID, rl->op_id);
        tlv_put_u8(out,  &off, PKT_TLV_REL_TYPE, rl->rel_type);
        tlv_put_u64(out, &off, PKT_TLV_REL_SRC_OBJECT_ID, rl->src_object_id);
        tlv_put_u64(out, &off, PKT_TLV_REL_DST_OBJECT_ID, rl->dst_object_id);
        tlv_put_u8(out,  &off, PKT_TLV_REL_FLAGS, rl->rel_flags);
        if (rl->rel_type == PKT_REL_SPAN_MAP || rl->stream_offset != 0 || rl->span_len != 0) {
            tlv_put_u64(out, &off, PKT_TLV_REL_STREAM_OFFSET, rl->stream_offset);
            tlv_put_u32(out, &off, PKT_TLV_REL_SPAN_LEN, rl->span_len);
        }
        break;
    }

    case PKT_EV_SUMMARY: {
        if (raw_len < offsetof(struct bpf_ev_summary, hdr_bytes)) return;
        const struct bpf_ev_summary *sm = (const struct bpf_ev_summary *)raw;
        eh.object_id = sm->object_id;

        tlv_put_u32(out, &off, PKT_TLV_SUM_PKT_LEN, sm->pkt_len);
        tlv_put_u32(out, &off, PKT_TLV_SUM_LINEAR_LEN, sm->linear_len);
        tlv_put_u32(out, &off, PKT_TLV_SUM_IFINDEX, sm->ifindex);
        tlv_put_u8(out,  &off, PKT_TLV_SUM_DIR, sm->dir);

        if ((sm->valid_flags & PKT_SUM_F_L3) && (sm->ip_version == 4 || sm->ip_version == 6)) {
            uint16_t iplen = (sm->ip_version == 4) ? 4U : 16U;
            tlv_put_u8(out, &off, PKT_TLV_SUM_IP_VERSION, sm->ip_version);
            tlv_put_u8(out, &off, PKT_TLV_SUM_L4_PROTO, sm->l4_proto);
            tlv_put(out, &off, PKT_TLV_SUM_SRC_IP, sm->src_ip, iplen);
            tlv_put(out, &off, PKT_TLV_SUM_DST_IP, sm->dst_ip, iplen);
            if (sm->ip_version == 4)
                tlv_put_u16(out, &off, PKT_TLV_SUM_IP_ID, sm->ip_id);
            tlv_put_u8(out, &off, PKT_TLV_SUM_FRAG_FLAGS, sm->frag_flags);
        }
        if (sm->valid_flags & PKT_SUM_F_L4) {
            tlv_put_u16(out, &off, PKT_TLV_SUM_SRC_PORT, sm->src_port);
            tlv_put_u16(out, &off, PKT_TLV_SUM_DST_PORT, sm->dst_port);
        }
        if (sm->valid_flags & PKT_SUM_F_TCP) {
            tlv_put_u32(out, &off, PKT_TLV_SUM_TCP_SEQ, sm->tcp_seq);
            tlv_put_u32(out, &off, PKT_TLV_SUM_TCP_SEQ_END, sm->tcp_seq_end);
            tlv_put_u8(out,  &off, PKT_TLV_SUM_TCP_FLAGS, sm->tcp_flags);
        }

        tlv_put_u32(out, &off, PKT_TLV_SUM_SKB_HASH, sm->skb_hash);
        tlv_put_u32(out, &off, PKT_TLV_SUM_SKB_MARK, sm->skb_mark);
        tlv_put_u32(out, &off, PKT_TLV_SUM_SKB_PRIORITY, sm->skb_priority);

        bool emitted_tgid = false;
        if (sm->valid_flags & PKT_SUM_F_UID)
            tlv_put_u32(out, &off, PKT_TLV_SUM_UID, sm->uid);
        if (sm->valid_flags & PKT_SUM_F_TGID) {
            tlv_put_u32(out, &off, PKT_TLV_SUM_TGID, sm->tgid);
            emitted_tgid = (sm->tgid != 0);
        }
        if (sm->valid_flags & PKT_SUM_F_COMM)
            tlv_put(out, &off, PKT_TLV_SUM_COMM, sm->comm, 16);

        tlv_put_u32(out, &off, PKT_TLV_SUM_ENQUEUE_TID, sm->enqueue_tid);

        if (sm->valid_flags & PKT_SUM_F_CREATE_TS)
            tlv_put_u64(out, &off, PKT_TLV_SUM_SKB_CREATE_TS, sm->skb_create_ts);
        if (sm->valid_flags & PKT_SUM_F_PLUGIN_VALS) {
            for (uint32_t pi = 0; pi < PKT_MAX_SOCK_PLUGINS; pi++) {
                if (!(sm->plugin_mask & (1U << pi)))
                    continue;
                uint8_t role = (pi < (uint32_t)rec->plan.plugins.num_sock_fields)
                                   ? rec->plan.plugins.sock_fields[pi].role
                                   : PKT_SOCK_PLUG_TAG;
                if (role == PKT_SOCK_PLUG_TGID_FALLBACK) {
                    if (!emitted_tgid && sm->plugin_vals[pi] != 0) {
                        tlv_put_u32(out, &off, PKT_TLV_SUM_TGID, (uint32_t)sm->plugin_vals[pi]);
                        emitted_tgid = true;
                    }
                } else {
                    tlv_put_u64(out, &off, (uint16_t)(PKT_TLV_SUM_PLUGIN_VAL0 + pi), sm->plugin_vals[pi]);
                }
            }
        }

        uint16_t lt = sm->linktype;
        if (lt == 0) {
            const struct topo_dev_entry *td = topo_find_dev_by_ifindex(&rec->topo, sm->ifindex);
            lt = td ? td->linktype : PKT_LINKTYPE_ETHERNET;
        }
        if ((sm->valid_flags & PKT_SUM_F_HDR_BYTES) && sm->hdr_cap_len > 0 &&
            raw_len >= offsetof(struct bpf_ev_summary, hdr_bytes) + sm->hdr_cap_len) {
            uint16_t cap = sm->hdr_cap_len <= PKT_MAX_SNAP_LEN ? sm->hdr_cap_len : PKT_MAX_SNAP_LEN;
            tlv_put(out, &off, PKT_TLV_SUM_HDR_BYTES, sm->hdr_bytes, cap);
        }
        tlv_put_u16(out, &off, PKT_TLV_SUM_LINKTYPE, lt);
        break;
    }

    case PKT_EV_QSTATE: {
        if (raw_len < sizeof(struct bpf_ev_qstate)) return;
        const struct bpf_ev_qstate *qs = (const struct bpf_ev_qstate *)raw;
        eh.object_id = 0;
        uint64_t qgen = qs->queue_gen;
        if (qgen == 0 && qs->ifindex != 0)
            qgen = topo_lookup_queue_gen(&rec->topo, qs->ifindex, 0, (uint32_t)qs->txq + 1U);
        if (qgen != 0)
            tlv_put_u64(out, &off, PKT_TLV_QS_QUEUE_GEN, qgen);
        tlv_put_u32(out, &off, PKT_TLV_QS_IFINDEX, qs->ifindex);
        tlv_put_u16(out, &off, PKT_TLV_QS_TXQ, qs->txq);
        tlv_put_u8(out,  &off, PKT_TLV_QS_STATE_OP, qs->state_op);
        tlv_put_u32(out, &off, PKT_TLV_QS_VALUE, qs->value);
        break;
    }

    case PKT_EV_QUALITY: {
        if (raw_len < sizeof(struct bpf_ev_quality)) return;
        const struct bpf_ev_quality *ql = (const struct bpf_ev_quality *)raw;
        eh.object_id = ql->object_id;
        uint16_t sidx = ql->qual_site_idx ? ql->qual_site_idx : ql->h.site_dict_idx;
        tlv_put_u8(out,  &off, PKT_TLV_QUAL_KIND, ql->qual_kind);
        tlv_put_u16(out, &off, PKT_TLV_QUAL_SITE_DICT_IDX, sidx);
        tlv_put_u64(out, &off, PKT_TLV_QUAL_WIN_START_NS, ql->win_start_ns);
        tlv_put_u64(out, &off, PKT_TLV_QUAL_WIN_END_NS, ql->win_end_ns);
        tlv_put_u64(out, &off, PKT_TLV_QUAL_COUNT, ql->count);
        break;
    }

    default:
        return;
    }

    eh.total_len = (uint16_t)off;
    memcpy(out, &eh, sizeof(eh));
    append_wire_event(rec, out, off, h->ts_ns);
}

static void drain_ringbuf(struct recorder_ctx *rec) {
    if (!rec->rb_cons_pos || !rec->rb_prod_pos) return;
    unsigned long cons = __atomic_load_n(rec->rb_cons_pos, __ATOMIC_RELAXED);
    unsigned long prod = __atomic_load_n(rec->rb_prod_pos, __ATOMIC_ACQUIRE);
    while (cons < prod) {
        const uint32_t *hdr = (const uint32_t *)(rec->rb_data + (cons & rec->rb_mask));
        uint32_t len = __atomic_load_n(hdr, __ATOMIC_ACQUIRE);
        if (len & (1U << 31)) /* BPF_RINGBUF_BUSY_BIT */
            break;
        uint32_t payload_len = len & ~0xC0000000U;
        uint32_t rec_sz = (payload_len + 8U + 7U) & ~7U;
        if (!(len & (1U << 30))) { /* not BPF_RINGBUF_DISCARD_BIT */
            transcode_bpf_record(rec, (const uint8_t *)(hdr + 2), payload_len);
        }
        cons += rec_sz;
        __atomic_store_n(rec->rb_cons_pos, cons, __ATOMIC_RELEASE);
    }
}

/* ==========================================================================
 * 7. Manifest & Dictionary JSON Writers
 * ========================================================================== */

static int read_ctrl_snapshot(struct recorder_ctx *rec, struct bpf_ctrl_cfg *out) {
    if (rec->ctrl_shm) {
        memcpy(out, rec->ctrl_shm, sizeof(*out));
        return 0;
    }
    uint32_t z = 0;
    return bpf_map_lookup(rec->map_fds[PKT_MAP_CONTROL], &z, out);
}

static int write_manifest_and_dict(struct recorder_ctx *rec) {
    struct bpf_ctrl_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    if (rec->map_fds[PKT_MAP_CONTROL] >= 0)
        (void)read_ctrl_snapshot(rec, &cfg);

    /* 1. manifest.json */
    char m_tmp[600], m_fin[600];
    snprintf(m_tmp, sizeof(m_tmp), "%s/manifest.json.tmp", rec->opts->out_dir);
    snprintf(m_fin, sizeof(m_fin), "%s/manifest.json", rec->opts->out_dir);
    FILE *fp = fopen(m_tmp, "w");
    if (!fp) return -1;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"schema_version\": \"1.0\",\n");
    fprintf(fp, "  \"session_uuid\": "); json_write_escaped(fp, rec->session_uuid_str); fprintf(fp, ",\n");
    fprintf(fp, "  \"boot_id\": "); json_write_escaped(fp, rec->plan.boot_id); fprintf(fp, ",\n");
    fprintf(fp, "  \"kernel_release\": "); json_write_escaped(fp, rec->plan.uts.release); fprintf(fp, ",\n");
    fprintf(fp, "  \"arch\": "); json_write_escaped(fp, rec->plan.uts.machine); fprintf(fp, ",\n");
    fprintf(fp, "  \"dev\": "); json_write_escaped(fp, rec->opts->dev_name); fprintf(fp, ",\n");
    fprintf(fp, "  \"scope\": "); json_write_escaped(fp, scope_to_str(rec->opts->scope)); fprintf(fp, ",\n");
    fprintf(fp, "  \"mode\": "); json_write_escaped(fp, mode_to_str(rec->opts->mode)); fprintf(fp, ",\n");
    fprintf(fp, "  \"clock_domain\": \"CLOCK_BOOTTIME\",\n");
    fprintf(fp, "  \"calibrations\": [\n");
    for (uint32_t i = 0; i < rec->num_calibrations; i++) {
        const struct clock_calibration *c = &rec->calibrations[i];
        fprintf(fp, "    {\"boottime_ns\": %llu, \"realtime_ns\": %llu, \"err_ns\": %llu}%s\n",
                (unsigned long long)c->boottime_ns,
                (unsigned long long)c->realtime_ns,
                (unsigned long long)c->err_ns,
                (i + 1 < rec->num_calibrations) ? "," : "");
    }
    fprintf(fp, "  ],\n");
    fprintf(fp, "  \"sample_rate\": "); json_write_escaped(fp, rec->opts->sample_rate_str); fprintf(fp, ",\n");
    fprintf(fp, "  \"sample_by\": "); json_write_escaped(fp, rec->opts->sample_by_flow ? "flow" : "pkt"); fprintf(fp, ",\n");
    fprintf(fp, "  \"partial_coverage\": %s,\n", rec->plan.partial_coverage ? "true" : "false");
    fprintf(fp, "  \"btf_offsets\": {\n");
    fprintf(fp, "    \"skb_dev\": %u,\n", rec->plan.btf.skb_dev);
    fprintf(fp, "    \"skb_sk\": %u,\n", rec->plan.btf.skb_sk);
    fprintf(fp, "    \"skb_len\": %u,\n", rec->plan.btf.skb_len);
    fprintf(fp, "    \"skb_data_len\": %u,\n", rec->plan.btf.skb_data_len);
    fprintf(fp, "    \"skb_head\": %u,\n", rec->plan.btf.skb_head);
    fprintf(fp, "    \"skb_data\": %u,\n", rec->plan.btf.skb_data);
    fprintf(fp, "    \"skb_network_header\": %u,\n", rec->plan.btf.skb_network_header);
    fprintf(fp, "    \"skb_transport_header\": %u,\n", rec->plan.btf.skb_transport_header);
    fprintf(fp, "    \"skb_mac_header\": %u,\n", rec->plan.btf.skb_mac_header);
    fprintf(fp, "    \"skb_protocol\": %u,\n", rec->plan.btf.skb_protocol);
    fprintf(fp, "    \"skb_pkt_type\": %u,\n", rec->plan.btf.skb_pkt_type);
    fprintf(fp, "    \"skb_hash\": %u,\n", rec->plan.btf.skb_hash);
    fprintf(fp, "    \"skb_mark\": %u,\n", rec->plan.btf.skb_mark);
    fprintf(fp, "    \"skb_priority\": %u,\n", rec->plan.btf.skb_priority);
    fprintf(fp, "    \"skb_cb\": %u,\n", rec->plan.btf.skb_cb);
    fprintf(fp, "    \"dev_ifindex\": %u,\n", rec->plan.btf.dev_ifindex);
    fprintf(fp, "    \"dev_nd_net\": %u,\n", rec->plan.btf.dev_nd_net);
    fprintf(fp, "    \"net_ns_inum\": %u,\n", rec->plan.btf.net_ns_inum);
    fprintf(fp, "    \"sk_state\": %u,\n", rec->plan.btf.sk_state);
    fprintf(fp, "    \"sk_cookie\": %u,\n", rec->plan.btf.sk_cookie);
    fprintf(fp, "    \"sk_uid\": %u,\n", rec->plan.btf.sk_uid);
    fprintf(fp, "    \"socket_sk\": %u,\n", rec->plan.btf.socket_sk);
    fprintf(fp, "    \"qdisc_handle\": %u,\n", rec->plan.btf.qdisc_handle);
    fprintf(fp, "    \"qdisc_parent\": %u,\n", rec->plan.btf.qdisc_parent);
    fprintf(fp, "    \"task_preempt_count\": %u,\n", rec->plan.btf.task_preempt_count);
    fprintf(fp, "    \"tp_kfree_skb_reason\": %u,\n", rec->plan.btf.tp_kfree_skb_reason);
    fprintf(fp, "    \"dev_tx_queues\": %u,\n", rec->plan.btf.dev_tx_queues);
    fprintf(fp, "    \"netdev_queue_sz\": %u,\n", rec->plan.btf.netdev_queue_sz);
    fprintf(fp, "    \"tcf_res_classid\": %u\n", rec->plan.btf.tcf_res_classid);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"adapters\": [\n");
    for (int i = 0; i < rec->plan.num_adapters; i++) {
        const struct adapter_plan *ad = &rec->plan.adapters[i];
        fprintf(fp, "    {\"adapter_id\": "); json_write_escaped(fp, ad->adapter_id);
        fprintf(fp, ", \"name\": "); json_write_escaped(fp, ad->name);
        fprintf(fp, ", \"version\": \"1.0\", \"plugin\": %s, \"enabled\": %s, \"missing_reason\": ",
                ad->is_plugin ? "true" : "false",
                ad->enabled ? "true" : "false");
        json_write_escaped(fp, ad->missing_reason);
        fprintf(fp, ", \"missed_source\": "); json_write_escaped(fp, ad->missed_source);
        fprintf(fp, "}%s\n", (i + 1 < rec->plan.num_adapters) ? "," : "");
    }
    fprintf(fp, "  ],\n");
    fprintf(fp, "  \"admissions\": {\n");
    fprintf(fp, "    \"filter_unknown\": %llu,\n", (unsigned long long)cfg.filter_unknown);
    fprintf(fp, "    \"matched\": %llu,\n", (unsigned long long)cfg.admission_matched);
    fprintf(fp, "    \"selected\": %llu,\n", (unsigned long long)cfg.admission_selected);
    fprintf(fp, "    \"created\": %llu,\n", (unsigned long long)cfg.admission_created);
    fprintf(fp, "    \"rejected\": %llu\n", (unsigned long long)cfg.admission_rejected);
    fprintf(fp, "  }\n}\n");

    if (fclose(fp) != 0 || rename(m_tmp, m_fin) != 0) {
        (void)unlink(m_tmp);
        return -1;
    }

    /* 2. dict.json */
    char d_tmp[600], d_fin[600];
    snprintf(d_tmp, sizeof(d_tmp), "%s/dict.json.tmp", rec->opts->out_dir);
    snprintf(d_fin, sizeof(d_fin), "%s/dict.json", rec->opts->out_dir);
    fp = fopen(d_tmp, "w");
    if (!fp) return -1;

    fprintf(fp, "{\n  \"sites\": [\n");
    for (uint32_t i = 0; i < rec->plan.num_sites; i++) {
        const struct site_plan *sp = &rec->plan.sites[i];
        const struct bpf_prog_img *im = &pkt_bpf_progs[sp->prog_idx];
        const char *ptype = (im->prog_type == PKT_BPF_PROG_TYPE_TRACEPOINT)
                                ? "tracepoint"
                                : (im->is_retprobe ? "kretprobe" : "kprobe");
        const char *aid = rec->plan.adapters[sp->adapter_idx].adapter_id;
        fprintf(fp, "    {\"site_idx\": %u, \"adapter_id\": ", sp->site_id);
        json_write_escaped(fp, aid);
        fprintf(fp, ", \"name\": "); json_write_escaped(fp, sp->site_name[0] ? sp->site_name : im->sec_name);
        fprintf(fp, ", \"symbol\": "); json_write_escaped(fp, sp->resolved_sym[0] ? sp->resolved_sym : sp->target_sym);
        fprintf(fp, ", \"qdisc_kind\": "); json_write_escaped(fp, sp->qdisc_kind);
        fprintf(fp, ", \"probe_type\": "); json_write_escaped(fp, ptype);
        fprintf(fp, ", \"probe_version\": \"1.0\", \"stage\": %u, \"evidence_level\": 1}%s\n",
                sp->stage, (i + 1 < rec->plan.num_sites) ? "," : "");
    }
    fprintf(fp, "  ],\n  \"plugin_fields\": [\n");
    for (int i = 0; i < rec->plan.plugins.num_sock_fields; i++) {
        const struct dev_plugin_sock_field *sf = &rec->plan.plugins.sock_fields[i];
        fprintf(fp, "    {\"slot\": %d, \"plugin_id\": ", i);
        json_write_escaped(fp, sf->plugin_id);
        fprintf(fp, ", \"label\": "); json_write_escaped(fp, sf->label);
        fprintf(fp, ", \"role\": %s, \"resolved\": %s}%s\n",
                sf->role == PKT_SOCK_PLUG_TGID_FALLBACK ? "\"tgid_fallback\"" : "\"tag\"",
                sf->resolved ? "true" : "false",
                (i + 1 < rec->plan.plugins.num_sock_fields) ? "," : "");
    }
    fprintf(fp, "  ],\n  \"topology_epochs\": [\n");
    for (uint32_t e = 0; e < rec->topo.num_epochs; e++) {
        const struct topo_epoch_snap *ep = &rec->topo.epochs[e];
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"epoch_id\": %u,\n", ep->epoch_id);
        fprintf(fp, "      \"ts_ns\": %llu,\n", (unsigned long long)ep->ts_ns);
        fprintf(fp, "      \"netns_inum\": %u,\n", ep->netns_inum);
        fprintf(fp, "      \"devices\": [\n");
        for (uint32_t d = 0; d < ep->num_devs; d++) {
            const struct topo_dev_entry *dv = &ep->devs[d];
            fprintf(fp, "        {\"ifindex\": %u, \"dev_gen\": %u, \"name\": ",
                    dv->ifindex, dv->dev_gen);
            json_write_escaped(fp, dv->name);
            fprintf(fp, ", \"linktype\": %u}%s\n",
                    dv->linktype, (d + 1 < ep->num_devs) ? "," : "");
        }
        fprintf(fp, "      ],\n      \"qdiscs\": [\n");
        for (uint32_t q = 0; q < ep->num_qdiscs; q++) {
            const struct topo_qdisc_entry *qd = &ep->qdiscs[q];
            fprintf(fp, "        {\"ifindex\": %u, \"dev_gen\": %u, \"queue_gen\": %llu, \"kind\": ",
                    qd->ifindex, qd->dev_gen, (unsigned long long)qd->queue_gen);
            json_write_escaped(fp, qd->kind);
            fprintf(fp, ", \"handle\": %u, \"parent\": %u, \"bytes\": %llu, \"packets\": %u, "
                        "\"drops\": %u, \"overlimits\": %u}%s\n",
                    qd->handle, qd->parent,
                    (unsigned long long)qd->bytes, qd->packets, qd->drops, qd->overlimits,
                    (q + 1 < ep->num_qdiscs) ? "," : "");
        }
        fprintf(fp, "      ],\n      \"classes\": [\n");
        for (uint32_t c = 0; c < ep->num_classes; c++) {
            const struct topo_class_entry *cl = &ep->classes[c];
            fprintf(fp, "        {\"ifindex\": %u, \"dev_gen\": %u, \"kind\": ",
                    cl->ifindex, cl->dev_gen);
            json_write_escaped(fp, cl->kind);
            fprintf(fp, ", \"handle\": %u, \"parent\": %u, \"leaf\": %u, "
                        "\"prio\": %u, \"quantum\": %u, \"rate_bps\": %llu, \"ceil_bps\": %llu, "
                        "\"bytes\": %llu, \"packets\": %u, \"drops\": %u, \"overlimits\": %u}%s\n",
                    cl->handle, cl->parent, cl->leaf,
                    cl->prio, cl->quantum,
                    (unsigned long long)cl->rate_bps, (unsigned long long)cl->ceil_bps,
                    (unsigned long long)cl->bytes, cl->packets, cl->drops, cl->overlimits,
                    (c + 1 < ep->num_classes) ? "," : "");
        }
        fprintf(fp, "      ]\n    }%s\n", (e + 1 < rec->topo.num_epochs) ? "," : "");
    }
    fprintf(fp, "  ]\n}\n");

    if (fclose(fp) != 0 || rename(d_tmp, d_fin) != 0) {
        (void)unlink(d_tmp);
        return -1;
    }
    return 0;
}

/* ==========================================================================
 * 8. Periodic Quality Sampler, Active Map Drain & Daemon Rotation/Flush
 * ========================================================================== */

static void sample_health_and_losses(struct recorder_ctx *rec, bool emit_checkpoint_block) {
    uint64_t now_ns = now_boottime_ns();
    uint64_t win_start = rec->last_health_ts_ns ? rec->last_health_ts_ns : now_ns;

    uint8_t qbuf[8192];
    uint32_t qlen = 0;

    /* 1. Read kprobe_profile nmissed deltas */
    if (rec->plan.has_kprobe_profile) {
        struct kprobe_miss_entry entries[DEV_MAX_SITES];
        int n = tracefs_read_kprobe_profile(rec->kp_group, entries, DEV_MAX_SITES);
        for (int i = 0; i < n; i++) {
            for (uint32_t s = 0; s < rec->plan.num_sites; s++) {
                struct site_plan *sp = &rec->plan.sites[s];
                if (!sp->attached || strcmp(sp->kp_event_name, entries[i].event_name) != 0)
                    continue;
                if (entries[i].nmissed > sp->last_kp_missed) {
                    uint64_t delta = entries[i].nmissed - sp->last_kp_missed;
                    sp->last_kp_missed = entries[i].nmissed;
                    if (qlen + 128U <= sizeof(qbuf)) {
                        qlen += build_ctrl_quality_event(rec, PKT_QUAL_MISSED_DELTA,
                                                         sp->site_id, win_start, now_ns,
                                                         delta, qbuf + qlen);
                    }
                }
                break;
            }
        }
    }

    /* 2. Read bpf_prog_info.recursion_misses deltas */
    if (rec->plan.has_rec_misses) {
        for (uint32_t s = 0; s < rec->plan.num_sites; s++) {
            struct site_plan *sp = &rec->plan.sites[s];
            if (!sp->attached || sp->prog_fd < 0) continue;
            uint64_t rmiss = 0;
            if (bpf_read_recursion_misses(sp->prog_fd, &rmiss) == 0 &&
                rmiss > sp->last_rec_missed) {
                uint64_t delta = rmiss - sp->last_rec_missed;
                sp->last_rec_missed = rmiss;
                if (qlen + 128U <= sizeof(qbuf)) {
                    qlen += build_ctrl_quality_event(rec, PKT_QUAL_MISSED_DELTA,
                                                     sp->site_id, win_start, now_ns,
                                                     delta, qbuf + qlen);
                }
            }
        }
    }

    /* 3. Read ringbuf drop delta */
    struct bpf_ctrl_cfg cfg;
    if (read_ctrl_snapshot(rec, &cfg) == 0 && cfg.rb_drops > rec->last_rb_drops) {
        uint64_t delta = cfg.rb_drops - rec->last_rb_drops;
        rec->last_rb_drops = cfg.rb_drops;
        if (qlen + 128U <= sizeof(qbuf)) {
            qlen += build_ctrl_quality_event(rec, PKT_QUAL_RB_DROP_DELTA,
                                             0, win_start, now_ns, delta, qbuf + qlen);
        }
    }

    rec->last_health_ts_ns = now_ns;

    if (rec->num_calibrations < DEV_MAX_CALIBRATIONS) {
        sample_clock_calibration(&rec->calibrations[rec->num_calibrations++]);
    }

    if (rec->opts->mode == MODE_ONESHOT) {
        if (emit_checkpoint_block || qlen > 0) {
            seal_current_batch(rec);
            (void)write_atomic_block_file(rec, PKT_BLOCK_QUALITY_CHECKPOINT,
                                          PKT_PROD_CONTROLLER, rec->cur_epoch,
                                          win_start, now_ns,
                                          qlen > 0 ? qbuf : NULL, qlen);
        }
    } else if (qlen > 0) {
        /* In daemon mode, append quality events into the memory ring */
        uint32_t off = 0;
        while (off + sizeof(struct pkt_event_hdr_v1) <= qlen) {
            uint16_t tlen = 0;
            memcpy(&tlen, qbuf + off, 2);
            if (tlen < sizeof(struct pkt_event_hdr_v1) || off + tlen > qlen) break;
            append_wire_event(rec, qbuf + off, tlen, now_ns);
            off += tlen;
        }
    }
}

static uint64_t drain_active_slot_map(struct recorder_ctx *rec, int slot_fd) {
    if (slot_fd < 0) return 0;
    uint64_t ts_ns = now_boottime_ns();
    uint64_t truncated = 0;

    uint64_t key = 0, next_key = 0;
    const void *cur_key = NULL;
    while (bpf_map_get_next_key(slot_fd, cur_key, &next_key) == 0) {
        struct bpf_active_val av;
        if (bpf_map_lookup(slot_fd, &next_key, &av) == 0) {
            if (bpf_map_delete(slot_fd, &next_key) == 0) {
                if (rec->ctrl_shm) {
                    __atomic_fetch_sub(&rec->ctrl_shm->active_tracked_count, 1U, __ATOMIC_RELAXED);
                }
            }
            if (av.object_id != 0 && av.lifecycle_state != PKT_STATE_QUARANTINED) {
                uint8_t ev[128];
                uint32_t elen = build_ctrl_truncated_obj_event(rec, av.object_id, av.sample_id, ts_ns, ev);
                append_wire_event(rec, ev, elen, ts_ns);
                truncated++;
            }
            /* Restart from NULL since deletion mutates hash bucket chain */
            cur_key = NULL;
        } else {
            key = next_key;
            cur_key = &key;
        }
    }
    return truncated;
}

static void daemon_step_epoch_rotation(struct recorder_ctx *rec, uint64_t now_ns) {
    const char *env_ms = getenv("PKTPATH_EPOCH_MS");
    uint64_t rot_interval_ns = env_ms ? ((uint64_t)strtoull(env_ms, NULL, 10) * 1000000ULL)
                                      : 2000000000ULL; /* default 2s seamless A/B rotation */
    if (rot_interval_ns < 200000000ULL) rot_interval_ns = 200000000ULL;

    if (!rec->slot_draining) {
        if (now_ns - rec->last_epoch_rot_ns < rot_interval_ns)
            return;

        uint32_t old_slot  = rec->cur_slot;
        uint32_t next_slot = 1U - old_slot;

        /* Ensure next_slot has a fresh empty inner HASH map in active_slots[next_slot] */
        int fresh_fd = bpf_create_map_ext(BPF_MAP_TYPE_HASH, 8, sizeof(struct bpf_active_val),
                                          rec->max_active_entries, 0, -1);
        if (fresh_fd >= 0) {
            if (bpf_map_update(rec->map_fds[PKT_MAP_ACTIVE_SLOTS], &next_slot, &fresh_fd, 0) == 0) {
                if (rec->slot_fds[next_slot] >= 0) close(rec->slot_fds[next_slot]);
                rec->slot_fds[next_slot] = fresh_fd;
            } else {
                close(fresh_fd);
            }
        }

        rec->cur_slot = next_slot;
        rec->cur_epoch++;
        rec->slot_draining = true;
        rec->drain_started_ns = now_ns;
        rec->last_epoch_rot_ns = now_ns;

        if (rec->ctrl_shm) {
            __atomic_store_n(&rec->ctrl_shm->draining_slot_active, 1U, __ATOMIC_RELEASE);
            __atomic_store_n(&rec->ctrl_shm->epoch, rec->cur_epoch, __ATOMIC_RELEASE);
            __atomic_store_n(&rec->ctrl_shm->active_slot, rec->cur_slot, __ATOMIC_RELEASE);
        } else {
            uint32_t z = 0;
            struct bpf_ctrl_cfg cfg;
            if (bpf_map_lookup(rec->map_fds[PKT_MAP_CONTROL], &z, &cfg) == 0) {
                cfg.draining_slot_active = 1U;
                cfg.epoch = rec->cur_epoch;
                cfg.active_slot = rec->cur_slot;
                (void)bpf_map_update(rec->map_fds[PKT_MAP_CONTROL], &z, &cfg, 0);
            }
        }
    } else if (now_ns - rec->drain_started_ns >= 250000000ULL) {
        /* 250 ms drain window elapsed: close old slot lookup, drain residuals -> TIMEOUT_TRUNCATED */
        uint32_t old_slot = 1U - rec->cur_slot;
        if (rec->ctrl_shm) {
            __atomic_store_n(&rec->ctrl_shm->draining_slot_active, 0U, __ATOMIC_RELEASE);
        } else {
            uint32_t z = 0;
            struct bpf_ctrl_cfg cfg;
            if (bpf_map_lookup(rec->map_fds[PKT_MAP_CONTROL], &z, &cfg) == 0) {
                cfg.draining_slot_active = 0U;
                (void)bpf_map_update(rec->map_fds[PKT_MAP_CONTROL], &z, &cfg, 0);
            }
        }
        usleep(10000); /* RCU grace period */
        drain_ringbuf(rec);

        uint64_t trunc_cnt = drain_active_slot_map(rec, rec->slot_fds[old_slot]);
        uint8_t qev[128];
        uint32_t qlen = build_ctrl_quality_event(rec, PKT_QUAL_EPOCH_SWITCH, 0,
                                                 rec->drain_started_ns, now_ns,
                                                 trunc_cnt, qev);
        append_wire_event(rec, qev, qlen, now_ns);
        rec->slot_draining = false;
    }
}

static int daemon_flush_ring_to_disk(struct recorder_ctx *rec, bool manual_full_window) {
    if (mkdir_p(rec->opts->out_dir) != 0) {
        fprintf(stderr, "daemon flush error: mkdir_p(%s) failed: %s\n",
                rec->opts->out_dir, strerror(errno));
        return -1;
    }

    drain_ringbuf(rec);
    seal_current_batch(rec);

    uint64_t now_ns = now_boottime_ns();
    uint64_t min_keep_ts = 0;
    if (!manual_full_window && rec->trigger_ts_ns > 0) {
        uint64_t pre_ns = (uint64_t)rec->opts->pre_window_sec * 1000000000ULL;
        min_keep_ts = (rec->trigger_ts_ns > pre_ns) ? (rec->trigger_ts_ns - pre_ns) : 0ULL;
    }

    /* Reset output directory block counter & remove prior snapshot blocks if re-flushing */
    DIR *od = opendir(rec->opts->out_dir);
    if (od) {
        struct dirent *de;
        while ((de = readdir(od)) != NULL) {
            if (strncmp(de->d_name, "block_", 6) == 0) {
                char p[600];
                snprintf(p, sizeof(p), "%s/%s", rec->opts->out_dir, de->d_name);
                (void)unlink(p);
            }
        }
        closedir(od);
    }
    rec->next_block_no = 0;
    rec->disk_bytes_used = 0;
    rec->disk_budget_hit = false;

    /* Disclose evicted ring prefix if older blocks rolled out */
    if (rec->evicted_blocks > 0) {
        uint8_t qev[128];
        uint32_t qlen = build_ctrl_quality_event(rec, PKT_QUAL_RING_EVICTED_PREFIX, 0,
                                                 rec->evicted_first_ts_ns, rec->evicted_last_ts_ns,
                                                 rec->evicted_blocks, qev);
        (void)write_atomic_block_file(rec, PKT_BLOCK_QUALITY_CHECKPOINT,
                                      PKT_PROD_CONTROLLER, rec->cur_epoch,
                                      rec->evicted_first_ts_ns, rec->evicted_last_ts_ns,
                                      qev, qlen);
    }

    uint64_t total_written = rec->ring_write_seq;
    uint64_t retained = total_written < rec->ring_cap ? total_written : rec->ring_cap;
    uint64_t start_seq = total_written - retained;

    for (uint64_t s = start_seq; s < total_written; s++) {
        const struct mem_ring_block *mb = &rec->mem_ring[s % rec->ring_cap];
        if (!mb->valid) continue;
        if (min_keep_ts > 0 && mb->hdr.max_ts_ns > 0 && mb->hdr.max_ts_ns < min_keep_ts)
            continue;
        if (write_atomic_block_file(rec, mb->hdr.block_type, mb->hdr.producer_type,
                                    mb->hdr.epoch, mb->hdr.min_ts_ns, mb->hdr.max_ts_ns,
                                    mb->payload, mb->hdr.payload_len) < 0) {
            break;
        }
    }

    (void)write_atomic_block_file(rec, PKT_BLOCK_QUALITY_CHECKPOINT,
                                  PKT_PROD_CONTROLLER, rec->cur_epoch,
                                  now_ns, now_ns, NULL, 0);
    (void)write_atomic_block_file(rec, PKT_BLOCK_END_MARKER,
                                  PKT_PROD_CONTROLLER, rec->cur_epoch,
                                  now_ns, now_ns, NULL, 0);
    (void)write_manifest_and_dict(rec);

    rec->trigger_armed = false;
    rec->flush_count++;
    fprintf(stderr, "DAEMON_FLUSHED blocks=%u out=%s\n", rec->next_block_no, rec->opts->out_dir);
    fflush(stderr);
    return rec->disk_enospc ? -1 : 0;
}

/* ==========================================================================
 * 9. BPF Map & Probe Lifecycle Setup / Teardown
 * ========================================================================== */

static void prefix_to_mask6(uint8_t prefix, uint8_t mask[16]) {
    memset(mask, 0, 16);
    if (prefix > 128) prefix = 128;
    uint8_t full = prefix / 8U;
    uint8_t rem  = prefix % 8U;
    if (full > 0) memset(mask, 0xFF, full);
    if (rem > 0 && full < 16)
        mask[full] = (uint8_t)(0xFFU << (8U - rem));
}

static void cleanup_recorder(struct recorder_ctx *rec) {
    /* 1. Close all perf_event FDs FIRST so tracefs kprobe_events are no longer EBUSY */
    for (int s = (int)rec->plan.num_sites - 1; s >= 0; s--) {
        struct site_plan *sp = &rec->plan.sites[s];
        for (int j = 0; j < sp->num_perf_fds; j++) {
            if (sp->perf_fds[j] >= 0) close(sp->perf_fds[j]);
        }
        sp->num_perf_fds = 0;
        if (sp->prog_fd >= 0) {
            close(sp->prog_fd);
            sp->prog_fd = -1;
        }
    }

    /* 2. Remove registered kprobes and session state file */
    if (rec->kp_group[0]) {
        tracefs_unregister_group_all(rec->kp_group);
        tracefs_remove_state_file(getpid());
    }

    /* 3. Unmap ringbuf & control shm, close BPF maps */
    if (rec->rb_prod_map && rec->rb_prod_map != MAP_FAILED)
        munmap(rec->rb_prod_map, rec->rb_page_sz + 2U * rec->rb_sz);
    if (rec->rb_cons_map && rec->rb_cons_map != MAP_FAILED)
        munmap(rec->rb_cons_map, rec->rb_page_sz);
    if (rec->ctrl_shm && rec->ctrl_shm != MAP_FAILED)
        munmap(rec->ctrl_shm, rec->ctrl_shm_sz);

    for (int i = 0; i < PKT_MAP_COUNT; i++) {
        if (rec->map_fds[i] >= 0) close(rec->map_fds[i]);
    }
    for (int i = 0; i < (int)PKT_ACTIVE_SLOTS_CNT; i++) {
        if (rec->slot_fds[i] >= 0) close(rec->slot_fds[i]);
    }

    topo_mgr_destroy(&rec->topo);
    free(rec->visit_cache);
    free(rec->mem_ring);
}

static int setup_bpf_maps(struct recorder_ctx *rec) {
    rec->max_active_entries = rec->opts->profile_sendmsg
                                  ? PKT_SENDMSG_MAX_ACTIVE
                                  : PKT_DEFAULT_MAX_ACTIVE;
    rec->rb_page_sz = (size_t)sysconf(_SC_PAGESIZE);
    rec->rb_sz = PKT_DEFAULT_RINGBUF_SZ;
    if (rec->opts->mem_budget_bytes > 0 && rec->opts->mem_budget_bytes < 8ULL * 1024ULL * 1024ULL)
        rec->rb_sz = 1024U * 1024U; /* 1 MiB ringbuf for tight memory budgets */
    rec->rb_mask = rec->rb_sz - 1U;

    /* 0: active_slots (ARRAY_OF_MAPS with 2 inner HASH maps) */
    for (uint32_t i = 0; i < PKT_ACTIVE_SLOTS_CNT; i++) {
        rec->slot_fds[i] = bpf_create_map_ext(BPF_MAP_TYPE_HASH, 8,
                                              sizeof(struct bpf_active_val),
                                              rec->max_active_entries, 0, -1);
        if (rec->slot_fds[i] < 0) {
            fprintf(stderr, "record error: create inner active hash[%u] failed: %s\n",
                    i, strerror(errno));
            return -1;
        }
    }
    rec->map_fds[PKT_MAP_ACTIVE_SLOTS] =
        bpf_create_map_ext(BPF_MAP_TYPE_ARRAY_OF_MAPS, 4, 4,
                           PKT_ACTIVE_SLOTS_CNT, 0, rec->slot_fds[0]);
    if (rec->map_fds[PKT_MAP_ACTIVE_SLOTS] < 0) {
        fprintf(stderr, "record error: create active_slots ARRAY_OF_MAPS failed: %s\n",
                strerror(errno));
        return -1;
    }
    for (uint32_t i = 0; i < PKT_ACTIVE_SLOTS_CNT; i++) {
        int ifd = rec->slot_fds[i];
        if (bpf_map_update(rec->map_fds[PKT_MAP_ACTIVE_SLOTS], &i, &ifd, 0) < 0) {
            fprintf(stderr, "record error: populate active_slots[%u] failed: %s\n",
                    i, strerror(errno));
            return -1;
        }
    }

    /* 1: control (try BPF_F_MMAPABLE first for race-free atomic updates) */
    rec->map_fds[PKT_MAP_CONTROL] =
        bpf_create_map_ext(BPF_MAP_TYPE_ARRAY, 4, sizeof(struct bpf_ctrl_cfg),
                           1, BPF_F_MMAPABLE, -1);
    if (rec->map_fds[PKT_MAP_CONTROL] >= 0) {
        rec->ctrl_shm_sz = rec->rb_page_sz;
        while (rec->ctrl_shm_sz < sizeof(struct bpf_ctrl_cfg))
            rec->ctrl_shm_sz += rec->rb_page_sz;
        void *m = mmap(NULL, rec->ctrl_shm_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
                       rec->map_fds[PKT_MAP_CONTROL], 0);
        if (m != MAP_FAILED)
            rec->ctrl_shm = (struct bpf_ctrl_cfg *)m;
    } else {
        rec->map_fds[PKT_MAP_CONTROL] =
            bpf_create_map_ext(BPF_MAP_TYPE_ARRAY, 4, sizeof(struct bpf_ctrl_cfg), 1, 0, -1);
    }
    if (rec->map_fds[PKT_MAP_CONTROL] < 0) {
        fprintf(stderr, "record error: create control map failed: %s\n", strerror(errno));
        return -1;
    }

    /* 2..6: calls, rb, socks, cpu_seq, btf_off */
    rec->map_fds[PKT_MAP_CALLS] =
        bpf_create_map_ext(BPF_MAP_TYPE_HASH, sizeof(struct bpf_call_key),
                           sizeof(struct bpf_call_val), PKT_DEFAULT_MAX_CALLS, 0, -1);
    rec->map_fds[PKT_MAP_RB] =
        bpf_create_map_ext(BPF_MAP_TYPE_RINGBUF, 0, 0, (uint32_t)rec->rb_sz, 0, -1);
    rec->map_fds[PKT_MAP_SOCKS] =
        bpf_create_map_ext(BPF_MAP_TYPE_HASH, 8, sizeof(struct bpf_sock_owner),
                           PKT_DEFAULT_MAX_SOCKS, 0, -1);
    rec->map_fds[PKT_MAP_CPU_SEQ] =
        bpf_create_map_ext(BPF_MAP_TYPE_ARRAY, 4, 8, PKT_MAX_CPUS, 0, -1);
    rec->map_fds[PKT_MAP_BTF_OFF] =
        bpf_create_map_ext(BPF_MAP_TYPE_ARRAY, 4, sizeof(struct bpf_btf_offsets), 1, 0, -1);

    for (int i = 0; i < PKT_MAP_COUNT; i++) {
        if (rec->map_fds[i] < 0) {
            fprintf(stderr, "record error: create map[%d] failed: %s\n", i, strerror(errno));
            return -1;
        }
    }

    /* mmap ringbuf consumer & producer pages */
    rec->rb_cons_map = mmap(NULL, rec->rb_page_sz, PROT_READ | PROT_WRITE,
                            MAP_SHARED, rec->map_fds[PKT_MAP_RB], 0);
    if (rec->rb_cons_map == MAP_FAILED) {
        fprintf(stderr, "record error: mmap ringbuf consumer failed: %s\n", strerror(errno));
        return -1;
    }
    rec->rb_prod_map = mmap(NULL, rec->rb_page_sz + 2U * rec->rb_sz, PROT_READ,
                            MAP_SHARED, rec->map_fds[PKT_MAP_RB], (off_t)rec->rb_page_sz);
    if (rec->rb_prod_map == MAP_FAILED) {
        fprintf(stderr, "record error: mmap ringbuf producer failed: %s\n", strerror(errno));
        return -1;
    }
    rec->rb_cons_pos = (unsigned long *)rec->rb_cons_map;
    rec->rb_prod_pos = (unsigned long *)rec->rb_prod_map;
    rec->rb_data     = (const uint8_t *)rec->rb_prod_map + rec->rb_page_sz;

    /* Populate BTF offsets + sock plugin specs map */
    uint32_t z = 0;
    struct bpf_btf_offsets bo;
    populate_bpf_btf_offsets(&rec->plan, &bo);
    if (bpf_map_update(rec->map_fds[PKT_MAP_BTF_OFF], &z, &bo, 0) < 0) {
        fprintf(stderr, "record error: update btf_off map failed: %s\n", strerror(errno));
        return -1;
    }

    /* Warm up pre-existing long-lived sockets (keyed by sk_ptr and/or skc_cookie) */
    struct dev_warm_sock *warm = calloc(4096, sizeof(*warm));
    if (warm) {
        int nwarm = proc_warmup_scan(warm, 4096);
        for (int i = 0; i < nwarm; i++) {
            if (warm[i].cookie == 0 || warm[i].cookie == ~0ULL)
                continue;
            struct bpf_sock_owner so;
            memset(&so, 0, sizeof(so));
            so.cookie = warm[i].cookie;
            so.tgid   = warm[i].tgid;
            so.uid    = warm[i].uid;
            so.flags  = PKT_SOCK_F_HAS_OWNER;
            memcpy(so.comm, warm[i].comm, 16);
            if (warm[i].sk_ptr != 0)
                (void)bpf_map_update(rec->map_fds[PKT_MAP_SOCKS], &warm[i].sk_ptr, &so, 0);
            if (warm[i].cookie < 0xFFFF000000000000ULL) {
                uint64_t ck_key = warm[i].cookie;
                (void)bpf_map_update(rec->map_fds[PKT_MAP_SOCKS], &ck_key, &so, 0);
            }
        }
        free(warm);
    }

    return 0;
}

static int load_and_attach_probes(struct recorder_ctx *rec) {
    if (rec->plan.num_sites == 0) {
        fprintf(stderr, "record error: no compiled BPF programs in binary\n");
        return -1;
    }

    snprintf(rec->kp_group, sizeof(rec->kp_group), "pktpath_%d", (int)getpid());
    (void)tracefs_write_state_file(getpid(), rec->kp_group);

    int ncpus = (int)sysconf(_SC_NPROCESSORS_CONF);
    if (ncpus <= 0) ncpus = 1;
    if (ncpus > DEV_MAX_CPUS) ncpus = DEV_MAX_CPUS;

    for (uint32_t s = 0; s < rec->plan.num_sites; s++) {
        struct site_plan *sp = &rec->plan.sites[s];
        if (!sp->desired || !sp->available)
            continue;
        if (!rec->plan.adapters[sp->adapter_idx].enabled && sp->adapter_idx != ADAPT_L2_CORE)
            continue;

        const struct bpf_prog_img *im = &pkt_bpf_progs[sp->prog_idx];
        size_t code_bytes = (size_t)im->insn_cnt * sizeof(struct bpf_insn);
        struct bpf_insn *insns = malloc(code_bytes);
        if (!insns) return -1;
        memcpy(insns, im->insns, code_bytes);

        /* Patch dynamic template site_id sentinels BEFORE map FD relocation */
        if (sp->dyn_patch_enq_site != 0 || sp->dyn_patch_ret_site != 0) {
            for (uint32_t k = 0; k < im->insn_cnt; k++) {
                if (insns[k].code == (BPF_LD | BPF_DW | BPF_IMM))
                    continue;
                if (sp->dyn_patch_enq_site != 0 &&
                    insns[k].imm == (int32_t)PKT_SITE_DYN_ENQ_SENTINEL) {
                    insns[k].imm = (int32_t)sp->dyn_patch_enq_site;
                } else if (sp->dyn_patch_ret_site != 0 &&
                           insns[k].imm == (int32_t)PKT_SITE_DYN_RET_SENTINEL) {
                    insns[k].imm = (int32_t)sp->dyn_patch_ret_site;
                }
            }
        }

        for (uint32_t r = 0; r < im->reloc_cnt; r++) {
            uint32_t ix = im->relocs[r].insn_idx;
            uint32_t mx = im->relocs[r].map_idx;
            if (ix >= im->insn_cnt || mx >= PKT_MAP_COUNT) {
                free(insns);
                fprintf(stderr, "record error: invalid reloc in %s\n", im->sec_name);
                return -1;
            }
            insns[ix].src_reg = BPF_PSEUDO_MAP_FD;
            insns[ix].imm     = rec->map_fds[mx];
        }

        union bpf_attr a;
        memset(&a, 0, sizeof(a));
        a.prog_type = im->prog_type;
        a.insns     = (uintptr_t)insns;
        a.insn_cnt  = im->insn_cnt;
        a.license   = (uintptr_t)"GPL";

        size_t load_sz = offsetof(union bpf_attr, kern_version) + 4U;
        int pfd = bpf_sys(BPF_PROG_LOAD, &a, load_sz);
        if (pfd < 0) {
            static char vlog[65536];
            vlog[0] = '\0';
            a.log_level = 1;
            a.log_buf   = (uintptr_t)vlog;
            a.log_size  = sizeof(vlog);
            pfd = bpf_sys(BPF_PROG_LOAD, &a, load_sz);
            if (pfd < 0) {
                fprintf(stderr, "record error: BPF_PROG_LOAD(%s) failed: %s\n%s\n",
                        im->sec_name, strerror(errno), vlog);
                free(insns);
                return -1;
            }
        }
        free(insns);
        sp->prog_fd = pfd;

        int ev_id = -1;
        if (im->prog_type == PKT_BPF_PROG_TYPE_TRACEPOINT) {
            const char *grp = im->attach_group ? im->attach_group : "net";
            ev_id = tracefs_read_event_id(grp, im->attach_name);
        } else {
            snprintf(sp->kp_event_name, sizeof(sp->kp_event_name),
                     "%s_s%u", rec->kp_group, sp->site_id);
            if (tracefs_register_kprobe(rec->kp_group, sp->kp_event_name,
                                        sp->resolved_sym, im->is_retprobe != 0) == 0) {
                ev_id = tracefs_read_event_id(rec->kp_group, sp->kp_event_name);
            }
        }

        if (ev_id < 0) {
            if (rec->plan.adapters[sp->adapter_idx].required && !rec->opts->allow_partial) {
                fprintf(stderr, "record error: failed to register trace event for %s (%s)\n",
                        im->sec_name, sp->resolved_sym);
                return -1;
            }
            close(sp->prog_fd);
            sp->prog_fd = -1;
            continue;
        }

        struct perf_event_attr pe;
        memset(&pe, 0, sizeof(pe));
        pe.size          = sizeof(pe);
        pe.type          = PERF_TYPE_TRACEPOINT;
        pe.config        = (uint64_t)ev_id;
        pe.disabled      = 1;
        pe.sample_period = 1;
        pe.wakeup_events = 1;

        int attached = 0;
        for (int cpu = 0; cpu < ncpus; cpu++) {
            int pf = (int)syscall(__NR_perf_event_open, &pe, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
            if (pf < 0 && (errno == ENODEV || errno == EINVAL))
                continue; /* offline CPU */
            if (pf < 0) break;
            if (attached == 0 && ioctl(pf, PERF_EVENT_IOC_SET_BPF, pfd) < 0) {
                close(pf);
                break;
            }
            if (ioctl(pf, PERF_EVENT_IOC_ENABLE, 0) < 0) {
                close(pf);
                break;
            }
            sp->perf_fds[sp->num_perf_fds++] = pf;
            attached++;
        }

        if (attached == 0) {
            if (rec->plan.adapters[sp->adapter_idx].required && !rec->opts->allow_partial) {
                fprintf(stderr, "record error: perf_event_open/SET_BPF failed on %s\n", im->sec_name);
                return -1;
            }
            close(sp->prog_fd);
            sp->prog_fd = -1;
            continue;
        }
        sp->attached = true;
    }

    /* Record baseline kprobe_profile & recursion_misses before opening admission */
    if (rec->plan.has_kprobe_profile) {
        struct kprobe_miss_entry entries[DEV_MAX_SITES];
        int n = tracefs_read_kprobe_profile(rec->kp_group, entries, DEV_MAX_SITES);
        for (int i = 0; i < n; i++) {
            for (uint32_t s = 0; s < rec->plan.num_sites; s++) {
                if (rec->plan.sites[s].attached &&
                    strcmp(rec->plan.sites[s].kp_event_name, entries[i].event_name) == 0) {
                    rec->plan.sites[s].last_kp_missed = entries[i].nmissed;
                }
            }
        }
    }
    if (rec->plan.has_rec_misses) {
        for (uint32_t s = 0; s < rec->plan.num_sites; s++) {
            if (rec->plan.sites[s].attached && rec->plan.sites[s].prog_fd >= 0)
                (void)bpf_read_recursion_misses(rec->plan.sites[s].prog_fd,
                                                &rec->plan.sites[s].last_rec_missed);
        }
    }

    return 0;
}

/* ==========================================================================
 * 10. `pktpath record` Main Orchestrator
 * ========================================================================== */

int run_record(const struct dev_cli_opts *opts) {
    crc32_init_once();
    install_signal_handlers();
    (void)tracefs_reap_stale_groups();

    /* Explicit /dev/full character-device fast check */
    struct stat ost;
    if (stat(opts->out_dir, &ost) == 0 && S_ISCHR(ost.st_mode)) {
        int cfd = open(opts->out_dir, O_WRONLY | O_CLOEXEC);
        if (cfd >= 0) {
            char probe = 0;
            ssize_t w = write(cfd, &probe, 1);
            int saved = errno;
            close(cfd);
            if (w < 0) {
                fprintf(stderr, "record error: write(%s) failed: %s\n",
                        opts->out_dir, strerror(saved));
                return 1;
            }
        }
        fprintf(stderr, "record error: --out '%s' is a character device, expected directory\n",
                opts->out_dir);
        return 1;
    }

    struct recorder_ctx rec;
    memset(&rec, 0, sizeof(rec));
    rec.opts = opts;
    rec.cur_epoch = 1;
    rec.cur_slot = 0;
    for (int i = 0; i < PKT_MAP_COUNT; i++) rec.map_fds[i] = -1;
    for (uint32_t i = 0; i < PKT_ACTIVE_SLOTS_CNT; i++) rec.slot_fds[i] = -1;
    generate_session_uuid(rec.session_uuid, rec.session_uuid_str);

    char err[256] = "";
    if (topo_mgr_init(&rec.topo, err, sizeof(err)) != 0) {
        fprintf(stderr, "record error: %s\n", err);
        return 1;
    }
    if (build_probe_plan(opts, &rec.topo, &rec.plan, err, sizeof(err)) != 0) {
        fprintf(stderr, "record error: %s\n", err);
        cleanup_recorder(&rec);
        return 1;
    }

    rec.visit_cache = calloc(OPEN_VISIT_SLOTS, sizeof(struct open_visit_slot));
    if (!rec.visit_cache) {
        fprintf(stderr, "record error: out of memory allocating visit_cache\n");
        cleanup_recorder(&rec);
        return 1;
    }

    if (opts->mode == MODE_DAEMON) {
        uint64_t nblk = opts->mem_budget_bytes / sizeof(struct mem_ring_block);
        if (nblk < 8ULL) nblk = 8ULL;
        if (nblk > 2048ULL) nblk = 2048ULL;
        rec.ring_cap = (uint32_t)nblk;
        rec.mem_ring = calloc(rec.ring_cap, sizeof(struct mem_ring_block));
        if (!rec.mem_ring) {
            fprintf(stderr, "record error: out of memory allocating daemon ring (%u blocks)\n",
                    rec.ring_cap);
            cleanup_recorder(&rec);
            return 1;
        }
    } else {
        if (mkdir_p(opts->out_dir) != 0) {
            fprintf(stderr, "record error: mkdir_p(%s) failed: %s\n",
                    opts->out_dir, strerror(errno));
            cleanup_recorder(&rec);
            return 1;
        }
    }

    if (setup_bpf_maps(&rec) != 0) {
        cleanup_recorder(&rec);
        return 1;
    }

    /* Configure initial control map with admission gated OFF while attaching */
    struct bpf_ctrl_cfg init_cfg;
    memset(&init_cfg, 0, sizeof(init_cfg));
    uint32_t cflags = PKT_CTRL_DEFAULT_FLAGS;
    if (opts->profile_sendmsg) cflags |= PKT_CTRL_F_SENDMSG;
    if (rec.plan.sock_plugins_active) cflags |= PKT_CTRL_F_SOCK_PLUGINS;
    if (opts->capture_hdr_len > 0) cflags |= PKT_CTRL_F_CAPTURE_HDR;
    if (rec.plan.partial_coverage) cflags |= PKT_CTRL_F_PARTIAL_COV;

    init_cfg.active_slot     = 0;
    init_cfg.epoch           = 1;
    init_cfg.flags           = cflags | PKT_CTRL_F_ADMIT_OFF;
    init_cfg.capture_hdr_len = opts->capture_hdr_len;
    init_cfg.sample_stride   = 0;
    init_cfg.sample_by_flow  = opts->sample_by_flow ? 1U : 0U;
    init_cfg.filter_ifindex  = rec.plan.target_ifindex;
    init_cfg.filter_netns    = (opts->scope == SCOPE_FWD) ? 0U : rec.topo.netns_inum;
    init_cfg.filter_proto    = opts->filter_proto;
    init_cfg.filter_ip_ver   = opts->filter_ip_ver;
    init_cfg.filter_src_port = opts->src_port;
    init_cfg.filter_dst_port = opts->dst_port;
    init_cfg.filter_src_ip4  = opts->src_ip4;
    init_cfg.filter_src_ip4_mask = opts->src_mask4;
    init_cfg.filter_dst_ip4  = opts->dst_ip4;
    init_cfg.filter_dst_ip4_mask = opts->dst_mask4;
    init_cfg.filter_mark     = opts->mark_val;
    init_cfg.filter_mark_mask = opts->has_mark ? opts->mark_mask : 0U;
    init_cfg.filter_uid      = opts->has_uid ? opts->uid : PKT_FILTER_UID_ANY;
    init_cfg.filter_tgid     = opts->tgid;
    if (opts->has_src_ip && opts->filter_ip_ver == 6) {
        memcpy(init_cfg.filter_src_ip6, opts->src_ip6, 16);
        prefix_to_mask6(opts->src_prefix6, init_cfg.filter_src_ip6_mask);
    }
    if (opts->has_dst_ip && opts->filter_ip_ver == 6) {
        memcpy(init_cfg.filter_dst_ip6, opts->dst_ip6, 16);
        prefix_to_mask6(opts->dst_prefix6, init_cfg.filter_dst_ip6_mask);
    }

    uint32_t z = 0;
    if (bpf_map_update(rec.map_fds[PKT_MAP_CONTROL], &z, &init_cfg, 0) < 0) {
        fprintf(stderr, "record error: init control map failed: %s\n", strerror(errno));
        cleanup_recorder(&rec);
        return 1;
    }

    if (load_and_attach_probes(&rec) != 0) {
        cleanup_recorder(&rec);
        return 1;
    }

    sample_clock_calibration(&rec.calibrations[rec.num_calibrations++]);
    uint64_t start_ns = now_boottime_ns();
    rec.last_health_ts_ns = start_ns;
    rec.last_epoch_rot_ns = start_ns;

    /* In oneshot mode, persist initial manifest.json & dict.json BEFORE arming
     * admission so SIGKILL mid-capture still leaves a loadable session dir! */
    if (opts->mode == MODE_ONESHOT) {
        if (write_manifest_and_dict(&rec) != 0) {
            fprintf(stderr, "record error: write initial manifest/dict failed: %s\n",
                    strerror(errno));
            cleanup_recorder(&rec);
            return 1;
        }
    }

    /* Set up epoll on ringbuf + live rtnetlink socket */
    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) {
        fprintf(stderr, "record error: epoll_create1 failed: %s\n", strerror(errno));
        cleanup_recorder(&rec);
        return 1;
    }
    struct epoll_event ev_rb = {.events = EPOLLIN, .data.fd = rec.map_fds[PKT_MAP_RB]};
    (void)epoll_ctl(ep, EPOLL_CTL_ADD, rec.map_fds[PKT_MAP_RB], &ev_rb);
    struct epoll_event ev_nl = {.events = EPOLLIN, .data.fd = rec.topo.nl_fd};
    (void)epoll_ctl(ep, EPOLL_CTL_ADD, rec.topo.nl_fd, &ev_nl);

    /* Open admission! */
    if (rec.ctrl_shm) {
        __atomic_store_n(&rec.ctrl_shm->sample_stride, opts->sample_stride, __ATOMIC_RELEASE);
        __atomic_store_n(&rec.ctrl_shm->flags, cflags, __ATOMIC_RELEASE);
    } else {
        init_cfg.sample_stride = opts->sample_stride;
        init_cfg.flags = cflags;
        (void)bpf_map_update(rec.map_fds[PKT_MAP_CONTROL], &z, &init_cfg, 0);
    }

    fprintf(stderr, "READY uuid=%s mode=%s dev=%s ifindex=%u\n",
            rec.session_uuid_str, mode_to_str(opts->mode),
            opts->dev_name, rec.plan.target_ifindex);
    fflush(stderr);

    uint64_t deadline_ns = (opts->duration_sec > 0)
                               ? (start_ns + (uint64_t)opts->duration_sec * 1000000000ULL)
                               : 0ULL;
    uint64_t last_partial_seal_ns = start_ns;
    struct epoll_event events[8];

    while (!g_sig_stop) {
        uint64_t now_ns = now_boottime_ns();
        if (deadline_ns > 0 && now_ns >= deadline_ns)
            break;
        if (rec.disk_enospc || (opts->mode == MODE_ONESHOT && rec.disk_budget_hit))
            break;

        (void)epoll_wait(ep, events, 8, 25);
        drain_ringbuf(&rec);

        bool topo_chg = false, topo_desync = false;
        (void)topo_mgr_poll(&rec.topo, &topo_chg, &topo_desync);
        if (topo_chg && opts->mode == MODE_ONESHOT) {
            (void)write_manifest_and_dict(&rec);
        }
        if (topo_desync) {
            uint8_t qev[128];
            uint32_t qlen = build_ctrl_quality_event(&rec, PKT_QUAL_TOPO_DESYNC, 0,
                                                     rec.last_health_ts_ns, now_boottime_ns(),
                                                     1, qev);
            append_wire_event(&rec, qev, qlen, now_boottime_ns());
        }

        now_ns = now_boottime_ns();
        if (now_ns - rec.last_health_ts_ns >= 500000000ULL) {
            sample_health_and_losses(&rec, false);
        }

        if (opts->mode == MODE_DAEMON) {
            if (rec.cur_pay_len > 0 && now_ns - last_partial_seal_ns >= 250000000ULL) {
                seal_current_batch(&rec);
                last_partial_seal_ns = now_ns;
            }
            daemon_step_epoch_rotation(&rec, now_ns);

            if (g_sig_flush) {
                g_sig_flush = 0;
                (void)daemon_flush_ring_to_disk(&rec, true);
            } else if (rec.trigger_armed && now_ns >= rec.flush_deadline_ns) {
                (void)daemon_flush_ring_to_disk(&rec, false);
            }
        }
    }

    close(ep);

    /* Close admission & bounded in-flight drain (50 ms) */
    if (rec.ctrl_shm) {
        __atomic_store_n(&rec.ctrl_shm->sample_stride, 0U, __ATOMIC_RELEASE);
        __atomic_fetch_or(&rec.ctrl_shm->flags, PKT_CTRL_F_ADMIT_OFF, __ATOMIC_RELEASE);
    } else {
        struct bpf_ctrl_cfg stop_cfg;
        if (bpf_map_lookup(rec.map_fds[PKT_MAP_CONTROL], &z, &stop_cfg) == 0) {
            stop_cfg.sample_stride = 0U;
            stop_cfg.flags |= PKT_CTRL_F_ADMIT_OFF;
            (void)bpf_map_update(rec.map_fds[PKT_MAP_CONTROL], &z, &stop_cfg, 0);
        }
    }
    usleep(50000);
    drain_ringbuf(&rec);

    /* Sample final missed counts BEFORE detaching probes */
    sample_health_and_losses(&rec, opts->mode == MODE_ONESHOT);

    /* Detach probes cleanly so no further kernel writes occur */
    for (int s = (int)rec.plan.num_sites - 1; s >= 0; s--) {
        struct site_plan *sp = &rec.plan.sites[s];
        for (int j = 0; j < sp->num_perf_fds; j++) {
            if (sp->perf_fds[j] >= 0) close(sp->perf_fds[j]);
        }
        sp->num_perf_fds = 0;
    }
    drain_ringbuf(&rec);

    /* Drain any residual tracked objects in both A/B slots as TIMEOUT_TRUNCATED */
    for (uint32_t i = 0; i < PKT_ACTIVE_SLOTS_CNT; i++)
        (void)drain_active_slot_map(&rec, rec.slot_fds[i]);

    seal_current_batch(&rec);

    int exit_code = 0;
    if (opts->mode == MODE_ONESHOT) {
        if (rec.disk_enospc) {
            fprintf(stderr, "record error: disk write failed (%s); preserved %u valid blocks\n",
                    strerror(rec.enospc_errno), rec.next_block_no);
            exit_code = 1;
        } else if (rec.disk_budget_hit) {
            fprintf(stderr, "record warning: disk budget (%llu B) reached; preserved %u valid blocks\n",
                    (unsigned long long)opts->disk_budget_bytes, rec.next_block_no);
            (void)write_manifest_and_dict(&rec);
            /* If budget was too tiny for even 1 event/end block, signal budget limit */
            if (rec.next_block_no == 0)
                exit_code = 1;
        } else {
            uint64_t end_ns = now_boottime_ns();
            if (write_atomic_block_file(&rec, PKT_BLOCK_END_MARKER, PKT_PROD_CONTROLLER,
                                        rec.cur_epoch, end_ns, end_ns, NULL, 0) < 0) {
                fprintf(stderr, "record error: failed writing END_MARKER (%s)\n",
                        strerror(rec.enospc_errno));
                exit_code = 1;
            }
            if (write_manifest_and_dict(&rec) != 0)
                exit_code = 1;
        }
    } else {
        /* Daemon mode: if SIGUSR1 or pending trigger arrived right before stop, flush! */
        if (g_sig_flush || rec.trigger_armed) {
            if (daemon_flush_ring_to_disk(&rec, g_sig_flush != 0) != 0)
                exit_code = 1;
        }
    }

    struct bpf_ctrl_cfg final_cfg;
    memset(&final_cfg, 0, sizeof(final_cfg));
    (void)read_ctrl_snapshot(&rec, &final_cfg);
    fprintf(stderr,
            "DONE mode=%s blocks=%u matched=%llu selected=%llu created=%llu rejected=%llu rb_drops=%llu\n",
            mode_to_str(opts->mode), rec.next_block_no,
            (unsigned long long)final_cfg.admission_matched,
            (unsigned long long)final_cfg.admission_selected,
            (unsigned long long)final_cfg.admission_created,
            (unsigned long long)final_cfg.admission_rejected,
            (unsigned long long)final_cfg.rb_drops);
    fflush(stderr);

    cleanup_recorder(&rec);
    return exit_code;
}
