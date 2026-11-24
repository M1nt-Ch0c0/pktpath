#ifndef PKTPATH_DEVICE_COMMON_H
#define PKTPATH_DEVICE_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "../include/pktpath_wire.h"

/* ==========================================================================
 * Common Constants & Limits
 * ========================================================================== */

#define DEV_MAX_CPUS            64
#define DEV_MAX_SITES           192
#define DEV_MAX_ADAPTERS        64
#define DEV_MAX_TOPO_DEVICES    256
#define DEV_MAX_TOPO_QDISCS     1024
#define DEV_MAX_TOPO_CLASSES    512
#define DEV_MAX_TOPO_EPOCHS     128
#define DEV_MAX_CALIBRATIONS    256
#define DEV_MAX_WARM_SOCKS      8192

/* ==========================================================================
 * Scope & Mode Enumerations
 * ========================================================================== */

enum dev_scope {
    SCOPE_TC_EGRESS = 0,
    SCOPE_IP_TX     = 1,
    SCOPE_SOCK_TX   = 2,
    SCOPE_RX_SOCK   = 3,
    SCOPE_FWD       = 4,
};

#define DEV_MAX_PLUGIN_PATHS    32
#define DEV_MAX_PLUGIN_SOCKS    16
#define DEV_MAX_PLUGIN_QDISCS   32

enum dev_mode {
    MODE_ONESHOT = 0,
    MODE_DAEMON  = 1,
};

/* ==========================================================================
 * CLI Options (inspect + record)
 * ========================================================================== */

struct dev_cli_opts {
    bool is_record;              /* false = inspect, true = record */
    bool json_output;            /* --json (inspect) */
    enum dev_mode mode;          /* --mode oneshot|daemon */
    enum dev_scope scope;        /* --scope ... */
    char dev_name[64];           /* --dev <ifname> */
    char out_dir[512];           /* --out <dir> */

    /* Structured filters */
    uint8_t  filter_proto;       /* --proto tcp(6)|udp(17)|icmp(1)|icmpv6(58), 0=any */
    uint8_t  filter_ip_ver;      /* 0=any, 4=IPv4, 6=IPv6 */
    bool     has_src_ip;
    bool     has_dst_ip;
    uint32_t src_ip4;            /* network byte order */
    uint32_t src_mask4;          /* network byte order */
    uint32_t dst_ip4;            /* network byte order */
    uint32_t dst_mask4;          /* network byte order */
    uint8_t  src_ip6[16];
    uint8_t  src_prefix6;
    uint8_t  dst_ip6[16];
    uint8_t  dst_prefix6;
    uint16_t src_port;           /* host byte order, 0=any */
    uint16_t dst_port;           /* host byte order, 0=any */
    bool     has_mark;
    uint32_t mark_val;
    uint32_t mark_mask;
    bool     has_uid;
    uint32_t uid;                /* 0xFFFFFFFF = any when !has_uid */
    uint32_t tgid;               /* 0 = any */

    /* Sampling */
    uint32_t sample_stride;      /* 1 = 1/1, N = 1/N */
    bool     sample_by_flow;     /* false = pkt, true = flow */
    char     sample_rate_str[32];

    /* Budgets & windows */
    uint32_t duration_sec;       /* --duration Ns (default 10s oneshot, 0=infinite daemon) */
    uint64_t mem_budget_bytes;   /* --mem-budget MB (default 32 MiB) */
    uint64_t disk_budget_bytes;  /* --disk-budget MB (default 128 MiB) */
    uint64_t trigger_sojourn_us; /* --trigger sojourn_us>X (0 = disabled) */
    uint32_t trigger_drop_burst; /* --trigger drop_burst>Y (0 = disabled) */
    uint32_t pre_window_sec;     /* --pre-window Ns (default 5s) */
    uint32_t post_window_sec;    /* --post-window Ns (default 5s) */

    /* Profiles & runtime plugins */
    bool     profile_sendmsg;    /* --profile sendmsg */
    int      num_plugin_paths;
    char     plugin_paths[DEV_MAX_PLUGIN_PATHS][512]; /* --plugin <file.json> */
    char     plugin_dir[512];    /* --plugin-dir <dir> */
    uint32_t capture_hdr_len;    /* --capture-hdr N (0..128) */
    bool     allow_partial;      /* --allow-partial */
};

/* ==========================================================================
 * BTF Parser Module (btf_parse.c)
 * ========================================================================== */

struct btf_db;

struct dev_btf_resolved {
    bool     loaded;
    char     error[256];

    uint32_t skb_dev;
    uint32_t skb_sk;
    uint32_t skb_len;
    uint32_t skb_data_len;
    uint32_t skb_head;
    uint32_t skb_data;
    uint32_t skb_network_header;
    uint32_t skb_transport_header;
    uint32_t skb_mac_header;
    uint32_t skb_protocol;
    uint32_t skb_pkt_type;
    uint32_t skb_hash;
    uint32_t skb_mark;
    uint32_t skb_priority;
    uint32_t skb_cb;
    uint32_t skb_tstamp;
    uint32_t skb_queue_mapping;

    uint32_t dev_ifindex;
    uint32_t dev_nd_net;
    uint32_t net_ns_inum;

    uint32_t sk_state;
    uint32_t sk_cookie;
    uint32_t sk_uid;
    uint32_t socket_sk;

    uint32_t qdisc_handle;
    uint32_t qdisc_parent;
    uint32_t netdev_queue_dev;   /* optional: struct netdev_queue.dev */
    uint32_t netdev_queue_state; /* optional: struct netdev_queue.state */

    uint32_t task_preempt_count;

    /* Optional tracepoint / netdev_queue / tc classify helpers matching bpf_btf_offsets */
    uint32_t tp_kfree_skb_reason;
    uint32_t dev_tx_queues;
    uint32_t netdev_queue_sz;
    uint32_t tcf_res_classid;
};

struct btf_db *btf_db_load(const char *path, char *err_buf, size_t err_cap);
void btf_db_free(struct btf_db *db);
int btf_resolve_all_offsets(const struct btf_db *db, struct dev_btf_resolved *out);
int btf_resolve_field(const struct btf_db *db, const char *struct_name,
                      const char *field_path, uint32_t *byte_off_out);
int btf_find_func_id(const struct btf_db *db, const char *func_name);

/* ==========================================================================
 * Kallsyms & Tracefs Kprobe Manager (kallsyms.c)
 * ========================================================================== */

struct ksym_db;

struct ksym_db *ksym_db_load(const char *path, char *err_buf, size_t err_cap);
void ksym_db_free(struct ksym_db *db);
/* Resolves exact <sym> or ThinLTO <sym>.llvm.<hash>. Returns 0 on success. */
int ksym_resolve(const struct ksym_db *db, const char *base_sym,
                 char *resolved_out, size_t resolved_cap);

const char *tracefs_root(void);
int read_boot_id(char *out, size_t cap);
/* Reaps stale .pktpath_state_<oldpid> and dead pktpath_<oldpid> kprobe groups */
int tracefs_reap_stale_groups(void);
int tracefs_write_state_file(pid_t pid, const char *group_name);
void tracefs_remove_state_file(pid_t pid);

int tracefs_register_kprobe(const char *group, const char *event_name,
                            const char *resolved_sym, bool is_retprobe);
int tracefs_unregister_kprobe(const char *group, const char *event_name);
void tracefs_unregister_group_all(const char *group);
int tracefs_read_event_id(const char *category, const char *event_name);
bool tracefs_event_exists(const char *category, const char *event_name);

struct kprobe_miss_entry {
    char     event_name[96];
    uint64_t nhit;
    uint64_t nmissed;
};
int tracefs_read_kprobe_profile(const char *group_prefix,
                                struct kprobe_miss_entry *out, int max_entries);

/* ==========================================================================
 * RTNetlink Topology Module (topo_netlink.c)
 * ========================================================================== */

struct topo_dev_entry {
    uint32_t ifindex;
    uint32_t dev_gen;
    uint16_t linktype;     /* PKT_LINKTYPE_ETHERNET (1) or PKT_LINKTYPE_RAW_IP (101) */
    uint16_t arphrd;
    uint32_t flags;
    bool     present;
    char     name[32];
};

struct topo_qdisc_entry {
    uint32_t ifindex;
    uint32_t dev_gen;
    uint64_t queue_gen;
    uint32_t handle;
    uint32_t parent;
    uint64_t bytes;
    uint32_t packets;
    uint32_t drops;
    uint32_t overlimits;
    bool     present;
    char     kind[32];
};

struct topo_class_entry {
    uint32_t ifindex;
    uint32_t dev_gen;
    uint32_t handle;      /* tcm_handle */
    uint32_t parent;      /* tcm_parent */
    uint32_t leaf;        /* tcm_info */
    uint32_t prio;
    uint32_t quantum;
    uint64_t rate_bps;    /* bits/s */
    uint64_t ceil_bps;    /* bits/s */
    uint64_t bytes;
    uint32_t packets;
    uint32_t drops;
    uint32_t overlimits;
    bool     present;
    char     kind[32];
};

struct topo_epoch_snap {
    uint32_t epoch_id;
    uint64_t ts_ns;
    uint32_t netns_inum;
    uint32_t num_devs;
    uint32_t num_qdiscs;
    uint32_t num_classes;
    struct topo_dev_entry   *devs;
    struct topo_qdisc_entry *qdiscs;
    struct topo_class_entry *classes;
};

struct topo_mgr {
    int      nl_fd;
    uint32_t netns_inum;
    uint32_t next_dev_gen;
    uint64_t next_queue_gen;
    uint32_t cur_epoch_id;
    uint64_t desync_count;

    uint32_t num_devs;
    struct topo_dev_entry devs[DEV_MAX_TOPO_DEVICES];

    uint32_t num_qdiscs;
    struct topo_qdisc_entry qdiscs[DEV_MAX_TOPO_QDISCS];

    uint32_t num_classes;
    struct topo_class_entry classes[DEV_MAX_TOPO_CLASSES];

    uint32_t num_epochs;
    struct topo_epoch_snap epochs[DEV_MAX_TOPO_EPOCHS];
};

int topo_mgr_init(struct topo_mgr *tm, char *err_buf, size_t err_cap);
void topo_mgr_destroy(struct topo_mgr *tm);
int topo_mgr_poll(struct topo_mgr *tm, bool *changed_out, bool *desync_out);
const struct topo_dev_entry *topo_find_dev_by_name(const struct topo_mgr *tm, const char *ifname);
const struct topo_dev_entry *topo_find_dev_by_ifindex(const struct topo_mgr *tm, uint32_t ifindex);
uint64_t topo_lookup_queue_gen(const struct topo_mgr *tm, uint32_t ifindex,
                               uint32_t handle, uint32_t parent);
uint64_t topo_ensure_queue_gen(struct topo_mgr *tm, uint32_t ifindex,
                               uint32_t handle, uint32_t parent, const char *fallback_kind);
bool topo_dev_has_qdisc_kind(const struct topo_mgr *tm, uint32_t ifindex, const char *kind);

/* ==========================================================================
 * Pre-existing Socket Warmup Module (proc_warmup.c)
 * ========================================================================== */

struct dev_warm_sock {
    uint64_t sk_ptr;
    uint64_t cookie;
    uint32_t tgid;
    uint32_t uid;
    char     comm[16];
};

/* Scans SOCK_DIAG + /proc/net/{tcp,tcp6,udp,udp6} + /proc/<pid>/fd.
 * Returns number of resolved kernel sk_ptr entries (>= 0). */
int proc_warmup_scan(struct dev_warm_sock *out, int max_entries);

/* ==========================================================================
 * Runtime JSON Plugin Loader (plugin_loader.c)
 * ========================================================================== */

struct dev_plugin_sock_field {
    char     plugin_id[64];
    char     struct_name[64];
    char     field_path[128];
    char     label[64];
    uint8_t  size;              /* 1, 2, 4, or 8 */
    uint8_t  role;              /* 1 = tag (TLV 0x0320+slot), 2 = tgid_fallback */
    uint32_t resolved_offset;
    bool     resolved;
    char     error[128];
};

struct dev_plugin_qdisc {
    char     plugin_id[64];
    char     adapter_id[64];
    char     name[96];
    char     kind[32];
    bool     is_leaf;           /* false = classful, true = leaf */
    char     enqueue_sym[96];
    char     dequeue_sym[96];
    int      slot_idx;          /* 0 or 1 within classful/leaf slots */
};

struct dev_plugin_registry {
    int  num_plugins;
    char plugin_ids[DEV_MAX_PLUGIN_PATHS][64];
    char plugin_names[DEV_MAX_PLUGIN_PATHS][96];
    int  num_sock_fields;
    struct dev_plugin_sock_field sock_fields[DEV_MAX_PLUGIN_SOCKS];
    int  num_qdiscs;
    struct dev_plugin_qdisc qdiscs[DEV_MAX_PLUGIN_QDISCS];
};

int plugin_registry_load(const struct dev_cli_opts *opts, const struct btf_db *btf,
                         struct dev_plugin_registry *reg, char *err_buf, size_t err_cap);

/* ==========================================================================
 * Time Helpers & Recorder Entrypoints (recorder.c)
 * ========================================================================== */

struct clock_calibration {
    uint64_t boottime_ns;
    uint64_t realtime_ns;
    uint64_t err_ns;
};

uint64_t now_boottime_ns(void);
void sample_clock_calibration(struct clock_calibration *cal);

const char *scope_to_str(enum dev_scope s);
const char *mode_to_str(enum dev_mode m);

int run_inspect(const struct dev_cli_opts *opts);
int run_record(const struct dev_cli_opts *opts);

#endif /* PKTPATH_DEVICE_COMMON_H */
