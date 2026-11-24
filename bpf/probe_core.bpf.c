#include "pktpath_bpf.h"

#define SEC(name)      __attribute__((section(name), used))
#define IN             static __attribute__((always_inline)) inline
#define offsetof(t, m) __builtin_offsetof(t, m)

/* ==================== 1. Relocated BPF Map Placeholders (0..6) ==================== */

int active_slots SEC("maps"); /* 0: PKT_MAP_ACTIVE_SLOTS (ARRAY_OF_MAPS, 2 slots) */
int control      SEC("maps"); /* 1: PKT_MAP_CONTROL      (ARRAY, 1 entry) */
int calls        SEC("maps"); /* 2: PKT_MAP_CALLS        (HASH) */
int rb           SEC("maps"); /* 3: PKT_MAP_RB           (RINGBUF) */
int socks        SEC("maps"); /* 4: PKT_MAP_SOCKS        (HASH) */
int cpu_seq      SEC("maps"); /* 5: PKT_MAP_CPU_SEQ      (ARRAY, 16 entries) */
int btf_off      SEC("maps"); /* 6: PKT_MAP_BTF_OFF      (ARRAY, 1 entry) */

/* ==================== 2. Kernel BPF Helpers ==================== */

static void *(*map_lookup)(void *, const void *) = (void *)1;
static long  (*map_update)(void *, const void *, const void *, uint64_t) = (void *)2;
static long  (*map_delete)(void *, const void *) = (void *)3;
static uint32_t (*get_cpu)(void) = (void *)8;
static uint64_t (*get_pid_tgid)(void) = (void *)14;
static long  (*get_comm)(void *, uint32_t) = (void *)16;
static uint64_t (*get_current_task)(void) = (void *)35;
static long  (*probe_read_k)(void *, uint32_t, const void *) = (void *)113;
static uint64_t (*ktime_boot_ns)(void) = (void *)125;
static void *(*rb_reserve)(void *, uint64_t, uint64_t) = (void *)131;
static void  (*rb_submit)(void *, uint64_t) = (void *)132;

#ifdef PKT_ARCH_X86_64
/* Linux x86_64 struct pt_regs (unsigned long[]):
 *   10: ax (ret), 11: cx (parm4), 12: dx (parm3), 13: si (parm2), 14: di (parm1), 19: sp.
 * On x86_64, ret pops the 8-byte return address before kretprobe runs, so sp_ret - 8 == sp_entry. */
#define PT_PARM1(r)    ((r)[14])
#define PT_PARM2(r)    ((r)[13])
#define PT_PARM3(r)    ((r)[12])
#define PT_PARM4(r)    ((r)[11])
#define PT_RC(r)       ((r)[10])
#define PT_SP_ENTRY(r) ((r)[19])
#define PT_SP_RET(r)   ((r)[19] - 8ULL)
#else
/* Linux arm64 struct user_pt_regs: regs[0..30], sp at index 31 (LR holds return addr) */
#define PT_PARM1(r)    ((r)[0])
#define PT_PARM2(r)    ((r)[1])
#define PT_PARM3(r)    ((r)[2])
#define PT_PARM4(r)    ((r)[3])
#define PT_RC(r)       ((r)[0])
#define PT_SP_ENTRY(r) ((r)[31])
#define PT_SP_RET(r)   ((r)[31])
#endif
#define BPF_ANY_FLAG     0ULL
#define BPF_NOEXIST_FLAG 1ULL

/* Linux netdev_tx_t / TC qdisc return codes */
#define NETDEV_TX_OK_RC   0
#define NETDEV_TX_BUSY_RC 0x10
#define NET_XMIT_DROP_RC  1
#define NET_XMIT_CN_RC    2

/* ==================== 3. Runtime BTF Offset Helpers ==================== */

#define OFF_OR(o, field, defval) (((o) && (o)->field) ? (o)->field : (uint32_t)(defval))

IN struct bpf_ctrl_cfg *get_ctrl(void) {
    uint32_t z = 0;
    return map_lookup(&control, &z);
}

IN struct bpf_btf_offsets *get_btf(void) {
    uint32_t z = 0;
    return map_lookup(&btf_off, &z);
}

IN int ctrl_bypass_on(const struct bpf_ctrl_cfg *c) {
    return (c->flags & PKT_CTRL_F_NO_BYPASS) == 0;
}

IN int ctrl_ringbuf_on(const struct bpf_ctrl_cfg *c) {
    return (c->flags & PKT_CTRL_F_NO_RINGBUF) == 0;
}

IN int ctrl_l1_on(const struct bpf_ctrl_cfg *c) {
    return (c->flags & PKT_CTRL_F_NO_L1_ATTR) == 0;
}

/*
 * Check task vs softirq/hardirq/NMI context via task_struct.thread_info.preempt.count.
 * NEVER read tracepoint ctx[0..7] directly (rejected by Linux BPF verifier).
 */
IN uint32_t read_irq_preempt_bits(const struct bpf_btf_offsets *off) {
#ifdef PKT_ARCH_X86_64
    if (!off || !off->task_preempt_count)
        return 0;
#endif
    uint64_t task = get_current_task();
    uint32_t pc = 0;
    uint32_t pc_off = OFF_OR(off, task_preempt_count, 16);
    if (!task || probe_read_k(&pc, sizeof(pc), (const void *)(task + pc_off)) != 0)
        return PKT_PREEMPT_IRQ_MASK;
    return pc & PKT_PREEMPT_IRQ_MASK;
}

IN uint32_t is_in_task(const struct bpf_btf_offsets *off) {
    return read_irq_preempt_bits(off) == 0;
}

/*
 * §3.4 Call pairing context ID:
 *   - in_task(): (0 | pid_tgid)
 *   - irq/softirq: (1ULL << 63) | ((uint64_t)irq_bits << 16) | cpu_id
 */
IN uint64_t make_ctx_id(const struct bpf_btf_offsets *off) {
    uint32_t irq_bits = read_irq_preempt_bits(off);
    if (irq_bits == 0)
        return get_pid_tgid();
    return (1ULL << 63) | ((uint64_t)irq_bits << 16) | (uint64_t)(get_cpu() & 0xFFFFU);
}

IN uint64_t next_cpu_seq(uint32_t cpu) {
    uint32_t idx = cpu & (PKT_MAX_CPUS - 1U);
    uint64_t *p = map_lookup(&cpu_seq, &idx);
    if (!p)
        return 0;
    uint64_t v = *p + 1ULL;
    *p = v;
    return v;
}

IN uint16_t compose_ev_flags(const struct bpf_ctrl_cfg *c, uint16_t extra) {
    if (c->flags & PKT_CTRL_F_PARTIAL_COV)
        extra |= PKT_EVF_PARTIAL_COVERAGE;
    return extra;
}

IN void read_skb_dev_ids(uint64_t skb, const struct bpf_btf_offsets *off,
                         uint32_t *ifindex_out, uint32_t *netns_out) {
    uint64_t dev = 0;
    uint32_t dev_off = OFF_OR(off, skb_dev, 16);
    *ifindex_out = 0;
    *netns_out = 0;
    if (probe_read_k(&dev, sizeof(dev), (const void *)(skb + dev_off)) != 0 || !dev)
        return;

    uint32_t ifi_off = OFF_OR(off, dev_ifindex, 216);
    probe_read_k(ifindex_out, sizeof(*ifindex_out), (const void *)(dev + ifi_off));

    uint64_t net_ptr = 0;
    uint32_t nd_off = OFF_OR(off, dev_nd_net, 1280);
    if (probe_read_k(&net_ptr, sizeof(net_ptr), (const void *)(dev + nd_off)) == 0 && net_ptr) {
        uint32_t inum_off = OFF_OR(off, net_ns_inum, 136);
        probe_read_k(netns_out, sizeof(*netns_out), (const void *)(net_ptr + inum_off));
    }
}

/* ==================== 4. A/B Double-Buffered Active Map Helpers ==================== */

IN struct bpf_active_val *lookup_active(const struct bpf_ctrl_cfg *c, uint64_t skb) {
    uint32_t s0 = c->active_slot & 1U;
    void *m0 = map_lookup(&active_slots, &s0);
    if (m0) {
        struct bpf_active_val *av = map_lookup(m0, &skb);
        if (av)
            return av;
    }
    if (c->draining_slot_active) {
        uint32_t s1 = 1U - s0;
        void *m1 = map_lookup(&active_slots, &s1);
        if (m1) {
            struct bpf_active_val *av = map_lookup(m1, &skb);
            if (av)
                return av;
        }
    }
    return 0;
}

IN int insert_active_current(struct bpf_ctrl_cfg *c, uint64_t skb,
                             struct bpf_active_val *av, uint64_t now_ns) {
    uint32_t s0 = c->active_slot & 1U;
    void *m0 = map_lookup(&active_slots, &s0);
    if (!m0)
        return -1;
    av->slot_hint = (uint8_t)s0;
    if (map_update(m0, &skb, av, BPF_NOEXIST_FLAG) != 0)
        return -1;
    uint32_t prev = __sync_fetch_and_add(&c->active_tracked_count, 1);
    if (prev == 0)
        c->last_idle_exit_ns = now_ns;
    return 0;
}

IN int delete_active(struct bpf_ctrl_cfg *c, uint64_t skb) {
    uint32_t s0 = c->active_slot & 1U;
    void *m0 = map_lookup(&active_slots, &s0);
    if (m0 && map_delete(m0, &skb) == 0) {
        __sync_fetch_and_sub(&c->active_tracked_count, 1);
        return 0;
    }
    if (c->draining_slot_active) {
        uint32_t s1 = 1U - s0;
        void *m1 = map_lookup(&active_slots, &s1);
        if (m1 && map_delete(m1, &skb) == 0) {
            __sync_fetch_and_sub(&c->active_tracked_count, 1);
            return 0;
        }
    }
    return -1;
}

/* ==================== 5. Ringbuf Event Emitters (Zero Stack Copy) ==================== */

IN void emit_object(struct bpf_ctrl_cfg *c, uint16_t site, uint64_t ts_ns,
                    uint64_t obj_id, uint64_t sample_id,
                    uint16_t end_reason, uint32_t drop_reason, uint16_t ev_flags) {
    if (!ctrl_ringbuf_on(c))
        return;
    uint32_t cpu = get_cpu();
    uint64_t seq = next_cpu_seq(cpu);
    struct bpf_ev_object *ev = rb_reserve(&rb, sizeof(*ev), 0);
    if (!ev) {
        __sync_fetch_and_add(&c->rb_drops, 1);
        return;
    }
    ev->h.kind = PKT_EV_OBJECT;
    ev->h.object_type = PKT_OBJ_SKB;
    ev->h.evidence_level = PKT_EVID_DIRECT;
    ev->h.site_dict_idx = site;
    ev->h.flags = compose_ev_flags(c, ev_flags);
    ev->h.cpu = cpu;
    ev->h.reserved = 0;
    ev->h.seq = seq;
    ev->h.ts_ns = ts_ns;
    ev->object_id = obj_id;
    ev->sample_id = sample_id;
    ev->drop_reason = drop_reason;
    ev->end_reason = end_reason;
    ev->reserved = 0;
    rb_submit(ev, 0);
}

IN void emit_step(struct bpf_ctrl_cfg *c, uint16_t site, uint64_t ts_ns,
                  uint64_t obj_id, uint64_t vc_id,
                  uint32_t netns_inum, uint32_t ifindex,
                  uint32_t qh, uint32_t qp, uint32_t classid,
                  int32_t raw_ret, uint32_t ctx_tid, uint16_t txq,
                  uint8_t dir, uint8_t stage, uint16_t ev_flags) {
    if (!ctrl_ringbuf_on(c))
        return;
    uint32_t cpu = get_cpu();
    uint64_t seq = next_cpu_seq(cpu);
    struct bpf_ev_step *ev = rb_reserve(&rb, sizeof(*ev), 0);
    if (!ev) {
        __sync_fetch_and_add(&c->rb_drops, 1);
        return;
    }
    ev->h.kind = PKT_EV_STEP;
    ev->h.object_type = PKT_OBJ_SKB;
    ev->h.evidence_level = PKT_EVID_DIRECT;
    ev->h.site_dict_idx = site;
    ev->h.flags = compose_ev_flags(c, ev_flags);
    ev->h.cpu = cpu;
    ev->h.reserved = 0;
    ev->h.seq = seq;
    ev->h.ts_ns = ts_ns;
    ev->object_id = obj_id;
    ev->visit_or_call_id = vc_id;
    ev->netns_inum = netns_inum;
    ev->ifindex = ifindex;
    ev->qdisc_handle = qh;
    ev->qdisc_parent = qp;
    ev->classid = classid;
    ev->raw_ret = raw_ret;
    ev->ctx_tid = ctx_tid;
    ev->txq = txq;
    ev->dir = dir;
    ev->stage = stage;
    rb_submit(ev, 0);
}

IN void emit_rel(struct bpf_ctrl_cfg *c, uint16_t site, uint64_t ts_ns,
                 uint64_t op_id, uint64_t src_obj, uint64_t dst_obj,
                 uint8_t rel_type, uint8_t rel_flags) {
    if (!ctrl_ringbuf_on(c))
        return;
    uint32_t cpu = get_cpu();
    uint64_t seq = next_cpu_seq(cpu);
    struct bpf_ev_rel *ev = rb_reserve(&rb, sizeof(*ev), 0);
    if (!ev) {
        __sync_fetch_and_add(&c->rb_drops, 1);
        return;
    }
    ev->h.kind = PKT_EV_RELATION;
    ev->h.object_type = PKT_OBJ_SKB;
    ev->h.evidence_level = PKT_EVID_DIRECT;
    ev->h.site_dict_idx = site;
    ev->h.flags = compose_ev_flags(c, 0);
    ev->h.cpu = cpu;
    ev->h.reserved = 0;
    ev->h.seq = seq;
    ev->h.ts_ns = ts_ns;
    ev->op_id = op_id;
    ev->src_object_id = src_obj;
    ev->dst_object_id = dst_obj;
    ev->stream_offset = 0;
    ev->span_len = 0;
    ev->rel_type = rel_type;
    ev->rel_flags = rel_flags;
    ev->reserved = 0;
    rb_submit(ev, 0);
}

IN void emit_quality(struct bpf_ctrl_cfg *c, uint16_t site, uint64_t ts_ns,
                     uint8_t qual_kind, uint16_t qual_site,
                     uint64_t obj_id, uint64_t count) {
    if (!ctrl_ringbuf_on(c))
        return;
    uint32_t cpu = get_cpu();
    uint64_t seq = next_cpu_seq(cpu);
    struct bpf_ev_quality *ev = rb_reserve(&rb, sizeof(*ev), 0);
    if (!ev) {
        __sync_fetch_and_add(&c->rb_drops, 1);
        return;
    }
    ev->h.kind = PKT_EV_QUALITY;
    ev->h.object_type = PKT_OBJ_SKB;
    ev->h.evidence_level = PKT_EVID_GAP;
    ev->h.site_dict_idx = site;
    ev->h.flags = compose_ev_flags(c, 0);
    ev->h.cpu = cpu;
    ev->h.reserved = 0;
    ev->h.seq = seq;
    ev->h.ts_ns = ts_ns;
    ev->object_id = obj_id;
    ev->win_start_ns = ts_ns;
    ev->win_end_ns = ts_ns;
    ev->count = count;
    ev->qual_site_idx = qual_site;
    ev->qual_kind = qual_kind;
    ev->reserved2 = 0;
    ev->reserved3 = 0;
    rb_submit(ev, 0);
}

/* ==================== 6. L1 Socket Ownership & Pluggable Sock-Field Extensions ==================== */

IN void populate_sock_plugins_raw(uint64_t sk, const struct bpf_btf_offsets *off,
                                  uint32_t *tgid_io, uint64_t *vals_out, uint32_t *mask_io) {
    (void)tgid_io;
    if (!off || !sk)
        return;
    uint32_t n = off->sock_plugin_count;
    if (n > PKT_MAX_SOCK_PLUGINS)
        n = PKT_MAX_SOCK_PLUGINS;
    if (n == 0U)
        return;
#pragma clang loop unroll(disable)
    for (uint32_t i = 0; i < PKT_MAX_SOCK_PLUGINS; i++) {
        if (i >= n)
            break;
        uint32_t foff = off->sock_plugins[i].offset;
        uint32_t fsz  = off->sock_plugins[i].size;
        uint64_t v = 0;
        probe_read_k(&v, 8, (const void *)(sk + (uint64_t)foff));
        uint32_t sh = ((8U - (fsz & 7U)) & 7U) << 3;
        vals_out[i] = (v << sh) >> sh;
    }
    *mask_io |= off->sock_plugin_valid_mask;
}

IN void populate_sock_plugins(uint64_t sk, const struct bpf_ctrl_cfg *c,
                              const struct bpf_btf_offsets *off,
                              struct bpf_sock_owner *val) {
    if (!(c->flags & PKT_CTRL_F_SOCK_PLUGINS) || !off || !sk)
        return;
    uint32_t p_tgid = val->plugin_tgid;
    uint32_t p_mask = val->plugin_mask;
    populate_sock_plugins_raw(sk, off, &p_tgid, val->plugin_vals, &p_mask);
    val->plugin_tgid = p_tgid;
    val->plugin_mask = p_mask;
    if (p_tgid || p_mask)
        val->flags |= PKT_SOCK_F_HAS_PLUGINS;
}

IN void record_sock_owner(uint64_t sk) {
    if (!sk)
        return;
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c || !ctrl_l1_on(c))
        return;
    const struct bpf_btf_offsets *off = get_btf();

    uint8_t state = 0;
    uint32_t st_off = OFF_OR(off, sk_state, 18);
    if (probe_read_k(&state, sizeof(state), (const void *)(sk + st_off)) != 0)
        return;
    if (state == 6 || state == 12) /* TCP_TIME_WAIT / TCP_NEW_SYN_RECV */
        return;

    struct bpf_sock_owner val = {};
    uint32_t ck_off = OFF_OR(off, sk_cookie, 88);
    uint32_t uid_off = OFF_OR(off, sk_uid, 576);
    probe_read_k(&val.cookie, sizeof(val.cookie), (const void *)(sk + ck_off));
    probe_read_k(&val.uid, sizeof(val.uid), (const void *)(sk + uid_off));
    val.tgid = (uint32_t)(get_pid_tgid() >> 32);
    get_comm(val.comm, sizeof(val.comm));
    val.flags = PKT_SOCK_F_HAS_OWNER;
    populate_sock_plugins(sk, c, off, &val);

    map_update(&socks, &sk, &val, BPF_ANY_FLAG);
}

IN struct bpf_sock_owner *lookup_sock_owner(uint64_t sk_ptr, uint64_t ck) {
    struct bpf_sock_owner *so = map_lookup(&socks, &sk_ptr);
    if (so) {
        if (so->cookie == 0 || ck == 0 || so->cookie == ck)
            return so;
        return 0;
    }
    /* Fallback for pre-existing sockets warmed up via NETLINK_SOCK_DIAG under kptr_restrict=2 */
    if (ck != 0 && ck < 0xFFFF000000000000ULL) {
        so = map_lookup(&socks, &ck);
        if (so && so->cookie == ck)
            return so;
    }
    return 0;
}

IN void record_sock_sendmsg(uint64_t sk) {
    if (!sk)
        return;
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c || !(c->flags & PKT_CTRL_F_SENDMSG))
        return;
    const struct bpf_btf_offsets *off = get_btf();

    uint64_t ck = 0;
    uint32_t ck_off = OFF_OR(off, sk_cookie, 88);
    probe_read_k(&ck, sizeof(ck), (const void *)(sk + ck_off));

    uint64_t pt = get_pid_tgid();
    uint64_t now = ktime_boot_ns();

    struct bpf_sock_owner *so = lookup_sock_owner(sk, ck);
    if (so) {
        if (so->cookie == 0 && ck != 0)
            so->cookie = ck;
        so->last_send_tid = (uint32_t)pt;
        so->last_send_ts_ns = now;
        so->flags |= PKT_SOCK_F_HAS_SENDMSG;
        if (!(so->flags & PKT_SOCK_F_HAS_OWNER) && so->tgid == 0) {
            so->tgid = (uint32_t)(pt >> 32);
            get_comm(so->comm, sizeof(so->comm));
            so->flags |= PKT_SOCK_F_HAS_OWNER;
        }
        if ((c->flags & PKT_CTRL_F_SOCK_PLUGINS) && !(so->flags & PKT_SOCK_F_HAS_PLUGINS))
            populate_sock_plugins(sk, c, off, so);
        return;
    }

    struct bpf_sock_owner nv = {};
    uint32_t uid_off = OFF_OR(off, sk_uid, 576);
    nv.cookie = ck;
    probe_read_k(&nv.uid, sizeof(nv.uid), (const void *)(sk + uid_off));
    nv.tgid = (uint32_t)(pt >> 32);
    nv.last_send_tid = (uint32_t)pt;
    nv.last_send_ts_ns = now;
    get_comm(nv.comm, sizeof(nv.comm));
    nv.flags = PKT_SOCK_F_HAS_OWNER | PKT_SOCK_F_HAS_SENDMSG;
    populate_sock_plugins(sk, c, off, &nv);
    map_update(&socks, &sk, &nv, BPF_ANY_FLAG);
}

SEC("tp_sock_create")
int prog_tp_sock_create(uint64_t *regs) {
    uint64_t sock = PT_PARM1(regs);
    if (!sock)
        return 0;
    const struct bpf_btf_offsets *off = get_btf();
    uint64_t sk = 0;
    uint32_t sk_off = OFF_OR(off, socket_sk, 24);
    if (probe_read_k(&sk, sizeof(sk), (const void *)(sock + sk_off)) != 0 || !sk)
        return 0;
    record_sock_owner(sk);
    return 0;
}

SEC("kp_tcp_v4_conn")
int prog_kp_tcp_v4_conn(uint64_t *regs) {
    record_sock_owner(PT_PARM1(regs));
    return 0;
}

SEC("kp_tcp_v6_conn")
int prog_kp_tcp_v6_conn(uint64_t *regs) {
    record_sock_owner(PT_PARM1(regs));
    return 0;
}

SEC("kr_inet_accept")
int prog_kr_inet_accept(uint64_t *regs) {
    record_sock_owner(PT_RC(regs));
    return 0;
}

SEC("kp_sk_destruct")
int prog_kp_sk_destruct(uint64_t *regs) {
    uint64_t sk = PT_PARM1(regs);
    if (sk) {
        map_delete(&socks, &sk);
        const struct bpf_btf_offsets *off = get_btf();
        uint64_t ck = 0;
        if (probe_read_k(&ck, sizeof(ck), (const void *)(sk + OFF_OR(off, sk_cookie, 88))) == 0 &&
            ck != 0 && ck < 0xFFFF000000000000ULL) {
            map_delete(&socks, &ck);
        }
    }
    return 0;
}

SEC("kp_tcp_sendmsg")
int prog_kp_tcp_sendmsg(uint64_t *regs) {
    record_sock_sendmsg(PT_PARM1(regs));
    return 0;
}

SEC("kp_udp_sendmsg")
int prog_kp_udp_sendmsg(uint64_t *regs) {
    record_sock_sendmsg(PT_PARM1(regs));
    return 0;
}

/* ==================== 7. Packet Header Parsing, Structured Filter & Summary ==================== */

struct parsed_pkt {
    uint64_t data_ptr;
    uint64_t sk_ptr;
    uint32_t netns_inum;
    uint32_t ifindex;
    uint32_t pkt_len;
    uint32_t linear_len;
    uint32_t skb_hash;
    uint32_t skb_mark;
    uint32_t skb_priority;
    uint32_t uid;
    uint32_t tcp_seq;
    uint32_t tcp_seq_end;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t ip_id;
    uint16_t linktype;
    uint8_t  ip_version;
    uint8_t  l4_proto;
    uint8_t  tcp_flags;
    uint8_t  frag_flags;
    uint8_t  has_l3;
    uint8_t  has_l4;
    uint8_t  has_tcp;
    uint8_t  has_uid;
    uint8_t  nonlin_trunc;
    uint8_t  pad[3];
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
};

IN void parse_skb(uint64_t skb, uint32_t fallback_len,
                  uint32_t known_ifindex, uint32_t known_netns,
                  const struct bpf_btf_offsets *off,
                  struct parsed_pkt *p) {
    __builtin_memset(p, 0, sizeof(*p));
    p->ifindex = known_ifindex;
    p->netns_inum = known_netns;

    uint32_t len = 0, data_len = 0;
    probe_read_k(&len, 4, (const void *)(skb + OFF_OR(off, skb_len, 112)));
    probe_read_k(&data_len, 4, (const void *)(skb + OFF_OR(off, skb_data_len, 116)));
    if (len == 0)
        len = fallback_len;
    p->pkt_len = len;
    p->linear_len = (len >= data_len) ? (len - data_len) : 0;

    probe_read_k(&p->skb_hash, 4, (const void *)(skb + OFF_OR(off, skb_hash, 164)));
    probe_read_k(&p->skb_mark, 4, (const void *)(skb + OFF_OR(off, skb_mark, 168)));
    probe_read_k(&p->skb_priority, 4, (const void *)(skb + OFF_OR(off, skb_priority, 156)));

    /* Read sk & sk_uid (exclude TIME_WAIT=6 and NEW_SYN_RECV=12) */
    uint64_t sk = 0;
    if (probe_read_k(&sk, 8, (const void *)(skb + OFF_OR(off, skb_sk, 24))) == 0 && sk) {
        uint8_t st = 0;
        if (probe_read_k(&st, 1, (const void *)(sk + OFF_OR(off, sk_state, 18))) == 0 &&
            st != 6 && st != 12) {
            p->sk_ptr = sk;
            if (probe_read_k(&p->uid, 4, (const void *)(sk + OFF_OR(off, sk_uid, 576))) == 0)
                p->has_uid = 1;
        }
    }

    uint64_t head = 0, data = 0;
    uint16_t net_hdr = 0;
    probe_read_k(&head, 8, (const void *)(skb + OFF_OR(off, skb_head, 216)));
    probe_read_k(&data, 8, (const void *)(skb + OFF_OR(off, skb_data, 224)));
    probe_read_k(&net_hdr, 2, (const void *)(skb + OFF_OR(off, skb_network_header, 196)));
    p->data_ptr = data;
    p->linktype = PKT_LINKTYPE_ETH;

    if (!data || p->linear_len == 0) {
        if (data_len > 0)
            p->nonlin_trunc = 1;
        return;
    }

    uint8_t buf[40];
    __builtin_memset(buf, 0, sizeof(buf));

    uint64_t l3_ptr = 0;
    uint32_t l3_avail = 0;

    if (head && net_hdr != 0 && net_hdr != 0xFFFFU) {
        uint64_t cand = head + (uint64_t)net_hdr;
        if (cand >= data && cand < data + (uint64_t)p->linear_len) {
            l3_ptr = cand;
            l3_avail = (uint32_t)((data + (uint64_t)p->linear_len) - cand);
            p->linktype = (cand > data) ? PKT_LINKTYPE_ETH : PKT_LINKTYPE_RAW_IP;
        }
    }

    if (!l3_ptr) {
        if (p->linear_len >= 14 && probe_read_k(buf, 18, (const void *)data) == 0) {
            uint16_t eth_p = ((uint16_t)buf[12] << 8) | buf[13];
            if (eth_p == 0x0800U || eth_p == 0x86DDU) {
                p->linktype = PKT_LINKTYPE_ETH;
                l3_ptr = data + 14;
                l3_avail = p->linear_len - 14;
            } else if ((eth_p == 0x8100U || eth_p == 0x88A8U) && p->linear_len >= 18) {
                uint16_t inner_p = ((uint16_t)buf[16] << 8) | buf[17];
                if (inner_p == 0x0800U || inner_p == 0x86DDU) {
                    p->linktype = PKT_LINKTYPE_ETH;
                    l3_ptr = data + 18;
                    l3_avail = p->linear_len - 18;
                }
            }
        }
        if (!l3_ptr && p->linear_len >= 20 && probe_read_k(buf, 1, (const void *)data) == 0) {
            uint8_t ver = buf[0] >> 4;
            if (ver == 4 || ver == 6) {
                p->linktype = PKT_LINKTYPE_RAW_IP;
                l3_ptr = data;
                l3_avail = p->linear_len;
            }
        }
    }

    if (!l3_ptr || l3_avail < 20) {
        if (data_len > 0)
            p->nonlin_trunc = 1;
        return;
    }

    uint64_t l4_ptr = 0;
    uint32_t l4_avail = 0;
    uint32_t ip_payload_len = 0;

    if (probe_read_k(buf, 20, (const void *)l3_ptr) != 0)
        return;

    uint8_t ip_ver = buf[0] >> 4;
    if (ip_ver == 4) {
        uint32_t ihl = (uint32_t)(buf[0] & 0x0FU) * 4U;
        if (ihl < 20 || l3_avail < ihl) {
            p->nonlin_trunc = 1;
            return;
        }
        uint16_t tot_len = ((uint16_t)buf[2] << 8) | buf[3];
        uint16_t frag_w  = ((uint16_t)buf[6] << 8) | buf[7];
        p->ip_version = 4;
        p->has_l3 = 1;
        p->l4_proto = buf[9];
        p->ip_id = ((uint16_t)buf[4] << 8) | buf[5];
        if (frag_w & 0x2000U)
            p->frag_flags |= PKT_FRAG_F_MORE;
        if (frag_w & 0x4000U)
            p->frag_flags |= PKT_FRAG_F_DONT;
        if (frag_w & 0x1FFFU)
            p->frag_flags |= PKT_FRAG_F_NON_FIRST;
        __builtin_memcpy(p->src_ip, &buf[12], 4);
        __builtin_memcpy(p->dst_ip, &buf[16], 4);
        l4_ptr = l3_ptr + ihl;
        l4_avail = l3_avail - ihl;
        ip_payload_len = (tot_len >= ihl) ? ((uint32_t)tot_len - ihl) : 0;
    } else if (ip_ver == 6) {
        if (l3_avail < 40 || probe_read_k(buf, 40, (const void *)l3_ptr) != 0) {
            p->nonlin_trunc = 1;
            return;
        }
        uint16_t plen = ((uint16_t)buf[4] << 8) | buf[5];
        uint8_t nh = buf[6];
        p->ip_version = 6;
        p->has_l3 = 1;
        __builtin_memcpy(p->src_ip, &buf[8], 16);
        __builtin_memcpy(p->dst_ip, &buf[24], 16);
        l4_ptr = l3_ptr + 40;
        l4_avail = l3_avail - 40;
        ip_payload_len = plen;

        /* Unwrap IPv6 Fragment Extension Header (nexthdr == 44) */
        if (nh == 44) {
            if (l4_avail < 8 || probe_read_k(buf, 8, (const void *)l4_ptr) != 0) {
                p->nonlin_trunc = 1;
                p->l4_proto = nh;
                return;
            }
            nh = buf[0];
            uint16_t fw = ((uint16_t)buf[2] << 8) | buf[3];
            p->ip_id = ((uint16_t)buf[6] << 8) | buf[7];
            if (fw & 0x0001U)
                p->frag_flags |= PKT_FRAG_F_MORE;
            if (fw & 0xFFF8U)
                p->frag_flags |= PKT_FRAG_F_NON_FIRST;
            l4_ptr += 8;
            l4_avail -= 8;
            ip_payload_len = (ip_payload_len >= 8) ? (ip_payload_len - 8) : 0;
        }
        p->l4_proto = nh;
    } else {
        return;
    }

    if (p->frag_flags & PKT_FRAG_F_NON_FIRST)
        return;

    if (p->l4_proto == 6) { /* TCP */
        if (l4_avail < 20 || probe_read_k(buf, 20, (const void *)l4_ptr) != 0) {
            p->nonlin_trunc = 1;
            return;
        }
        p->src_port = ((uint16_t)buf[0] << 8) | buf[1];
        p->dst_port = ((uint16_t)buf[2] << 8) | buf[3];
        p->tcp_seq = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                     ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];
        uint32_t doff = (uint32_t)(buf[12] >> 4) * 4U;
        p->tcp_flags = buf[13];
        uint32_t seg = (doff >= 20 && ip_payload_len >= doff) ? (ip_payload_len - doff) : 0;
        p->tcp_seq_end = p->tcp_seq + seg;
        p->has_l4 = 1;
        p->has_tcp = 1;
    } else if (p->l4_proto == 17 || p->l4_proto == 136 || p->l4_proto == 132) { /* UDP/UDPLite/SCTP */
        if (l4_avail < 4 || probe_read_k(buf, 4, (const void *)l4_ptr) != 0) {
            p->nonlin_trunc = 1;
            return;
        }
        p->src_port = ((uint16_t)buf[0] << 8) | buf[1];
        p->dst_port = ((uint16_t)buf[2] << 8) | buf[3];
        p->has_l4 = 1;
    } else if (p->l4_proto == 1 || p->l4_proto == 58) { /* ICMP / ICMPv6 */
        if (l4_avail < 4) {
            p->nonlin_trunc = 1;
            return;
        }
        p->has_l4 = 1;
    }
}

/*
 * L3/L4 filter evaluation (after early ifindex/netns/mark/uid/tgid checks):
 *   returns  1 : matched
 *   returns  0 : definitively mismatched
 *   returns -1 : cannot evaluate due to non-first fragment or linear truncation
 */
IN int eval_l3_l4_filter(const struct bpf_ctrl_cfg *c, const struct parsed_pkt *p,
                         int has_s6, int has_d6) {
    int need_l3 = (c->filter_ip_ver != 0) || (c->filter_proto != 0) ||
                  (c->filter_src_ip4_mask != 0) || (c->filter_dst_ip4_mask != 0) ||
                  has_s6 || has_d6;
    int need_ports = (c->filter_src_port != 0) || (c->filter_dst_port != 0);

    if (need_l3 || need_ports) {
        if (!p->has_l3)
            return p->nonlin_trunc ? -1 : 0;
    }

    if (c->filter_ip_ver && p->ip_version != c->filter_ip_ver)
        return 0;
    if (c->filter_proto && p->l4_proto != c->filter_proto)
        return 0;

    if (c->filter_src_ip4_mask) {
        if (p->ip_version != 4)
            return 0;
        uint32_t s4 = 0;
        __builtin_memcpy(&s4, p->src_ip, 4);
        if ((s4 & c->filter_src_ip4_mask) != (c->filter_src_ip4 & c->filter_src_ip4_mask))
            return 0;
    }
    if (c->filter_dst_ip4_mask) {
        if (p->ip_version != 4)
            return 0;
        uint32_t d4 = 0;
        __builtin_memcpy(&d4, p->dst_ip, 4);
        if ((d4 & c->filter_dst_ip4_mask) != (c->filter_dst_ip4 & c->filter_dst_ip4_mask))
            return 0;
    }
    if (has_s6) {
        if (p->ip_version != 6)
            return 0;
        const uint32_t *ps6 = (const uint32_t *)p->src_ip;
        const uint32_t *fs6 = (const uint32_t *)c->filter_src_ip6;
        const uint32_t *sm6 = (const uint32_t *)c->filter_src_ip6_mask;
        if (((ps6[0] ^ fs6[0]) & sm6[0]) || ((ps6[1] ^ fs6[1]) & sm6[1]) ||
            ((ps6[2] ^ fs6[2]) & sm6[2]) || ((ps6[3] ^ fs6[3]) & sm6[3]))
            return 0;
    }
    if (has_d6) {
        if (p->ip_version != 6)
            return 0;
        const uint32_t *pd6 = (const uint32_t *)p->dst_ip;
        const uint32_t *fd6 = (const uint32_t *)c->filter_dst_ip6;
        const uint32_t *dm6 = (const uint32_t *)c->filter_dst_ip6_mask;
        if (((pd6[0] ^ fd6[0]) & dm6[0]) || ((pd6[1] ^ fd6[1]) & dm6[1]) ||
            ((pd6[2] ^ fd6[2]) & dm6[2]) || ((pd6[3] ^ fd6[3]) & dm6[3]))
            return 0;
    }

    if (need_ports) {
        if (p->frag_flags & PKT_FRAG_F_NON_FIRST)
            return -1;
        if (!p->has_l4)
            return p->nonlin_trunc ? -1 : 0;
        if (c->filter_src_port && p->src_port != c->filter_src_port)
            return 0;
        if (c->filter_dst_port && p->dst_port != c->filter_dst_port)
            return 0;
    }

    return 1;
}

/* FNV-1a + Jenkins mix over 5-tuple for consistent --sample-by flow */
IN uint32_t hash_flow_5tuple(const struct parsed_pkt *p) {
    uint32_t h = 2166136261U;
    const uint32_t *s32 = (const uint32_t *)p->src_ip;
    const uint32_t *d32 = (const uint32_t *)p->dst_ip;
    h = (h ^ s32[0]) * 16777619U;
    h = (h ^ s32[1]) * 16777619U;
    h = (h ^ s32[2]) * 16777619U;
    h = (h ^ s32[3]) * 16777619U;
    h = (h ^ d32[0]) * 16777619U;
    h = (h ^ d32[1]) * 16777619U;
    h = (h ^ d32[2]) * 16777619U;
    h = (h ^ d32[3]) * 16777619U;
    uint32_t ports = ((uint32_t)p->src_port << 16) | (uint32_t)p->dst_port;
    h = (h ^ ports) * 16777619U;
    h = (h ^ (((uint32_t)p->ip_version << 8) | p->l4_proto)) * 16777619U;
    h ^= h >> 16;
    h *= 0x85ebca6bU;
    h ^= h >> 13;
    return h;
}

IN void emit_summary_from_parsed(struct bpf_ctrl_cfg *c, const struct bpf_btf_offsets *off,
                                 uint16_t site, uint64_t ts_ns, uint64_t obj_id,
                                 const struct parsed_pkt *p, uint8_t dir,
                                 uint32_t in_task, uint64_t pid_tgid) {
    if (!ctrl_ringbuf_on(c))
        return;

    uint32_t cpu = get_cpu();
    uint64_t seq = next_cpu_seq(cpu);
    struct bpf_ev_summary *sm = rb_reserve(&rb, sizeof(*sm), 0);
    if (!sm) {
        __sync_fetch_and_add(&c->rb_drops, 1);
        return;
    }

    __builtin_memset(sm, 0, offsetof(struct bpf_ev_summary, hdr_bytes));

    uint16_t evf = 0;
    if (in_task)
        evf |= PKT_EVF_IN_TASK;
    if (p->nonlin_trunc)
        evf |= PKT_EVF_NONLINEAR_TRUNC;

    sm->h.kind = PKT_EV_SUMMARY;
    sm->h.object_type = PKT_OBJ_SKB;
    sm->h.evidence_level = PKT_EVID_DIRECT;
    sm->h.site_dict_idx = site;
    sm->h.flags = compose_ev_flags(c, evf);
    sm->h.cpu = cpu;
    sm->h.seq = seq;
    sm->h.ts_ns = ts_ns;

    sm->object_id = obj_id;
    sm->netns_inum = p->netns_inum;
    sm->ifindex = p->ifindex;
    sm->pkt_len = p->pkt_len;
    sm->linear_len = p->linear_len;
    sm->skb_hash = p->skb_hash;
    sm->skb_mark = p->skb_mark;
    sm->skb_priority = p->skb_priority;
    sm->tcp_seq = p->tcp_seq;
    sm->tcp_seq_end = p->tcp_seq_end;
    sm->src_port = p->src_port;
    sm->dst_port = p->dst_port;
    sm->ip_id = p->ip_id;
    sm->linktype = p->linktype;
    sm->dir = dir;
    sm->ip_version = p->ip_version;
    sm->l4_proto = p->l4_proto;
    sm->tcp_flags = p->tcp_flags;
    sm->frag_flags = p->frag_flags;
    __builtin_memcpy(sm->src_ip, p->src_ip, 16);
    __builtin_memcpy(sm->dst_ip, p->dst_ip, 16);

    uint32_t vflags = 0;
    if (p->has_l3)
        vflags |= PKT_SUM_F_L3;
    if (p->has_l4)
        vflags |= PKT_SUM_F_L4;
    if (p->has_tcp)
        vflags |= PKT_SUM_F_TCP;

    if (ctrl_l1_on(c)) {
        if (in_task) {
            sm->enqueue_tid = (uint32_t)pid_tgid;
            vflags |= PKT_SUM_F_TID;
        }
        if (p->has_uid) {
            sm->uid = p->uid;
            vflags |= PKT_SUM_F_UID;
        }
        if (p->sk_ptr) {
            uint64_t ck = 0;
            probe_read_k(&ck, 8, (const void *)(p->sk_ptr + OFF_OR(off, sk_cookie, 88)));
            struct bpf_sock_owner *so = lookup_sock_owner(p->sk_ptr, ck);
            if (so) {
                if (so->cookie == 0 && ck != 0)
                    so->cookie = ck;
                if (so->tgid) {
                    sm->tgid = so->tgid;
                    __builtin_memcpy(sm->comm, so->comm, 16);
                    vflags |= PKT_SUM_F_TGID | PKT_SUM_F_COMM;
                }
                if ((c->flags & PKT_CTRL_F_SENDMSG) && (so->flags & PKT_SOCK_F_HAS_SENDMSG)) {
                    sm->enqueue_tid = so->last_send_tid;
                    sm->skb_create_ts = so->last_send_ts_ns;
                    vflags |= PKT_SUM_F_TID | PKT_SUM_F_CREATE_TS;
                }
                if (c->flags & PKT_CTRL_F_SOCK_PLUGINS) {
                    /* Refresh from live struct sock in case fields were set after socket creation (e.g. setsockopt / DPI) */
                    populate_sock_plugins(p->sk_ptr, c, off, so);
                    if (!sm->tgid && so->plugin_tgid) {
                        sm->tgid = so->plugin_tgid;
                        vflags |= PKT_SUM_F_TGID;
                    }
                    if (so->plugin_mask) {
                        sm->plugin_mask = so->plugin_mask;
                        __builtin_memcpy(sm->plugin_vals, so->plugin_vals, sizeof(sm->plugin_vals));
                        vflags |= PKT_SUM_F_PLUGIN_VALS;
                    }
                }
            } else if (in_task) {
                /* Lazy populate sock_owner_map for pre-existing long-lived sockets */
                sm->tgid = (uint32_t)(pid_tgid >> 32);
                get_comm(sm->comm, sizeof(sm->comm));
                vflags |= PKT_SUM_F_TGID | PKT_SUM_F_COMM;

                struct bpf_sock_owner nv = {};
                nv.cookie = ck;
                nv.uid = p->uid;
                nv.tgid = sm->tgid;
                __builtin_memcpy(nv.comm, sm->comm, 16);
                nv.flags = PKT_SOCK_F_HAS_OWNER;
                populate_sock_plugins(p->sk_ptr, c, off, &nv);
                if (nv.plugin_mask) {
                    sm->plugin_mask = nv.plugin_mask;
                    __builtin_memcpy(sm->plugin_vals, nv.plugin_vals, sizeof(sm->plugin_vals));
                    vflags |= PKT_SUM_F_PLUGIN_VALS;
                }
                map_update(&socks, &p->sk_ptr, &nv, BPF_ANY_FLAG);
            } else if ((c->flags & PKT_CTRL_F_SOCK_PLUGINS) && off) {
                /* Direct plugin fallback in softirq when sock_owner_map missed */
                uint32_t p_tgid = 0;
                uint32_t p_mask = 0;
                populate_sock_plugins_raw(p->sk_ptr, off, &p_tgid, sm->plugin_vals, &p_mask);
                if (p_tgid && !sm->tgid) {
                    sm->tgid = p_tgid;
                    vflags |= PKT_SUM_F_TGID;
                }
                if (p_mask) {
                    sm->plugin_mask = p_mask;
                    vflags |= PKT_SUM_F_PLUGIN_VALS;
                }
            }
        }
    }

    /* Optional bounded packet header capture (<= 128 B) directly into ringbuf */
    uint64_t cap = c->capture_hdr_len;
    if (cap > 0 && p->data_ptr && p->linear_len > 0) {
        if (cap > (uint64_t)p->linear_len)
            cap = (uint64_t)p->linear_len;
        if (cap > PKT_MAX_SNAP_LEN)
            cap = PKT_MAX_SNAP_LEN;
        asm volatile("" : "+r"(cap));
        if (cap > 0 && cap <= PKT_MAX_SNAP_LEN) {
            if (probe_read_k(sm->hdr_bytes, (uint32_t)cap, (const void *)p->data_ptr) == 0) {
                sm->hdr_cap_len = (uint8_t)cap;
                vflags |= PKT_SUM_F_HDR_BYTES;
            }
        }
    }

    sm->valid_flags = vflags;
    rb_submit(sm, 0);
}

/* ==================== 8. L2 Entry State Machine: tp_net_dev_queue ==================== */

SEC("tp_net_dev_queue")
int prog_tp_net_dev_queue(uint8_t *ctx) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c)
        return 0;

    const struct bpf_btf_offsets *off = get_btf();
    uint64_t skb = *(uint64_t *)(ctx + 8);
    uint32_t tp_len = *(uint32_t *)(ctx + 16);
    uint64_t now = ktime_boot_ns();

    uint32_t ifindex = 0, netns = 0;
    read_skb_dev_ids(skb, off, &ifindex, &netns);
    uint32_t in_task = 0;
    uint64_t pt = 0;
    uint64_t reentry_obj_id = 0;
    int has_s6 = 0;
    int has_d6 = 0;
    int pre_sampled = 0;

    /* Step 1: Check existing active object (legal re-entry vs stale conflict vs quarantine) */
    struct bpf_active_val *av = 0;
    if (!ctrl_bypass_on(c) || c->active_tracked_count > 0)
        av = lookup_active(c, skb);

    /*
     * Step 1b: Synchronous stacked virtual netdev handoff (e.g. VLAN pfvlan -> pfx):
     * While still inside outer ndo_start_xmit on the SAME CPU & ctx_id (before outer
     * tp_xmit_ret runs), outer tp_start_xmit already revoked active_slots mapping and
     * placed cv in `calls`. If skb re-enters dev_queue_xmit on a lower device/netns
     * synchronously, continue tracking the SAME object_id!
     */
    if (!av && c->in_xmit_count > 0) {
        uint32_t cpu = get_cpu();
        struct bpf_call_key xck = {
            .ctx_id = make_ctx_id(off),
            .sp = skb ^ ((uint64_t)cpu << 56),
            .site_id = PKT_SITE_TP_START_XMIT,
            .pad = 0,
        };
        struct bpf_call_val *xcv = map_lookup(&calls, &xck);
        if (xcv && xcv->skb == skb && xcv->object_id != 0 &&
            (xcv->ifindex != ifindex || xcv->netns_inum != netns)) {
            uint64_t stacked_obj = xcv->object_id;
            uint64_t stacked_smp = xcv->sample_id;
            uint64_t outer_cid   = xcv->call_id;
            uint32_t outer_ns    = xcv->netns_inum;
            uint32_t outer_ifi   = xcv->ifindex;
            uint16_t outer_txq   = xcv->txq;
            uint8_t  outer_dir   = xcv->dir;
            if (map_delete(&calls, &xck) == 0)
                __sync_fetch_and_sub(&c->in_xmit_count, 1);

            /* Close outer virtual xmit call cleanly and restore active tracking on lower dev */
            emit_step(c, PKT_SITE_TP_XMIT_RET, now, stacked_obj, outer_cid,
                      outer_ns, outer_ifi, 0, 0, 0, 0, 0, outer_txq,
                      outer_dir, PKT_STAGE_XMIT_RET, 0);

            struct bpf_active_val sav = {};
            sav.object_id = stacked_obj;
            sav.sample_id = stacked_smp;
            sav.lifecycle_state = PKT_STATE_ACTIVE_PIPELINE;
            sav.last_netns = netns;
            sav.last_ifindex = ifindex;
            sav.last_dir = PKT_DIR_TX;
            if (insert_active_current(c, skb, &sav, now) == 0) {
                in_task = is_in_task(off);
                pt = in_task ? get_pid_tgid() : 0;
                uint32_t tid = in_task ? (uint32_t)pt : 0;
                uint16_t evf = in_task ? PKT_EVF_IN_TASK : 0;
                reentry_obj_id = stacked_obj;
                emit_step(c, PKT_SITE_TP_NET_DEV_QUEUE, now, reentry_obj_id, 0,
                          netns, ifindex, 0, 0, 0, (int32_t)tp_len, tid, 0,
                          PKT_DIR_TX, PKT_STAGE_HANDOFF_LAYER, evf);
            }
        }
    }

    if (!reentry_obj_id && av) {
        if (av->lifecycle_state == PKT_STATE_QUARANTINED) {
            if (now < av->quarantine_until_ns) {
                __sync_fetch_and_add(&c->admission_rejected, 1);
                return 0;
            }
            /* 100 ms cooldown expired: lift quarantine and proceed to fresh admission */
            delete_active(c, skb);
            av = 0;
        } else {
            in_task = is_in_task(off);
            pt = in_task ? get_pid_tgid() : 0;
            uint32_t tid = in_task ? (uint32_t)pt : 0;
            uint16_t evf = in_task ? PKT_EVF_IN_TASK : 0;

            /* Legal re-entry (§3.3): HANDED_OFF_LAYER or changed (netns, ifindex, dir) */
            if (av->lifecycle_state == PKT_STATE_HANDED_OFF_LAYER ||
                av->last_netns != netns ||
                av->last_ifindex != ifindex ||
                av->last_dir != PKT_DIR_TX) {
                reentry_obj_id = av->object_id;
                av->lifecycle_state = PKT_STATE_ACTIVE_PIPELINE;
                av->open_visit_id = 0;
                av->last_netns = netns;
                av->last_ifindex = ifindex;
                av->last_dir = PKT_DIR_TX;
                av->saw_qdisc_enq = 0;
                av->requeued = 0;

                emit_step(c, PKT_SITE_TP_NET_DEV_QUEUE, now, reentry_obj_id, 0,
                          netns, ifindex, 0, 0, 0, (int32_t)tp_len, tid, 0,
                          PKT_DIR_TX, PKT_STAGE_HANDOFF_LAYER, evf);
            } else {
                /* Unexpected same-(netns, ifindex, dir) hit -> IDENTITY_CONFLICT + 100 ms quarantine */
                uint64_t conflict_obj = av->object_id;
                uint64_t conflict_smp = av->sample_id;
                av->lifecycle_state = PKT_STATE_QUARANTINED;
                av->open_visit_id = 0;
                av->quarantine_until_ns = now + PKT_QUARANTINE_NS;
                __sync_fetch_and_add(&c->identity_conflicts, 1);

                emit_object(c, PKT_SITE_TP_NET_DEV_QUEUE, now, conflict_obj, conflict_smp,
                            PKT_END_CONFLICT_TRUNCATED, 0, evf);
                emit_quality(c, PKT_SITE_TP_NET_DEV_QUEUE, now,
                             PKT_QUAL_IDENTITY_CONFLICT, PKT_SITE_TP_NET_DEV_QUEUE,
                             conflict_obj, 1);
                return 0;
            }
        }
    }

    /* Step 2: Early scalar filters BEFORE touching skb->data / L3 / L4 headers (§8.1) */
    if (!reentry_obj_id) {
        if (c->sample_stride == 0 || (c->flags & PKT_CTRL_F_ADMIT_OFF))
            return 0;
        if (c->filter_ifindex && ifindex != c->filter_ifindex)
            return 0;
        if (c->filter_netns && netns != c->filter_netns)
            return 0;
        if (c->filter_mark_mask) {
            uint32_t mk = 0;
            probe_read_k(&mk, 4, (const void *)(skb + OFF_OR(off, skb_mark, 168)));
            if ((mk & c->filter_mark_mask) != (c->filter_mark & c->filter_mark_mask))
                return 0;
        }

        in_task = is_in_task(off);
        pt = (in_task || c->filter_tgid) ? get_pid_tgid() : 0;

        if (c->filter_uid != PKT_FILTER_UID_ANY || c->filter_tgid != 0) {
            uint64_t sk = 0;
            uint8_t st = 0;
            int valid_sk = 0;
            if (probe_read_k(&sk, 8, (const void *)(skb + OFF_OR(off, skb_sk, 24))) == 0 && sk &&
                probe_read_k(&st, 1, (const void *)(sk + OFF_OR(off, sk_state, 18))) == 0 &&
                st != 6 && st != 12) {
                valid_sk = 1;
            }
            if (c->filter_uid != PKT_FILTER_UID_ANY) {
                uint32_t uid = 0;
                if (!valid_sk || probe_read_k(&uid, 4, (const void *)(sk + OFF_OR(off, sk_uid, 576))) != 0) {
                    __sync_fetch_and_add(&c->filter_unknown, 1);
                    return 0;
                }
                if (uid != c->filter_uid)
                    return 0;
            }
            if (c->filter_tgid) {
                uint32_t pkt_tgid = 0;
                if (valid_sk) {
                    uint64_t ck = 0;
                    probe_read_k(&ck, 8, (const void *)(sk + OFF_OR(off, sk_cookie, 88)));
                    struct bpf_sock_owner *so = lookup_sock_owner(sk, ck);
                    if (so)
                        pkt_tgid = so->tgid ? so->tgid : so->plugin_tgid;
                }
                if (!pkt_tgid && in_task)
                    pkt_tgid = (uint32_t)(pt >> 32);
                if (!pkt_tgid) {
                    __sync_fetch_and_add(&c->filter_unknown, 1);
                    return 0;
                }
                if (pkt_tgid != c->filter_tgid)
                    return 0;
            }
        }

        const uint32_t *sm6 = (const uint32_t *)c->filter_src_ip6_mask;
        const uint32_t *dm6 = (const uint32_t *)c->filter_dst_ip6_mask;
        has_s6 = (sm6[0] | sm6[1] | sm6[2] | sm6[3]) != 0;
        has_d6 = (dm6[0] | dm6[1] | dm6[2] | dm6[3]) != 0;
        int need_l3_l4 = (c->filter_ip_ver != 0) || (c->filter_proto != 0) ||
                         (c->filter_src_ip4_mask != 0) || (c->filter_dst_ip4_mask != 0) ||
                         has_s6 || has_d6 ||
                         (c->filter_src_port != 0) || (c->filter_dst_port != 0);

        /* Fast packet-mode sampling when no L3/L4 filter or flow hash is active */
        if (!need_l3_l4 && !c->sample_by_flow) {
            __sync_fetch_and_add(&c->admission_matched, 1);
            if (c->sample_stride > 1) {
                uint64_t n = __sync_fetch_and_add(&c->pkt_seen_seq, 1);
                if ((n % c->sample_stride) != 0)
                    return 0;
            }
            __sync_fetch_and_add(&c->admission_selected, 1);
            pre_sampled = 1;
        }
    }

    struct parsed_pkt p;
    parse_skb(skb, tp_len, ifindex, netns, off, &p);

    if (reentry_obj_id) {
        emit_summary_from_parsed(c, off, PKT_SITE_TP_NET_DEV_QUEUE, now,
                                 reentry_obj_id, &p, PKT_DIR_TX, in_task, pt);
        return 0;
    }

    if (!pre_sampled) {
        int f_rc = eval_l3_l4_filter(c, &p, has_s6, has_d6);
        if (f_rc < 0) {
            __sync_fetch_and_add(&c->filter_unknown, 1);
            return 0;
        }
        if (f_rc == 0)
            return 0;

        __sync_fetch_and_add(&c->admission_matched, 1);

        if (c->sample_stride > 1) {
            if (c->sample_by_flow) {
                uint32_t fh = hash_flow_5tuple(&p);
                if ((fh % c->sample_stride) != 0)
                    return 0;
            } else {
                uint64_t n = __sync_fetch_and_add(&c->pkt_seen_seq, 1);
                if ((n % c->sample_stride) != 0)
                    return 0;
            }
        }
        __sync_fetch_and_add(&c->admission_selected, 1);
    }

    uint64_t obj_id = __sync_fetch_and_add(&c->next_obj_id, 1) + 1ULL;
    uint64_t sample_id = __sync_fetch_and_add(&c->next_sample_id, 1) + 1ULL;

    struct bpf_active_val nav = {};
    nav.object_id = obj_id;
    nav.sample_id = sample_id;
    nav.lifecycle_state = PKT_STATE_ACTIVE_PIPELINE;
    nav.last_netns = p.netns_inum;
    nav.last_ifindex = p.ifindex;
    nav.last_dir = PKT_DIR_TX;

    if (insert_active_current(c, skb, &nav, now) != 0) {
        __sync_fetch_and_add(&c->admission_rejected, 1);
        return 0;
    }

    __sync_fetch_and_add(&c->admission_created, 1);

    uint32_t tid = in_task ? (uint32_t)pt : 0;
    uint16_t evf = in_task ? PKT_EVF_IN_TASK : 0;
    if (p.nonlin_trunc)
        evf |= PKT_EVF_NONLINEAR_TRUNC;

    emit_object(c, PKT_SITE_TP_NET_DEV_QUEUE, now, obj_id, sample_id,
                PKT_END_OPEN, 0, evf);
    emit_step(c, PKT_SITE_TP_NET_DEV_QUEUE, now, obj_id, 0,
              p.netns_inum, p.ifindex, 0, 0, 0, (int32_t)p.pkt_len, tid, 0,
              PKT_DIR_TX, PKT_STAGE_ENTRY, evf);
    emit_summary_from_parsed(c, off, PKT_SITE_TP_NET_DEV_QUEUE, now,
                             obj_id, &p, PKT_DIR_TX, in_task, pt);
    return 0;
}

/* ==================== 9. L2 kprobe/kretprobe Call Pairing Helpers (§3.4) ==================== */

IN void record_call_entry(struct bpf_ctrl_cfg *c, const struct bpf_call_key *ck,
                          const struct bpf_call_val *cv, uint16_t site, uint64_t now) {
    if (map_update(&calls, ck, cv, BPF_NOEXIST_FLAG) != 0) {
        /* Stale entry at same (ctx_id, sp, site_id): prior kretprobe was missed! */
        struct bpf_call_val *old = map_lookup(&calls, ck);
        if (old && old->object_id != 0) {
            uint64_t old_obj = old->object_id;
            __sync_fetch_and_add(&c->ret_unmatched, 1);
            emit_quality(c, site, now, PKT_QUAL_RET_UNMATCHED, site, old_obj, 1);
        }
        map_update(&calls, ck, cv, BPF_ANY_FLAG);
    }
}

IN uint32_t parent_to_classid(uint32_t qp) {
    return (qp != 0 && (qp & 0xFFFF0000U) != 0xFFFF0000U && (qp & 0xFFFFU) != 0) ? qp : 0U;
}

/*
 * leaf_mode:
 *   0 = classful scheduler (htb / plugin classful): emits PKT_STAGE_CLASSIFY, sets saw_qdisc_enq = 1 if 0
 *   1 = dedicated leaf qdisc (fq_codel / pfifo_fast / sfq / plugin leaf): sets saw_qdisc_enq = 1
 *   2 = shared-head fifo leaf (pfifo / bfifo / pfifo_tail): sets saw_qdisc_enq = 2
 *       so kr_fifo_deq (qdisc_dequeue_head) only closes visits opened by leaf_mode == 2.
 */
IN int handle_qdisc_enq(uint64_t *regs, uint16_t site, int leaf_mode) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c)
        return 0;
    if (ctrl_bypass_on(c) && !c->active_tracked_count)
        return 0;

    const struct bpf_btf_offsets *off = get_btf();
    uint64_t now = ktime_boot_ns();
    uint64_t skb = PT_PARM1(regs);
    struct bpf_active_val *av = skb ? lookup_active(c, skb) : 0;

    if (!av || av->lifecycle_state == PKT_STATE_QUARANTINED) {
        if (leaf_mode > 0) {
            /* Record untracked sentinel so paired kretprobe won't false-fire RET_UNMATCHED */
            struct bpf_call_key ck = {
                .ctx_id = make_ctx_id(off),
                .sp = PT_SP_ENTRY(regs),
                .site_id = site,
                .pad = 0,
            };
            struct bpf_call_val sentinel = {};
            record_call_entry(c, &ck, &sentinel, site, now);
        }
        return 0;
    }

    uint32_t qh = 0, qp = 0;
    uint64_t qdisc = PT_PARM2(regs);
    if (qdisc) {
        probe_read_k(&qh, 4, (const void *)(qdisc + OFF_OR(off, qdisc_handle, 56)));
        probe_read_k(&qp, 4, (const void *)(qdisc + OFF_OR(off, qdisc_parent, 60)));
    }

    uint32_t cls_id = parent_to_classid(qp);
    uint64_t vid = 0;
    uint8_t stage = PKT_STAGE_CLASSIFY;

    if (leaf_mode == 0) {
        if (!av->saw_qdisc_enq)
            av->saw_qdisc_enq = 1;
    } else {
        av->saw_qdisc_enq = (leaf_mode == 2) ? 2U : 1U;
        vid = av->next_visit_id + 1ULL;
        av->next_visit_id = vid;
        av->open_visit_id = vid;
        av->lifecycle_state = PKT_STATE_IN_QUEUE;
        av->qdisc_handle = qh;
        av->qdisc_parent = qp;
        av->requeued = 0;
        stage = PKT_STAGE_QDISC_ENQ;

        uint64_t cid = __sync_fetch_and_add(&c->next_call_id, 1) + 1ULL;
        struct bpf_call_key ck = {
            .ctx_id = make_ctx_id(off),
            .sp = PT_SP_ENTRY(regs),
            .site_id = site,
            .pad = 0,
        };
        struct bpf_call_val cv = {};
        cv.call_id = cid;
        cv.object_id = av->object_id;
        cv.sample_id = av->sample_id;
        cv.visit_id = vid;
        cv.skb = skb;
        cv.entry_ts_ns = now;
        cv.netns_inum = av->last_netns;
        cv.ifindex = av->last_ifindex;
        cv.qdisc_handle = qh;
        cv.qdisc_parent = qp;
        cv.dir = av->last_dir;
        record_call_entry(c, &ck, &cv, site, now);
    }

    emit_step(c, site, now, av->object_id, vid,
              av->last_netns, av->last_ifindex, qh, qp, cls_id, 0, 0, 0,
              av->last_dir, stage, 0);
    return 0;
}

IN int handle_qdisc_enq_ret(uint64_t *regs, uint16_t entry_site, uint16_t ret_site) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c)
        return 0;
    if (ctrl_bypass_on(c) && !c->active_tracked_count)
        return 0;

    const struct bpf_btf_offsets *off = get_btf();
    uint64_t now = ktime_boot_ns();
    struct bpf_call_key ck = {
        .ctx_id = make_ctx_id(off),
        .sp = PT_SP_RET(regs),
        .site_id = entry_site,
        .pad = 0,
    };
    struct bpf_call_val *cv = map_lookup(&calls, &ck);
    if (!cv) {
        /* Guard against 0->1 bypass transition race within 1 ms of leaving idle */
        if (now > c->last_idle_exit_ns + 1000000ULL) {
            __sync_fetch_and_add(&c->ret_unmatched, 1);
            emit_quality(c, ret_site, now, PKT_QUAL_RET_UNMATCHED, ret_site, 0, 1);
        }
        return 0;
    }

    struct bpf_call_val copy = *cv;
    map_delete(&calls, &ck);

    if (copy.object_id == 0)
        return 0; /* Untracked sentinel */

    int32_t rc = (int32_t)PT_RC(regs);
    uint32_t cls_id = parent_to_classid(copy.qdisc_parent);
    emit_step(c, ret_site, now, copy.object_id, copy.visit_id,
              copy.netns_inum, copy.ifindex, copy.qdisc_handle, copy.qdisc_parent,
              cls_id, rc, 0, 0, copy.dir, PKT_STAGE_QDISC_ENQ_RET, 0);

    /* If enqueue rejected/dropped without queuing, close open_visit_id if still alive */
    if (rc != 0 && rc != NET_XMIT_CN_RC) {
        struct bpf_active_val *av = lookup_active(c, copy.skb);
        if (av && av->object_id == copy.object_id && av->open_visit_id == copy.visit_id) {
            av->open_visit_id = 0;
            if (av->saw_qdisc_enq == 2)
                av->saw_qdisc_enq = 1;
            av->lifecycle_state = PKT_STATE_ACTIVE_PIPELINE;
        }
    }
    return 0;
}

IN int handle_qdisc_deq_ret(uint64_t *regs, uint16_t site, int is_fifo_deq) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c)
        return 0;
    if (ctrl_bypass_on(c) && !c->active_tracked_count)
        return 0;

    uint64_t skb = PT_RC(regs);
    if (!skb)
        return 0;
    struct bpf_active_val *av = lookup_active(c, skb);
    if (!av || av->lifecycle_state == PKT_STATE_QUARANTINED || av->open_visit_id == 0)
        return 0;

    /* Prevent double-dequeue if another leaf qdisc internally calls qdisc_dequeue_head */
    if (is_fifo_deq) {
        if (av->saw_qdisc_enq != 2)
            return 0;
    } else {
        if (av->saw_qdisc_enq == 2)
            return 0;
    }

    uint64_t now = ktime_boot_ns();
    uint64_t vid = av->open_visit_id;
    uint32_t qh = av->qdisc_handle;
    uint32_t qp = av->qdisc_parent;
    uint32_t cls_id = parent_to_classid(qp);
    av->saw_qdisc_enq = 1;
    av->open_visit_id = 0;
    av->requeued = 0;
    av->lifecycle_state = PKT_STATE_ACTIVE_PIPELINE;

    emit_step(c, site, now, av->object_id, vid,
              av->last_netns, av->last_ifindex, qh, qp, cls_id, 0, 0, 0,
              av->last_dir, PKT_STAGE_QDISC_DEQ, 0);
    return 0;
}

/* ==================== 10. L2 Qdisc, TC Classify, Direct Xmit & Requeue Probes ==================== */

SEC("kp_htb_enq")
int prog_kp_htb_enq(uint64_t *regs) {
    return handle_qdisc_enq(regs, PKT_SITE_KP_HTB_ENQ, 0);
}

/* Reusable dynamic qdisc probe templates (cloned & site-ID patched at runtime for unlimited plugins) */
SEC("kp_plug_cls_tmpl")
int prog_kp_plug_cls_tmpl(uint64_t *regs) {
    return handle_qdisc_enq(regs, PKT_SITE_DYN_ENQ_SENTINEL, 0);
}

SEC("kp_plug_leaf_enq_tmpl")
int prog_kp_plug_leaf_enq_tmpl(uint64_t *regs) {
    return handle_qdisc_enq(regs, PKT_SITE_DYN_ENQ_SENTINEL, 1);
}

SEC("kr_plug_leaf_enq_tmpl")
int prog_kr_plug_leaf_enq_tmpl(uint64_t *regs) {
    return handle_qdisc_enq_ret(regs, PKT_SITE_DYN_ENQ_SENTINEL, PKT_SITE_DYN_RET_SENTINEL);
}

SEC("kr_plug_leaf_deq_tmpl")
int prog_kr_plug_leaf_deq_tmpl(uint64_t *regs) {
    return handle_qdisc_deq_ret(regs, PKT_SITE_DYN_ENQ_SENTINEL, 0);
}

SEC("kp_fq_codel_enq")
int prog_kp_fq_codel_enq(uint64_t *regs) {
    return handle_qdisc_enq(regs, PKT_SITE_KP_FQ_CODEL_ENQ, 1);
}

SEC("kr_fq_codel_enq")
int prog_kr_fq_codel_enq(uint64_t *regs) {
    return handle_qdisc_enq_ret(regs, PKT_SITE_KP_FQ_CODEL_ENQ, PKT_SITE_KR_FQ_CODEL_ENQ);
}

SEC("kr_fq_codel_deq")
int prog_kr_fq_codel_deq(uint64_t *regs) {
    return handle_qdisc_deq_ret(regs, PKT_SITE_KR_FQ_CODEL_DEQ, 0);
}

SEC("kp_pfifo_enq")
int prog_kp_pfifo_enq(uint64_t *regs) {
    return handle_qdisc_enq(regs, PKT_SITE_KP_PFIFO_ENQ, 1);
}

SEC("kr_pfifo_enq")
int prog_kr_pfifo_enq(uint64_t *regs) {
    return handle_qdisc_enq_ret(regs, PKT_SITE_KP_PFIFO_ENQ, PKT_SITE_KR_PFIFO_ENQ);
}

SEC("kr_pfifo_deq")
int prog_kr_pfifo_deq(uint64_t *regs) {
    return handle_qdisc_deq_ret(regs, PKT_SITE_KR_PFIFO_DEQ, 0);
}

SEC("kp_fifo_enq")
int prog_kp_fifo_enq(uint64_t *regs) {
    return handle_qdisc_enq(regs, PKT_SITE_KP_FIFO_ENQ, 2);
}

SEC("kr_fifo_enq")
int prog_kr_fifo_enq(uint64_t *regs) {
    return handle_qdisc_enq_ret(regs, PKT_SITE_KP_FIFO_ENQ, PKT_SITE_KR_FIFO_ENQ);
}

SEC("kp_bfifo_enq")
int prog_kp_bfifo_enq(uint64_t *regs) {
    return handle_qdisc_enq(regs, PKT_SITE_KP_BFIFO_ENQ, 2);
}

SEC("kr_bfifo_enq")
int prog_kr_bfifo_enq(uint64_t *regs) {
    return handle_qdisc_enq_ret(regs, PKT_SITE_KP_BFIFO_ENQ, PKT_SITE_KR_BFIFO_ENQ);
}

SEC("kp_ptail_enq")
int prog_kp_ptail_enq(uint64_t *regs) {
    return handle_qdisc_enq(regs, PKT_SITE_KP_PTAIL_ENQ, 2);
}

SEC("kr_ptail_enq")
int prog_kr_ptail_enq(uint64_t *regs) {
    return handle_qdisc_enq_ret(regs, PKT_SITE_KP_PTAIL_ENQ, PKT_SITE_KR_PTAIL_ENQ);
}

SEC("kr_fifo_deq")
int prog_kr_fifo_deq(uint64_t *regs) {
    return handle_qdisc_deq_ret(regs, PKT_SITE_KR_FIFO_DEQ, 1);
}

SEC("kp_sfq_enq")
int prog_kp_sfq_enq(uint64_t *regs) {
    return handle_qdisc_enq(regs, PKT_SITE_KP_SFQ_ENQ, 1);
}

SEC("kr_sfq_enq")
int prog_kr_sfq_enq(uint64_t *regs) {
    return handle_qdisc_enq_ret(regs, PKT_SITE_KP_SFQ_ENQ, PKT_SITE_KR_SFQ_ENQ);
}

SEC("kr_sfq_deq")
int prog_kr_sfq_deq(uint64_t *regs) {
    return handle_qdisc_deq_ret(regs, PKT_SITE_KR_SFQ_DEQ, 0);
}

SEC("kp_tcf_classify")
int prog_kp_tcf_classify(uint64_t *regs) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c)
        return 0;
    if (ctrl_bypass_on(c) && !c->active_tracked_count)
        return 0;

    uint64_t skb = PT_PARM1(regs);
    uint64_t res_ptr = PT_PARM4(regs);
    if (!skb || !res_ptr)
        return 0;

    struct bpf_active_val *av = lookup_active(c, skb);
    if (!av || av->lifecycle_state == PKT_STATE_QUARANTINED)
        return 0;

    const struct bpf_btf_offsets *off = get_btf();
    uint64_t now = ktime_boot_ns();
    struct bpf_call_key ck = {
        .ctx_id = make_ctx_id(off),
        .sp = PT_SP_ENTRY(regs),
        .site_id = PKT_SITE_KP_TCF_CLASSIFY,
        .pad = 0,
    };
    struct bpf_call_val cv = {};
    cv.call_id = __sync_fetch_and_add(&c->next_call_id, 1) + 1ULL;
    cv.object_id = av->object_id;
    cv.sample_id = av->sample_id;
    cv.skb = skb;
    cv.entry_ts_ns = now;
    cv.saved_next_visit_id = res_ptr;
    cv.netns_inum = av->last_netns;
    cv.ifindex = av->last_ifindex;
    cv.dir = av->last_dir;
    record_call_entry(c, &ck, &cv, PKT_SITE_KP_TCF_CLASSIFY, now);
    return 0;
}

SEC("kr_tcf_classify")
int prog_kr_tcf_classify(uint64_t *regs) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c)
        return 0;
    if (ctrl_bypass_on(c) && !c->active_tracked_count)
        return 0;

    const struct bpf_btf_offsets *off = get_btf();
    struct bpf_call_key ck = {
        .ctx_id = make_ctx_id(off),
        .sp = PT_SP_RET(regs),
        .site_id = PKT_SITE_KP_TCF_CLASSIFY,
        .pad = 0,
    };
    struct bpf_call_val *cv = map_lookup(&calls, &ck);
    if (!cv)
        return 0; /* Untracked packets skip entry write; do NOT emit RET_UNMATCHED */

    struct bpf_call_val copy = *cv;
    map_delete(&calls, &ck);

    int32_t verdict = (int32_t)PT_RC(regs);
    if (verdict >= 0 && copy.object_id != 0 && copy.saved_next_visit_id != 0) {
        uint32_t cid = 0;
        uint32_t cid_off = OFF_OR(off, tcf_res_classid, 8);
        if (probe_read_k(&cid, 4, (const void *)(copy.saved_next_visit_id + cid_off)) == 0 &&
            cid != 0 && (cid & 0xFFFF0000U) != 0xFFFF0000U) {
            uint64_t now = ktime_boot_ns();
            emit_step(c, PKT_SITE_KR_TCF_CLASSIFY, now, copy.object_id, 0,
                      copy.netns_inum, copy.ifindex, 0, 0, cid, verdict, 0, 0,
                      copy.dir, PKT_STAGE_CLASSIFY, 0);
        }
    }
    return 0;
}

SEC("kp_sch_direct_xmit")
int prog_kp_sch_direct_xmit(uint64_t *regs) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c)
        return 0;
    if (ctrl_bypass_on(c) && !c->active_tracked_count)
        return 0;

    uint64_t skb = PT_PARM1(regs);
    if (!skb)
        return 0;
    struct bpf_active_val *av = lookup_active(c, skb);
    if (!av || av->lifecycle_state == PKT_STATE_QUARANTINED)
        return 0;

    const struct bpf_btf_offsets *off = get_btf();
    uint64_t now = ktime_boot_ns();

    /* If draining gso_skb requeue (which skips q->dequeue), close requeue visit here */
    if (av->requeued && av->open_visit_id) {
        uint64_t vid = av->open_visit_id;
        av->open_visit_id = 0;
        av->requeued = 0;
        av->lifecycle_state = PKT_STATE_ACTIVE_PIPELINE;
        emit_step(c, PKT_SITE_KP_SCH_DIRECT_XMIT, now, av->object_id, vid,
                  av->last_netns, av->last_ifindex, av->qdisc_handle, av->qdisc_parent,
                  0, 0, 0, 0, av->last_dir, PKT_STAGE_QDISC_DEQ, 0);
        return 0;
    }

    /* Only emit BYPASS_DIRECT when q->enqueue was genuinely bypassed (§4.2) */
    if (!av->saw_qdisc_enq) {
        uint32_t qh = 0, qp = 0;
        uint64_t qdisc = PT_PARM2(regs);
        if (qdisc) {
            probe_read_k(&qh, 4, (const void *)(qdisc + OFF_OR(off, qdisc_handle, 56)));
            probe_read_k(&qp, 4, (const void *)(qdisc + OFF_OR(off, qdisc_parent, 60)));
        }
        emit_step(c, PKT_SITE_KP_SCH_DIRECT_XMIT, now, av->object_id, 0,
                  av->last_netns, av->last_ifindex, qh, qp, 0, 0, 0, 0,
                  av->last_dir, PKT_STAGE_BYPASS_DIRECT, 0);
    }
    return 0;
}

SEC("kp_dev_requeue")
int prog_kp_dev_requeue(uint64_t *regs) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c)
        return 0;
    if (ctrl_bypass_on(c) && !c->active_tracked_count)
        return 0;

    uint64_t skb = PT_PARM1(regs);
    if (!skb)
        return 0;
    struct bpf_active_val *av = lookup_active(c, skb);
    if (!av || av->lifecycle_state == PKT_STATE_QUARANTINED)
        return 0;

    const struct bpf_btf_offsets *off = get_btf();
    uint64_t now = ktime_boot_ns();
    uint32_t qh = 0, qp = 0;
    uint64_t qdisc = PT_PARM2(regs);
    if (qdisc) {
        probe_read_k(&qh, 4, (const void *)(qdisc + OFF_OR(off, qdisc_handle, 56)));
        probe_read_k(&qp, 4, (const void *)(qdisc + OFF_OR(off, qdisc_parent, 60)));
    }

    uint64_t vid = av->next_visit_id + 1ULL;
    av->next_visit_id = vid;
    av->open_visit_id = vid;
    av->lifecycle_state = PKT_STATE_IN_QUEUE;
    av->qdisc_handle = qh;
    av->qdisc_parent = qp;
    av->requeued = 1;

    emit_step(c, PKT_SITE_KP_DEV_REQUEUE, now, av->object_id, vid,
              av->last_netns, av->last_ifindex, qh, qp, 0, 0, 0, 0,
              av->last_dir, PKT_STAGE_REQUEUE_GSO, 0);
    return 0;
}

/* ==================== 11. L2 Driver Ownership Transfer (UAF-Safe §3.4) ==================== */

SEC("tp_start_xmit")
int prog_tp_start_xmit(uint8_t *ctx) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c)
        return 0;
    if (ctrl_bypass_on(c) && !c->active_tracked_count)
        return 0;

    uint64_t skb = *(uint64_t *)(ctx + 16);
    uint16_t txq = *(uint16_t *)(ctx + 12);
    struct bpf_active_val *av = lookup_active(c, skb);
    if (!av || av->lifecycle_state == PKT_STATE_QUARANTINED)
        return 0;

    const struct bpf_btf_offsets *off = get_btf();
    uint64_t now = ktime_boot_ns();

    /*
     * Check if device is an IFB redirect pseudo-device (`dev->name` @ offset 0 == "ifb*").
     * `ifb_xmit` queues skb to `ifb_ri_tasklet` and re-injects into `dev_queue_xmit`
     * asynchronously, so mark HANDED_OFF_LAYER instead of revoking active mapping!
     */
    uint64_t dev_ptr = 0;
    char dname[4] = {0, 0, 0, 0};
    if (probe_read_k(&dev_ptr, 8, (const void *)(skb + OFF_OR(off, skb_dev, 16))) == 0 && dev_ptr)
        probe_read_k(dname, 4, (const void *)dev_ptr);
    if (dname[0] == 'i' && dname[1] == 'f' && dname[2] == 'b') {
        uint32_t in_task = is_in_task(off);
        uint32_t tid = in_task ? (uint32_t)get_pid_tgid() : 0;
        uint16_t evf = in_task ? PKT_EVF_IN_TASK : 0;
        av->lifecycle_state = PKT_STATE_HANDED_OFF_LAYER;
        av->open_visit_id = 0;
        av->requeued = 0;
        emit_step(c, PKT_SITE_TP_START_XMIT, now, av->object_id, 0,
                  av->last_netns, av->last_ifindex, 0, 0, 0, 0, tid, txq,
                  av->last_dir, PKT_STAGE_HANDOFF_LAYER, evf);
        return 0;
    }

    /* Snapshot everything BEFORE revoking active address mapping */
    uint64_t obj_id = av->object_id;
    uint64_t sample_id = av->sample_id;
    uint64_t open_vid = av->open_visit_id;
    uint64_t saved_next_vid = av->next_visit_id;
    uint32_t netns = av->last_netns;
    uint32_t ifindex = av->last_ifindex;
    uint32_t qh = av->qdisc_handle;
    uint32_t qp = av->qdisc_parent;
    uint8_t  dir = av->last_dir;
    uint8_t  was_requeued = av->requeued;

    /* Revoke TX active-slot mapping BEFORE driver runs to eliminate cross-CPU UAF/collision */
    delete_active(c, skb);

    /* Close requeued gso_skb visit if kp_sch_direct_xmit was not attached */
    if (was_requeued && open_vid) {
        emit_step(c, PKT_SITE_TP_START_XMIT, now, obj_id, open_vid,
                  netns, ifindex, qh, qp, 0, 0, 0, txq,
                  dir, PKT_STAGE_QDISC_DEQ, 0);
    }

    uint32_t in_task = is_in_task(off);
    uint32_t tid = in_task ? (uint32_t)get_pid_tgid() : 0;
    uint16_t evf = in_task ? PKT_EVF_IN_TASK : 0;
    uint32_t cpu = get_cpu();

    uint64_t cid = __sync_fetch_and_add(&c->next_call_id, 1) + 1ULL;
    struct bpf_call_key ck = {
        .ctx_id = make_ctx_id(off),
        .sp = skb ^ ((uint64_t)cpu << 56),
        .site_id = PKT_SITE_TP_START_XMIT,
        .pad = 0,
    };
    struct bpf_call_val cv = {};
    cv.call_id = cid;
    cv.object_id = obj_id;
    cv.sample_id = sample_id;
    cv.visit_id = open_vid;
    cv.skb = skb;
    cv.entry_ts_ns = now;
    cv.netns_inum = netns;
    cv.ifindex = ifindex;
    cv.qdisc_handle = qh;
    cv.qdisc_parent = qp;
    cv.txq = txq;
    cv.dir = dir;
    cv.reopen_on_busy = 1;
    cv.saved_next_visit_id = saved_next_vid;
    cv.saved_qdisc_handle = qh;
    cv.saved_qdisc_parent = qp;

    if (map_update(&calls, &ck, &cv, BPF_ANY_FLAG) == 0)
        __sync_fetch_and_add(&c->in_xmit_count, 1);

    emit_step(c, PKT_SITE_TP_START_XMIT, now, obj_id, cid,
              netns, ifindex, 0, 0, 0, 0, tid, txq,
              dir, PKT_STAGE_XMIT_START, evf);
    return 0;
}

SEC("tp_xmit_ret")
int prog_tp_xmit_ret(uint8_t *ctx) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c)
        return 0;
    if (ctrl_bypass_on(c) && !c->in_xmit_count)
        return 0;

    const struct bpf_btf_offsets *off = get_btf();
    uint32_t cpu = get_cpu();
    /* Read raw skb integer value from tracepoint ctx ONLY as lookup key; NEVER dereference! */
    uint64_t skb_val = *(uint64_t *)(ctx + 8);
    int32_t rc = *(int32_t *)(ctx + 20);

    struct bpf_call_key ck = {
        .ctx_id = make_ctx_id(off),
        .sp = skb_val ^ ((uint64_t)cpu << 56),
        .site_id = PKT_SITE_TP_START_XMIT,
        .pad = 0,
    };
    struct bpf_call_val *cv = map_lookup(&calls, &ck);
    if (!cv)
        return 0;

    struct bpf_call_val copy = *cv;
    if (map_delete(&calls, &ck) == 0)
        __sync_fetch_and_sub(&c->in_xmit_count, 1);

    if (copy.skb != skb_val || copy.object_id == 0)
        return 0;

    uint64_t now = ktime_boot_ns();
    emit_step(c, PKT_SITE_TP_XMIT_RET, now, copy.object_id, copy.call_id,
              copy.netns_inum, copy.ifindex, 0, 0, 0, rc, 0, copy.txq,
              copy.dir, PKT_STAGE_XMIT_RET, 0);

    if (rc == NETDEV_TX_BUSY_RC && copy.reopen_on_busy) {
        /*
         * Driver refused ownership (NETDEV_TX_BUSY): roll back snapshot so
         * dev_requeue_skb on the next line of sch_direct_xmit continues same object_id
         * WITHOUT ever dereferencing skb memory!
         */
        struct bpf_active_val rav = {};
        rav.object_id = copy.object_id;
        rav.sample_id = copy.sample_id;
        rav.next_visit_id = copy.saved_next_visit_id;
        rav.lifecycle_state = PKT_STATE_ACTIVE_PIPELINE;
        rav.last_netns = copy.netns_inum;
        rav.last_ifindex = copy.ifindex;
        rav.qdisc_handle = copy.saved_qdisc_handle;
        rav.qdisc_parent = copy.saved_qdisc_parent;
        rav.last_dir = copy.dir;
        rav.saw_qdisc_enq = 1;
        insert_active_current(c, copy.skb, &rav, now);
    } else if (rc == NETDEV_TX_OK_RC || rc == NET_XMIT_CN_RC) {
        emit_object(c, PKT_SITE_TP_XMIT_RET, now, copy.object_id, copy.sample_id,
                    PKT_END_TX_OK, 0, 0);
    } else {
        emit_object(c, PKT_SITE_TP_XMIT_RET, now, copy.object_id, copy.sample_id,
                    PKT_END_DROP, (uint32_t)rc, 0);
    }
    return 0;
}

/* ==================== 12. L2 Drop & Consume Lifecycle Convergence ==================== */

IN uint32_t read_kfree_drop_reason(uint8_t *ctx, const struct bpf_btf_offsets *off) {
    uint32_t r_off = 28U; /* Linux 6.1..6.10 trace_event_raw_kfree_skb.reason */
    if (off) {
        if (off->tp_kfree_skb_reason)
            r_off = off->tp_kfree_skb_reason;
        else if (off->dev_ifindex >= 224U && off->dev_nd_net > 0U && off->dev_nd_net < 512U)
            r_off = 36U; /* Linux 6.11+/6.12 added rx_sk @ +24, moving reason to +36 */
    }

    /*
     * Pass `ctx` at exact offset 0 (zero PTR_TO_CTX arithmetic!) to bpf_probe_read_kernel,
     * then select from constant stack offsets so Linux's BPF verifier never sees
     * variable or non-zero PTR_TO_CTX pointer arithmetic.
     */
    uint32_t tp_words[12] = {};
    if (r_off >= 40U) {
        if (probe_read_k(tp_words, 48U, (const void *)ctx) != 0)
            return 0;
        return (r_off == 44U) ? tp_words[11] : tp_words[10];
    }
    if (r_off >= 36U) {
        if (probe_read_k(tp_words, 40U, (const void *)ctx) != 0)
            return 0;
        return tp_words[9];
    }
    if (r_off == 32U) {
        if (probe_read_k(tp_words, 36U, (const void *)ctx) != 0)
            return 0;
        return tp_words[8];
    }
    if (probe_read_k(tp_words, 32U, (const void *)ctx) != 0)
        return 0;
    return (r_off == 24U) ? tp_words[6] : tp_words[7];
}

SEC("tp_kfree_skb")
int prog_tp_kfree_skb(uint8_t *ctx) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c)
        return 0;
    if (ctrl_bypass_on(c) && !c->active_tracked_count)
        return 0;

    uint64_t skb = *(uint64_t *)(ctx + 8);
    struct bpf_active_val *av = lookup_active(c, skb);
    if (!av)
        return 0;

    /* Early release of 100 ms quarantine cooldown on deterministic kfree_skb! */
    if (av->lifecycle_state == PKT_STATE_QUARANTINED) {
        delete_active(c, skb);
        return 0;
    }

    const struct bpf_btf_offsets *off = get_btf();
    uint64_t now = ktime_boot_ns();
    uint32_t reason = read_kfree_drop_reason(ctx, off);

    uint64_t obj_id = av->object_id;
    uint64_t sample_id = av->sample_id;
    uint64_t open_vid = (av->lifecycle_state == PKT_STATE_IN_QUEUE) ? av->open_visit_id : 0;
    uint32_t qh = open_vid ? av->qdisc_handle : 0;
    uint32_t qp = open_vid ? av->qdisc_parent : 0;
    uint32_t netns = av->last_netns;
    uint32_t ifindex = av->last_ifindex;
    uint8_t  dir = av->last_dir;

    delete_active(c, skb);

    emit_step(c, PKT_SITE_TP_KFREE_SKB, now, obj_id, open_vid,
              netns, ifindex, qh, qp, 0, (int32_t)reason, 0, 0,
              dir, PKT_STAGE_DROP, 0);
    emit_object(c, PKT_SITE_TP_KFREE_SKB, now, obj_id, sample_id,
                PKT_END_DROP, reason, 0);
    return 0;
}

SEC("tp_consume_skb")
int prog_tp_consume_skb(uint8_t *ctx) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c)
        return 0;
    if (ctrl_bypass_on(c) && !c->active_tracked_count)
        return 0;

    uint64_t skb = *(uint64_t *)(ctx + 8);
    struct bpf_active_val *av = lookup_active(c, skb);
    if (!av)
        return 0;

    /* Early release of 100 ms quarantine cooldown on deterministic consume_skb! */
    if (av->lifecycle_state == PKT_STATE_QUARANTINED) {
        delete_active(c, skb);
        return 0;
    }

    uint64_t now = ktime_boot_ns();
    uint64_t obj_id = av->object_id;
    uint64_t sample_id = av->sample_id;
    uint64_t open_vid = (av->lifecycle_state == PKT_STATE_IN_QUEUE) ? av->open_visit_id : 0;
    uint32_t qh = open_vid ? av->qdisc_handle : 0;
    uint32_t qp = open_vid ? av->qdisc_parent : 0;
    uint32_t netns = av->last_netns;
    uint32_t ifindex = av->last_ifindex;
    uint8_t  dir = av->last_dir;

    delete_active(c, skb);

    emit_step(c, PKT_SITE_TP_CONSUME_SKB, now, obj_id, open_vid,
              netns, ifindex, qh, qp, 0, 0, 0, 0,
              dir, PKT_STAGE_CONSUME, 0);
    emit_object(c, PKT_SITE_TP_CONSUME_SKB, now, obj_id, sample_id,
                PKT_END_CONSUME, 0, 0);
    return 0;
}

/* ==================== 13. L2 Object Transformations (CLONE & In-Place Rewrite) ==================== */

SEC("kp_skb_clone")
int prog_kp_skb_clone(uint64_t *regs) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c)
        return 0;
    if (ctrl_bypass_on(c) && !c->active_tracked_count)
        return 0;

    const struct bpf_btf_offsets *off = get_btf();
    uint64_t now = ktime_boot_ns();
    uint64_t src_skb = PT_PARM1(regs);
    struct bpf_active_val *av = src_skb ? lookup_active(c, src_skb) : 0;

    struct bpf_call_key ck = {
        .ctx_id = make_ctx_id(off),
        .sp = PT_SP_ENTRY(regs),
        .site_id = PKT_SITE_KP_SKB_CLONE,
        .pad = 0,
    };

    if (!av || av->lifecycle_state == PKT_STATE_QUARANTINED) {
        struct bpf_call_val sentinel = {};
        record_call_entry(c, &ck, &sentinel, PKT_SITE_KP_SKB_CLONE, now);
        return 0;
    }

    uint64_t cid = __sync_fetch_and_add(&c->next_call_id, 1) + 1ULL;
    struct bpf_call_val cv = {};
    cv.call_id = cid;
    cv.object_id = av->object_id;
    cv.sample_id = av->sample_id;
    cv.skb = src_skb;
    cv.entry_ts_ns = now;
    cv.netns_inum = av->last_netns;
    cv.ifindex = av->last_ifindex;
    cv.dir = av->last_dir;
    record_call_entry(c, &ck, &cv, PKT_SITE_KP_SKB_CLONE, now);
    return 0;
}

SEC("kr_skb_clone")
int prog_kr_skb_clone(uint64_t *regs) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c)
        return 0;
    if (ctrl_bypass_on(c) && !c->active_tracked_count)
        return 0;

    const struct bpf_btf_offsets *off = get_btf();
    uint64_t now = ktime_boot_ns();
    struct bpf_call_key ck = {
        .ctx_id = make_ctx_id(off),
        .sp = PT_SP_RET(regs),
        .site_id = PKT_SITE_KP_SKB_CLONE,
        .pad = 0,
    };

    struct bpf_call_val *cv = map_lookup(&calls, &ck);
    if (!cv) {
        if (now > c->last_idle_exit_ns + 1000000ULL) {
            __sync_fetch_and_add(&c->ret_unmatched, 1);
            emit_quality(c, PKT_SITE_KR_SKB_CLONE, now,
                         PKT_QUAL_RET_UNMATCHED, PKT_SITE_KR_SKB_CLONE, 0, 1);
        }
        return 0;
    }

    struct bpf_call_val copy = *cv;
    map_delete(&calls, &ck);

    uint64_t dst_skb = PT_RC(regs);
    if (copy.object_id == 0 || !dst_skb)
        return 0;

    uint64_t dst_obj = __sync_fetch_and_add(&c->next_obj_id, 1) + 1ULL;
    struct bpf_active_val nav = {};
    nav.object_id = dst_obj;
    nav.sample_id = copy.sample_id;
    nav.lifecycle_state = PKT_STATE_HANDED_OFF_LAYER;
    nav.last_netns = copy.netns_inum;
    nav.last_ifindex = copy.ifindex;
    nav.last_dir = copy.dir;

    if (insert_active_current(c, dst_skb, &nav, now) != 0) {
        __sync_fetch_and_add(&c->admission_rejected, 1);
        return 0;
    }

    emit_object(c, PKT_SITE_KR_SKB_CLONE, now, dst_obj, copy.sample_id,
                PKT_END_OPEN, 0, 0);
    emit_rel(c, PKT_SITE_KR_SKB_CLONE, now, copy.call_id,
             copy.object_id, dst_obj, PKT_REL_CLONE, 0);
    return 0;
}

SEC("kp_pskb_expand")
int prog_kp_pskb_expand(uint64_t *regs) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c)
        return 0;
    if (ctrl_bypass_on(c) && !c->active_tracked_count)
        return 0;

    uint64_t skb = PT_PARM1(regs);
    if (!skb)
        return 0;
    struct bpf_active_val *av = lookup_active(c, skb);
    if (!av || av->lifecycle_state == PKT_STATE_QUARANTINED)
        return 0;

    const struct bpf_btf_offsets *off = get_btf();
    uint64_t now = ktime_boot_ns();
    uint32_t in_task = is_in_task(off);
    uint64_t pt = in_task ? get_pid_tgid() : 0;

    /* Same object_id preserved on pskb_expand_head; re-emit updated SUMMARY (§3.6) */
    uint32_t ifindex = 0, netns = 0;
    read_skb_dev_ids(skb, off, &ifindex, &netns);
    struct parsed_pkt p;
    parse_skb(skb, 0, ifindex, netns, off, &p);
    emit_summary_from_parsed(c, off, PKT_SITE_KP_PSKB_EXPAND, now,
                             av->object_id, &p, av->last_dir, in_task, pt);
    return 0;
}

/* ==================== 14. L2 Backpressure Queue State: QSTATE ==================== */

IN int handle_txq_qstate(uint64_t *regs, uint16_t site, uint8_t state_op) {
    struct bpf_ctrl_cfg *c = get_ctrl();
    if (!c || !ctrl_ringbuf_on(c))
        return 0;
    if (c->sample_stride == 0 && (!ctrl_bypass_on(c) ? 0 : !c->active_tracked_count))
        return 0;

    uint64_t dev_queue = PT_PARM1(regs);
    if (!dev_queue)
        return 0;

    const struct bpf_btf_offsets *off = get_btf();
    /* struct netdev_queue has `struct net_device *dev` at offset 0 */
    uint64_t dev = 0;
    if (probe_read_k(&dev, sizeof(dev), (const void *)dev_queue) != 0 || !dev)
        return 0;

    uint32_t ifindex = 0, netns = 0;
    probe_read_k(&ifindex, 4, (const void *)(dev + OFF_OR(off, dev_ifindex, 216)));
    if (c->filter_ifindex && ifindex != c->filter_ifindex)
        return 0;

    uint64_t net_ptr = 0;
    if (probe_read_k(&net_ptr, 8, (const void *)(dev + OFF_OR(off, dev_nd_net, 1280))) == 0 && net_ptr)
        probe_read_k(&netns, 4, (const void *)(net_ptr + OFF_OR(off, net_ns_inum, 136)));
    if (c->filter_netns && netns != c->filter_netns)
        return 0;

    uint16_t txq = 0;
    if (off && off->dev_tx_queues && off->netdev_queue_sz) {
        uint64_t tx_base = 0;
        if (probe_read_k(&tx_base, 8, (const void *)(dev + off->dev_tx_queues)) == 0 &&
            tx_base && dev_queue >= tx_base) {
            uint64_t diff = dev_queue - tx_base;
            uint64_t qsz = off->netdev_queue_sz;
            if (qsz > 0 && diff < 256ULL * qsz)
                txq = (uint16_t)(diff / qsz);
        }
    }

    uint32_t cpu = get_cpu();
    uint64_t seq = next_cpu_seq(cpu);
    struct bpf_ev_qstate *ev = rb_reserve(&rb, sizeof(*ev), 0);
    if (!ev) {
        __sync_fetch_and_add(&c->rb_drops, 1);
        return 0;
    }
    ev->h.kind = PKT_EV_QSTATE;
    ev->h.object_type = PKT_OBJ_SKB;
    ev->h.evidence_level = PKT_EVID_DIRECT;
    ev->h.site_dict_idx = site;
    ev->h.flags = compose_ev_flags(c, 0);
    ev->h.cpu = cpu;
    ev->h.reserved = 0;
    ev->h.seq = seq;
    ev->h.ts_ns = ktime_boot_ns();
    ev->queue_gen = 0;
    ev->netns_inum = netns;
    ev->ifindex = ifindex;
    ev->value = 0;
    ev->txq = txq;
    ev->state_op = state_op;
    ev->reserved2 = 0;
    rb_submit(ev, 0);
    return 0;
}

SEC("kp_txq_stop")
int prog_kp_txq_stop(uint64_t *regs) {
    return handle_txq_qstate(regs, PKT_SITE_KP_TXQ_STOP, PKT_QSTATE_TXQ_STOP);
}

SEC("kp_txq_wake")
int prog_kp_txq_wake(uint64_t *regs) {
    return handle_txq_qstate(regs, PKT_SITE_KP_TXQ_WAKE, PKT_QSTATE_TXQ_WAKE);
}

char _license[] SEC("license") = "GPL";
