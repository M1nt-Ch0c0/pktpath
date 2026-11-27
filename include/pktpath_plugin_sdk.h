#ifndef PKTPATH_PLUGIN_SDK_H
#define PKTPATH_PLUGIN_SDK_H

/*
 * PktPath External eBPF Plugin SDK (ABI v1)
 *
 * Hard Security & Portability Rules (enforced by device/bpf_elf.c):
 *   1. Target ELF64 little-endian EM_BPF (clang -target bpf -O2).
 *   2. ONLY the 3 whitelisted host maps may be referenced:
 *        - rb         (BPF_MAP_TYPE_RINGBUF): event output
 *        - btf_off    (BPF_MAP_TYPE_ARRAY, BPF_MAP_FREEZE read-only)
 *        - plugin_cfg (BPF_MAP_TYPE_ARRAY, BPF_MAP_FREEZE read-only)
 *      Any reference to control / active_slots / calls / socks / cpu_seq or
 *      private maps is REJECTED by the loader.
 *   3. No .rodata / .data / .bss relocations (no global arrays/strings/statics
 *      that require map-value relocation). Keep all constants immediate or in
 *      registers/stack.
 *   4. Emit events with site_dict_idx = PKT_SITE_EXT_SENTINEL (0x7E00). The
 *      collector patches this immediate to a unique runtime site_id in
 *      [0x2000, 0xFFFE] before BPF_PROG_LOAD.
 */

#ifndef __BPF__
#define __BPF__ 1
#endif

#include "pktpath_bpf.h"

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

/* Minimal BPF map definition header (BTF-less legacy struct compatible with
 * PktPath's zero-libbpf ELF64-BPF relocator). */
struct pkt_bpf_map_def {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
};

#define BPF_MAP_TYPE_ARRAY   2U
#define BPF_MAP_TYPE_RINGBUF 27U

/* Whitelisted host maps (bound by symbol name in device/bpf_elf.c) */
struct pkt_bpf_map_def SEC("maps") rb = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .key_size = 0,
    .value_size = 0,
    .max_entries = PKT_DEFAULT_RINGBUF_SZ,
    .map_flags = 0,
};

struct pkt_bpf_map_def SEC("maps") btf_off = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct bpf_btf_offsets),
    .max_entries = 1,
    .map_flags = 0,
};

struct pkt_bpf_map_def SEC("maps") plugin_cfg = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct bpf_plugin_cfg),
    .max_entries = 1,
    .map_flags = 0,
};

/* BPF helper function declarations (stable Linux UAPI helper IDs) */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static uint64_t (*bpf_ktime_get_ns)(void) = (void *)5;
static uint32_t (*bpf_get_smp_processor_id)(void) = (void *)8;
static uint64_t (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_probe_read_kernel)(void *dst, uint32_t size, const void *unsafe_ptr) = (void *)113;
static uint64_t (*bpf_ktime_get_boot_ns)(void) = (void *)125;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, uint64_t size, uint64_t flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, uint64_t flags) = (void *)132;

/* Architecture-specific pt_regs argument accessors */
#if defined(__TARGET_ARCH_arm64)
struct pkt_pt_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};
#define PKT_PT_REGS_PARM1(x) ((x)->regs[0])
#define PKT_PT_REGS_PARM2(x) ((x)->regs[1])
#define PKT_PT_REGS_PARM3(x) ((x)->regs[2])
#define PKT_PT_REGS_RC(x)    ((x)->regs[0])
#elif defined(__TARGET_ARCH_x86)
struct pkt_pt_regs {
    uint64_t r15, r14, r13, r12, bp, bx;
    uint64_t r11, r10, r9, r8;
    uint64_t ax, cx, dx, si, di;
    uint64_t orig_ax, ip, cs, flags, sp, ss;
};
#define PKT_PT_REGS_PARM1(x) ((x)->di)
#define PKT_PT_REGS_PARM2(x) ((x)->si)
#define PKT_PT_REGS_PARM3(x) ((x)->dx)
#define PKT_PT_REGS_RC(x)    ((x)->ax)
#else
#error "Define -D__TARGET_ARCH_arm64 or -D__TARGET_ARCH_x86 when compiling PktPath BPF plugins"
#endif

static __always_inline uint32_t pkt_plugin_read_skb_ifindex(uint64_t skb_ptr) {
    if (!skb_ptr) return 0;
    uint32_t zero = 0;
    struct bpf_btf_offsets *bo = (struct bpf_btf_offsets *)bpf_map_lookup_elem(&btf_off, &zero);
    if (!bo) return 0;
    uint64_t dev_ptr = 0;
    if (bpf_probe_read_kernel(&dev_ptr, sizeof(dev_ptr), (const void *)(skb_ptr + bo->skb_dev)) != 0 || !dev_ptr)
        return 0;
    uint32_t ifindex = 0;
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), (const void *)(dev_ptr + bo->dev_ifindex)) != 0)
        return 0;
    return ifindex;
}

static __always_inline int pkt_plugin_emit_step(uint64_t skb_ptr,
                                                uint8_t dir,
                                                uint8_t stage,
                                                int32_t raw_ret) {
    uint32_t zero = 0;
    struct bpf_plugin_cfg *cfg = (struct bpf_plugin_cfg *)bpf_map_lookup_elem(&plugin_cfg, &zero);
    uint32_t ifindex = pkt_plugin_read_skb_ifindex(skb_ptr);
    if (cfg && cfg->target_ifindex != 0 && ifindex != 0 && ifindex != cfg->target_ifindex)
        return 0;

    struct bpf_ev_step *ev = (struct bpf_ev_step *)bpf_ringbuf_reserve(&rb, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->h.kind          = PKT_EV_STEP;
    ev->h.object_type    = 1;
    ev->h.evidence_level = 1;
    *(volatile uint16_t *)&ev->h.site_dict_idx = (uint16_t)PKT_SITE_EXT_SENTINEL;
    ev->h.flags         = 0;
    ev->h.cpu           = bpf_get_smp_processor_id();
    ev->h.reserved      = 0;
    ev->h.seq           = 0;
    ev->h.ts_ns         = bpf_ktime_get_boot_ns();

    ev->object_id        = skb_ptr;
    ev->visit_or_call_id = 0;
    ev->netns_inum       = 0;
    ev->ifindex          = ifindex;
    ev->qdisc_handle     = 0;
    ev->qdisc_parent     = 0;
    ev->classid          = 0;
    ev->raw_ret          = raw_ret;
    ev->ctx_tid          = (uint32_t)(bpf_get_current_pid_tgid() & 0xFFFFFFFFULL);
    ev->txq              = 0;
    ev->dir              = dir;
    ev->stage            = stage;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}


static __always_inline void
pkt_plugin_emit_tcp_step(uint64_t object_id, const void *sk_ptr,
                         uint32_t ifindex, uint8_t dir,
                         uint8_t stage, int32_t raw_ret)
{
    struct bpf_ev_step *ev = bpf_ringbuf_reserve(&rb, sizeof(*ev), 0);
    if (!ev)
        return;

    uint16_t flags = 0;
    uint32_t tcp_seq = 0;
    uint32_t snd_cwnd = 0;
    uint32_t srtt_us = 0;

    if (sk_ptr) {
        uint32_t zero = 0;
        struct bpf_plugin_cfg *cfg = bpf_map_lookup_elem(&plugin_cfg, &zero);
        if (cfg) {
            uint32_t off_seq  = cfg->extra_off[PKT_PLUG_OFF_TCP_SND_NXT];
            uint32_t off_cwnd = cfg->extra_off[PKT_PLUG_OFF_TCP_SND_CWND];
            uint32_t off_srtt = cfg->extra_off[PKT_PLUG_OFF_TCP_SRTT_US];

            if (off_seq != PKT_PLUG_OFF_UNSET && off_seq < 4096U) {
                uint32_t v = 0;
                if (bpf_probe_read_kernel(&v, sizeof(v), (const char *)sk_ptr + off_seq) == 0) {
                    tcp_seq = v;
                    flags |= (uint16_t)PKT_EVF_HAS_TCP_SEQ;
                }
            }
            if (off_cwnd != PKT_PLUG_OFF_UNSET && off_cwnd < 4096U) {
                uint32_t v = 0;
                if (bpf_probe_read_kernel(&v, sizeof(v), (const char *)sk_ptr + off_cwnd) == 0) {
                    snd_cwnd = v;
                    flags |= (uint16_t)PKT_EVF_HAS_TCP_CWND;
                }
            }
            if (off_srtt != PKT_PLUG_OFF_UNSET && off_srtt < 4096U) {
                uint32_t v = 0;
                if (bpf_probe_read_kernel(&v, sizeof(v), (const char *)sk_ptr + off_srtt) == 0) {
                    srtt_us = v >> 3;
                    flags |= (uint16_t)PKT_EVF_HAS_TCP_SRTT;
                }
            }
        }
    }

    ev->h.kind           = PKT_EV_STEP;
    ev->h.object_type    = PKT_OBJ_SKB;
    ev->h.evidence_level = PKT_EVID_DIRECT;
    *(volatile uint16_t *)&ev->h.site_dict_idx = (uint16_t)PKT_SITE_EXT_SENTINEL;
    ev->h.flags          = flags;
    ev->h.cpu            = bpf_get_smp_processor_id();
    ev->h.reserved       = 0;
    ev->h.seq            = 0;
    ev->h.ts_ns          = bpf_ktime_get_boot_ns();

    ev->object_id        = object_id;
    ev->visit_or_call_id = 0;
    ev->netns_inum       = 0;
    ev->ifindex          = ifindex;
    ev->qdisc_handle     = tcp_seq;
    ev->qdisc_parent     = snd_cwnd;
    ev->classid          = srtt_us;
    ev->raw_ret          = raw_ret;
    ev->ctx_tid          = (uint32_t)bpf_get_current_pid_tgid();
    ev->txq              = 0;
    ev->dir              = dir;
    ev->stage            = stage;

    bpf_ringbuf_submit(ev, 0);
}

static __always_inline void
pkt_plugin_emit_tcp_step_from_skb(const void *skb_ptr, uint32_t ifindex,
                                  uint8_t dir, uint8_t stage, int32_t raw_ret)
{
    const void *sk_ptr = (const void *)0;
    if (skb_ptr) {
        uint32_t zero = 0;
        struct bpf_plugin_cfg *cfg = bpf_map_lookup_elem(&plugin_cfg, &zero);
        if (cfg) {
            uint32_t off_sk = cfg->extra_off[PKT_PLUG_OFF_SKB_SK];
            if (off_sk != PKT_PLUG_OFF_UNSET && off_sk < 512U) {
                const void *tmp = (const void *)0;
                if (bpf_probe_read_kernel(&tmp, sizeof(tmp), (const char *)skb_ptr + off_sk) == 0)
                    sk_ptr = tmp;
            }
        }
    }
    pkt_plugin_emit_tcp_step((uint64_t)(unsigned long)skb_ptr, sk_ptr, ifindex, dir, stage, raw_ret);
}

#endif /* PKTPATH_PLUGIN_SDK_H */
