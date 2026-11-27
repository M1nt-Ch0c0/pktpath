/*
 * PktPath Official Wave 3 pwru Probe Plugin (ABI v1)
 *
 * Implements optional pwru-style ingress, L3 routing, Netfilter/NAT, TCP
 * diagnostics, and opt-in high-noise tcp_probe hooks using only the frozen
 * read-only host maps (btf_off, plugin_cfg) and ringbuf (rb).
 *
 * Note on nf_hook_slow kprobe/kretprobe:
 *   kp_nf_hook_slow and kr_nf_hook_slow are separate independent sections so
 *   that if kretprobe attach fails, probe_inventory records attach_failed for
 *   kr_nf_hook_slow while kp_nf_hook_slow stays attached and verdict remains
 *   unobserved.
 */

#include "../../include/pktpath_plugin_sdk.h"

/* ---- Group: ingress_rx ---- */

struct tp_netif_receive_skb_ctx {
    uint64_t pad;
    uint64_t skbaddr;
};

SEC("tp_netif_receive_skb")
int prog_tp_netif_receive_skb(struct tp_netif_receive_skb_ctx *ctx) {
    uint64_t skb = 0;
    bpf_probe_read_kernel(&skb, sizeof(skb), &ctx->skbaddr);
    return pkt_plugin_emit_step(skb, PKT_DIR_RX, PKT_STAGE_ENTRY, 0);
}

SEC("kp_ip_rcv")
int prog_kp_ip_rcv(struct pkt_pt_regs *ctx) {
    return pkt_plugin_emit_step(PKT_PT_REGS_PARM1(ctx), PKT_DIR_RX, PKT_STAGE_HANDOFF_LAYER, 0);
}

SEC("kp_ipv6_rcv")
int prog_kp_ipv6_rcv(struct pkt_pt_regs *ctx) {
    return pkt_plugin_emit_step(PKT_PT_REGS_PARM1(ctx), PKT_DIR_RX, PKT_STAGE_HANDOFF_LAYER, 0);
}

SEC("kp_tcp_v4_rcv")
int prog_kp_tcp_v4_rcv(struct pkt_pt_regs *ctx) {
    return pkt_plugin_emit_step(PKT_PT_REGS_PARM1(ctx), PKT_DIR_RX, PKT_STAGE_DELIVER_SOCK, 0);
}

SEC("kp_udp_rcv")
int prog_kp_udp_rcv(struct pkt_pt_regs *ctx) {
    return pkt_plugin_emit_step(PKT_PT_REGS_PARM1(ctx), PKT_DIR_RX, PKT_STAGE_DELIVER_SOCK, 0);
}

/* ---- Group: l3_route ---- */

SEC("kp_ip_route_input_noref")
int prog_kp_ip_route_input_noref(struct pkt_pt_regs *ctx) {
    return pkt_plugin_emit_step(PKT_PT_REGS_PARM1(ctx), PKT_DIR_RX, PKT_STAGE_CLASSIFY, 0);
}

SEC("kp_ip_route_output_flow")
int prog_kp_ip_route_output_flow(struct pkt_pt_regs *ctx) {
    /* net, flp4, sk -> object_id = sk (parm3) */
    return pkt_plugin_emit_step(PKT_PT_REGS_PARM3(ctx), PKT_DIR_TX, PKT_STAGE_CLASSIFY, 0);
}

SEC("kp_ip_forward")
int prog_kp_ip_forward(struct pkt_pt_regs *ctx) {
    return pkt_plugin_emit_step(PKT_PT_REGS_PARM1(ctx), PKT_DIR_FWD, PKT_STAGE_HANDOFF_LAYER, 0);
}

SEC("kp_ip_output")
int prog_kp_ip_output(struct pkt_pt_regs *ctx) {
    /* net, sk, skb -> parm3 is skb */
    return pkt_plugin_emit_step(PKT_PT_REGS_PARM3(ctx), PKT_DIR_TX, PKT_STAGE_HANDOFF_LAYER, 0);
}

SEC("kp_ip6_output")
int prog_kp_ip6_output(struct pkt_pt_regs *ctx) {
    /* net, sk, skb -> parm3 is skb */
    return pkt_plugin_emit_step(PKT_PT_REGS_PARM3(ctx), PKT_DIR_TX, PKT_STAGE_HANDOFF_LAYER, 0);
}

SEC("kp_xfrm_output")
int prog_kp_xfrm_output(struct pkt_pt_regs *ctx) {
    /* sk, skb -> parm2 is skb */
    return pkt_plugin_emit_step(PKT_PT_REGS_PARM2(ctx), PKT_DIR_TX, PKT_STAGE_HANDOFF_LAYER, 0);
}

SEC("kp_xfrm_input")
int prog_kp_xfrm_input(struct pkt_pt_regs *ctx) {
    return pkt_plugin_emit_step(PKT_PT_REGS_PARM1(ctx), PKT_DIR_RX, PKT_STAGE_HANDOFF_LAYER, 0);
}

/* ---- Group: netfilter_nat ---- */

SEC("kp_nf_hook_slow")
int prog_kp_nf_hook_slow(struct pkt_pt_regs *ctx) {
    return pkt_plugin_emit_step(PKT_PT_REGS_PARM1(ctx), PKT_DIR_FWD, PKT_STAGE_CLASSIFY, 0);
}

SEC("kr_nf_hook_slow")
int prog_kr_nf_hook_slow(struct pkt_pt_regs *ctx) {
    int32_t verdict = (int32_t)PKT_PT_REGS_RC(ctx);
    return pkt_plugin_emit_step(0, PKT_DIR_FWD, PKT_STAGE_CLASSIFY, verdict);
}

SEC("kp_nf_conntrack_in")
int prog_kp_nf_conntrack_in(struct pkt_pt_regs *ctx) {
    /* skb is parm1 on >=5.10 nf_conntrack_in(struct sk_buff *skb, const struct nf_hook_state *state) */
    return pkt_plugin_emit_step(PKT_PT_REGS_PARM1(ctx), PKT_DIR_FWD, PKT_STAGE_CLASSIFY, 0);
}

SEC("kp_nf_nat_packet")
int prog_kp_nf_nat_packet(struct pkt_pt_regs *ctx) {
    /* ct, ctinfo, hooknum, skb -> use parm1 (ct) as correlation id */
    return pkt_plugin_emit_step(PKT_PT_REGS_PARM1(ctx), PKT_DIR_FWD, PKT_STAGE_HANDOFF_LAYER, 0);
}

/* ---- Group: tcp_diag ---- */

struct tp_tcp_retransmit_skb_ctx {
    uint64_t pad;
    uint64_t skbaddr;
    uint64_t skaddr;
};

SEC("tp_tcp_retransmit_skb")
int prog_tp_tcp_retransmit_skb(struct tp_tcp_retransmit_skb_ctx *ctx) {
    uint64_t skb = 0;
    bpf_probe_read_kernel(&skb, sizeof(skb), &ctx->skbaddr);
    return pkt_plugin_emit_step(skb, PKT_DIR_TX, PKT_STAGE_REQUEUE_GSO, 0);
}

struct tp_inet_sock_set_state_ctx {
    uint64_t pad;
    uint64_t skaddr;
    int32_t  oldstate;
    int32_t  newstate;
};

SEC("tp_inet_sock_set_state")
int prog_tp_inet_sock_set_state(struct tp_inet_sock_set_state_ctx *ctx) {
    uint64_t sk = 0;
    int32_t newst = 0;
    bpf_probe_read_kernel(&sk, sizeof(sk), &ctx->skaddr);
    bpf_probe_read_kernel(&newst, sizeof(newst), &ctx->newstate);
    return pkt_plugin_emit_step(sk, PKT_DIR_TX, PKT_STAGE_HANDOFF_LAYER, newst);
}

/* ---- Group: tcp_probe (9th opt-in high-noise group) ---- */

struct tp_tcp_probe_ctx {
    uint64_t pad;
    uint8_t  saddr[28];
    uint8_t  daddr[28];
    uint16_t sport;
    uint16_t dport;
    uint16_t family;
    uint32_t mark;
    uint16_t data_len;
    uint32_t snd_nxt;
    uint32_t snd_una;
    uint32_t snd_cwnd;
};

SEC("tp_tcp_probe")
int prog_tp_tcp_probe(struct tp_tcp_probe_ctx *ctx) {
    uint32_t cwnd = 0;
    bpf_probe_read_kernel(&cwnd, sizeof(cwnd), &ctx->snd_cwnd);
    return pkt_plugin_emit_step(0, PKT_DIR_TX, PKT_STAGE_HANDOFF_LAYER, (int32_t)cwnd);
}

char _license[] SEC("license") = "GPL";
