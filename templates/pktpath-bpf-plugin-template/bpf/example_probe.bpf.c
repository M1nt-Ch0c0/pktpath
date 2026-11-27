// Minimal CO-RE eBPF tracepoint example for PktPath external BPF plugin (ABI v1).
// Build with clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 -c bpf/example_probe.bpf.c -o bpf/arm64/example_probe.bpf.o

#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp_netif_receive_skb")
int tp_netif_receive_skb(void *ctx)
{
    (void)ctx;
    // Extend this hook using PktPath's shared ringbuf/config maps as documented in Wave 3 ABI v1.
    return 0;
}
