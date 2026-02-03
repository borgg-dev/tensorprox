#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_test_tx(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // For ICMP, just return XDP_TX without ANY modifications
    // This tests if XDP_TX works at all in this environment
    if (eth->h_proto == bpf_htons(0x0800)) {  // IPv4
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;
        
        if (iph->protocol == 1) {  // ICMP
            return XDP_TX;  // Reflect without modification
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
