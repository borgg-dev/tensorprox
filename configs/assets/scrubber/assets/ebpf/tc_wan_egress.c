// SPDX-License-Identifier: GPL-2.0
// TC egress on WAN - Reverse SNAT (Origin IP -> Private IP for AWS EIP mapping)
//
// NOTE: QoS enforcement is handled upstream in tc_ingress_wg.c (on WireGuard interfaces)
// This program ONLY does reverse SNAT for AWS EIP mapping.

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

// Minimal struct for reverse lookup
struct reverse_nat_entry {
    __be32 priv_ip;  // Private IP to SNAT to
};

// Reverse lookup map: Origin IP -> Private IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);  // origin_ip
    __type(value, struct reverse_nat_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} origin_to_priv_map SEC(".maps");

static __always_inline void update_iph_checksum(struct iphdr *iph)
{
    __u32 csum = 0;
    __u16 *buf = (__u16 *)iph;

    iph->check = 0;

    for (int i = 0; i < sizeof(*iph) >> 1; i++)
        csum += buf[i];

    csum = (csum >> 16) + (csum & 0xffff);
    csum += (csum >> 16);

    iph->check = ~csum;
}

SEC("cls_egress")
int tc_wan_egress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    // Check if source is an Origin IP (reply traffic)
    __be32 origin_ip = iph->saddr;
    struct reverse_nat_entry *entry = bpf_map_lookup_elem(&origin_to_priv_map, &origin_ip);

    if (!entry)
        return TC_ACT_OK; // Not origin traffic, pass through

    // Store old source IP for checksum delta
    __be32 old_saddr = iph->saddr;
    __be32 new_saddr = entry->priv_ip;

    // Reverse SNAT: Replace origin IP with private IP
    // AWS will then map private IP -> EIP automatically
    iph->saddr = new_saddr;

    // Recalculate IP header checksum
    update_iph_checksum(iph);

    // Update L4 checksum for IP address change
    __u32 csum_diff = bpf_csum_diff(&old_saddr, 4, &new_saddr, 4, 0);

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(iph + 1);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        __u32 tcp_csum_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
        bpf_l4_csum_replace(skb, tcp_csum_off, 0, csum_diff, BPF_F_PSEUDO_HDR);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(iph + 1);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        if (udp->check != 0) {
            __u32 udp_csum_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check);
            bpf_l4_csum_replace(skb, udp_csum_off, 0, csum_diff, BPF_F_PSEUDO_HDR);
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
