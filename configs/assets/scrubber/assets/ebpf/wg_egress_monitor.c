// SPDX-License-Identifier: GPL-2.0
/*
 * WireGuard Egress Monitor - Per-origin egress tracking for AWS billing
 *
 * Hook: TC egress on wgO* interfaces (before WireGuard encryption)
 * Purpose: Track bytes/packets going TO origin (Egress Path #1)
 *
 * This captures client requests BEFORE WireGuard encrypts them,
 * allowing per-origin attribution. After encryption, we can only see
 * the outer UDP packet to the exit hub.
 *
 * Bytes tracked: L3 (iph->tot_len) - matches AWS data transfer billing
 * Map type: PERCPU_HASH - no atomic contention at 14M+ PPS
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

/*
 * Per-origin egress billing map (PERCPU for maximum throughput)
 *
 * Key: origin_ip (destination IP on wgO* egress = origin being reached)
 * Value: egress_billing_stats (per-CPU counters, no atomics needed)
 *
 * This map is shared with tc_ingress_wg.c via pinning.
 * - wg_egress_monitor: updates to_origin_* fields
 * - tc_ingress_wg: updates to_client_* fields
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);  /* origin_ip */
    __type(value, struct egress_billing_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_billing_map SEC(".maps");

/*
 * WireGuard ifindex to origin_ip mapping for billing attribution.
 * All traffic on a WG interface gets billed to the same origin.
 * Populated by configure-origin.py, shared with tc_ingress_wg.c via pinning.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);      /* wg_ifindex */
    __type(value, __be32);   /* origin_ip */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} wg_ifindex_to_origin_map SEC(".maps");

/*
 * Global stats for debugging/monitoring (lightweight, per-CPU array)
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} wg_egress_stats SEC(".maps");

enum wg_egress_stat_idx {
    WG_EGRESS_TOTAL = 0,      /* Total packets processed */
    WG_EGRESS_IPV4 = 1,       /* IPv4 packets */
    WG_EGRESS_TRACKED = 2,    /* Packets with origin_ip in map */
    WG_EGRESS_UNTRACKED = 3,  /* Packets without origin_ip (new origin) */
};

static __always_inline void bump_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&wg_egress_stats, &idx);
    if (val)
        (*val)++;
}

SEC("tc/egress")
int wg_egress_monitor(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    bump_stat(WG_EGRESS_TOTAL);

    /*
     * WireGuard interfaces are L3 (no Ethernet header)
     * Packet starts directly with IP header
     */
    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    if (iph->version != 4)
        return TC_ACT_OK;

    bump_stat(WG_EGRESS_IPV4);

    /*
     * Look up origin_ip by interface index.
     * All traffic on a WireGuard interface (to origin IP or WG peer keepalives)
     * should be billed to the same origin that this tunnel serves.
     */
    __u32 ifindex = skb->ifindex;
    __be32 *origin_ip_ptr = bpf_map_lookup_elem(&wg_ifindex_to_origin_map, &ifindex);
    if (!origin_ip_ptr) {
        /* Interface not configured for billing - skip */
        return TC_ACT_OK;
    }
    __be32 origin_ip = *origin_ip_ptr;

    /*
     * L3 bytes = iph->tot_len (IP header + payload)
     * Add WireGuard overhead to match what AWS actually bills at ens5
     * (outer encapsulated packet is larger than inner packet we see here)
     */
    __u32 billable_bytes = bpf_ntohs(iph->tot_len) + WIREGUARD_OVERHEAD_BYTES;

    /*
     * Lookup or initialize per-origin stats
     * PERCPU map: each CPU has its own counter, no atomics needed
     */
    struct egress_billing_stats *stats = bpf_map_lookup_elem(&egress_billing_map, &origin_ip);

    if (stats) {
        /* Fast path: origin already tracked */
        stats->to_origin_packets++;
        stats->to_origin_bytes += billable_bytes;
        bump_stat(WG_EGRESS_TRACKED);
    } else {
        /*
         * New origin - initialize entry
         * This happens once per origin per CPU, then fast path
         */
        struct egress_billing_stats init = {
            .to_origin_packets = 1,
            .to_origin_bytes = billable_bytes,
            .to_client_packets = 0,
            .to_client_bytes = 0,
        };
        bpf_map_update_elem(&egress_billing_map, &origin_ip, &init, BPF_ANY);
        bump_stat(WG_EGRESS_UNTRACKED);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
