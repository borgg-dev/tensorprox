// SPDX-License-Identifier: GPL-2.0
// TC audit redirect - redirects WireGuard audit traffic to veth pair for XDP processing
//
// This program is attached to the WireGuard audit interface (wg_audit_XX) ingress.
// It redirects all packets to veth_in, which then flows to veth_out where XDP
// processes the packets with full attack filtering.
//
// This ensures audit traffic is counted SEPARATELY from eth0 global traffic.

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Map to store the target interface index for redirection
// Key: 0 (single entry)
// Value: ifindex of veth_in
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} audit_redirect_target SEC(".maps");

// Stats map for audit-specific counting
// This is separate from xdp_wan_stats so we count ONLY audit packets
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} audit_stats SEC(".maps");

// Stats indices
#define AUDIT_STAT_REDIRECTED 0
#define AUDIT_STAT_DROPPED    1
#define AUDIT_STAT_PASSED     2

static __always_inline void audit_stat_inc(__u32 idx)
{
    __u64 *counter = bpf_map_lookup_elem(&audit_stats, &idx);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

SEC("tc/ingress")
int tc_audit_redirect(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u32 *target_ifindex;

    // Look up the target interface index
    target_ifindex = bpf_map_lookup_elem(&audit_redirect_target, &key);
    if (!target_ifindex || *target_ifindex == 0) {
        // No redirect target configured, pass through
        audit_stat_inc(AUDIT_STAT_PASSED);
        return TC_ACT_OK;
    }

    // Redirect packet to veth_in interface ingress queue
    // BPF_F_INGRESS (1) redirects to target's ingress path, which then flows
    // through the veth pair to veth_out where XDP is attached
    int ret = bpf_redirect(*target_ifindex, BPF_F_INGRESS);
    if (ret == TC_ACT_REDIRECT) {
        audit_stat_inc(AUDIT_STAT_REDIRECTED);
    } else {
        audit_stat_inc(AUDIT_STAT_DROPPED);
    }

    return ret;
}

char _license[] SEC("license") = "GPL";
