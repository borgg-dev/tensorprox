// SPDX-License-Identifier: GPL-2.0
/*
 * XDP Metrics Collection for Exit Hub
 *
 * This XDP program runs on TPM-owned exit hubs to collect ground-truth
 * production metrics that cannot be gamed by miners.
 *
 * Tracks per-origin:
 *   - Packets passed (ingress from internet, egress to origin)
 *   - SYN packets (connection attempts)
 *   - SYN-ACK packets (successful handshakes from scrubber)
 *   - Bytes transferred
 *   - TCP flags distribution
 *
 * Pinned maps at /sys/fs/bpf/xdp/globals/
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Per-origin metrics structure */
struct origin_metrics {
    __u64 packets_in;           /* Packets from internet toward origin */
    __u64 packets_out;          /* Packets from origin toward internet */
    __u64 bytes_in;             /* Bytes from internet */
    __u64 bytes_out;            /* Bytes to internet */
    __u64 syn_count;            /* SYN packets (connection attempts) */
    __u64 synack_count;         /* SYN-ACK packets (successful from scrubber) */
    __u64 fin_count;            /* FIN packets */
    __u64 rst_count;            /* RST packets */
    __u64 ack_count;            /* Pure ACK packets */
    __u64 data_packets;         /* Packets with payload */
    __u64 last_update_ns;       /* Timestamp of last update */
};

/* Global aggregate metrics */
struct global_metrics {
    __u64 total_packets;
    __u64 total_bytes;
    __u64 total_syn;
    __u64 total_synack;
    __u64 xdp_pass;
    __u64 xdp_drop;
    __u64 parse_errors;
    __u64 last_update_ns;
};

/* Map: Origin IP -> Metrics
 * Key: __be32 (origin IP in network byte order)
 * Value: struct origin_metrics
 *
 * Pinned at: /sys/fs/bpf/xdp/globals/origin_metrics_map
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __be32);
    __type(value, struct origin_metrics);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} origin_metrics_map SEC(".maps");

/* Map: Global metrics (single entry, key=0)
 * Pinned at: /sys/fs/bpf/xdp/globals/global_metrics_map
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_metrics);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} global_metrics_map SEC(".maps");

/* Map: Known origin IPs to monitor
 * Key: __be32 (origin IP)
 * Value: __u32 (1 = monitor this origin)
 *
 * Populated by userspace when origins are registered
 * Pinned at: /sys/fs/bpf/xdp/globals/monitored_origins_map
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __be32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} monitored_origins_map SEC(".maps");

/* Helper: Check if IP is a monitored origin */
static __always_inline int is_monitored_origin(__be32 ip)
{
    __u32 *val = bpf_map_lookup_elem(&monitored_origins_map, &ip);
    return val != NULL;
}

/* Helper: Update origin metrics */
static __always_inline void update_origin_metrics(
    __be32 origin_ip,
    __u32 pkt_len,
    __u8 tcp_flags,
    int is_ingress)  /* 1 = from internet, 0 = from origin */
{
    struct origin_metrics *metrics;
    struct origin_metrics new_metrics = {0};

    metrics = bpf_map_lookup_elem(&origin_metrics_map, &origin_ip);
    if (!metrics) {
        /* First packet for this origin - initialize */
        bpf_map_update_elem(&origin_metrics_map, &origin_ip, &new_metrics, BPF_NOEXIST);
        metrics = bpf_map_lookup_elem(&origin_metrics_map, &origin_ip);
        if (!metrics)
            return;
    }

    /* Update counters atomically */
    if (is_ingress) {
        __sync_fetch_and_add(&metrics->packets_in, 1);
        __sync_fetch_and_add(&metrics->bytes_in, pkt_len);
    } else {
        __sync_fetch_and_add(&metrics->packets_out, 1);
        __sync_fetch_and_add(&metrics->bytes_out, pkt_len);
    }

    /* Track TCP flags */
    if (tcp_flags & 0x02) {  /* SYN */
        if (tcp_flags & 0x10) {  /* SYN-ACK */
            __sync_fetch_and_add(&metrics->synack_count, 1);
        } else {
            __sync_fetch_and_add(&metrics->syn_count, 1);
        }
    }
    if (tcp_flags & 0x01) {  /* FIN */
        __sync_fetch_and_add(&metrics->fin_count, 1);
    }
    if (tcp_flags & 0x04) {  /* RST */
        __sync_fetch_and_add(&metrics->rst_count, 1);
    }
    if ((tcp_flags & 0x10) && !(tcp_flags & 0x02)) {  /* Pure ACK (no SYN) */
        __sync_fetch_and_add(&metrics->ack_count, 1);
    }

    /* Track data packets (packets with payload beyond headers) */
    if (pkt_len > (sizeof(struct ethhdr) + sizeof(struct iphdr) + 20)) {
        __sync_fetch_and_add(&metrics->data_packets, 1);
    }

    metrics->last_update_ns = bpf_ktime_get_ns();
}

/* Helper: Update global metrics */
static __always_inline void update_global_metrics(
    __u32 pkt_len,
    __u8 tcp_flags,
    int action)  /* XDP_PASS or XDP_DROP */
{
    __u32 key = 0;
    struct global_metrics *gm;

    gm = bpf_map_lookup_elem(&global_metrics_map, &key);
    if (!gm)
        return;

    __sync_fetch_and_add(&gm->total_packets, 1);
    __sync_fetch_and_add(&gm->total_bytes, pkt_len);

    if (tcp_flags & 0x02) {
        if (tcp_flags & 0x10)
            __sync_fetch_and_add(&gm->total_synack, 1);
        else
            __sync_fetch_and_add(&gm->total_syn, 1);
    }

    if (action == XDP_PASS)
        __sync_fetch_and_add(&gm->xdp_pass, 1);
    else
        __sync_fetch_and_add(&gm->xdp_drop, 1);

    gm->last_update_ns = bpf_ktime_get_ns();
}

SEC("xdp")
int xdp_metrics(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len = data_end - data;

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto pass;

    /* Only process IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        goto pass;

    /* Parse IP header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        goto pass;

    if (ip->ihl < 5)
        goto pass;

    __be32 src_ip = ip->saddr;
    __be32 dst_ip = ip->daddr;
    __u8 tcp_flags = 0;

    /* Parse TCP header for flags */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            goto pass;

        /* Extract TCP flags (offset 13 in TCP header) */
        tcp_flags = (((__u8 *)tcp)[13]);
    }

    /* Check if source or destination is a monitored origin */
    int src_monitored = is_monitored_origin(src_ip);
    int dst_monitored = is_monitored_origin(dst_ip);

    if (dst_monitored) {
        /* Traffic TO origin (from internet via scrubber) */
        update_origin_metrics(dst_ip, pkt_len, tcp_flags, 1);
    }

    if (src_monitored) {
        /* Traffic FROM origin (responses going out) */
        update_origin_metrics(src_ip, pkt_len, tcp_flags, 0);
    }

    /* Update global metrics */
    update_global_metrics(pkt_len, tcp_flags, XDP_PASS);

pass:
    /* Exit hub doesn't drop packets - just monitors */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
