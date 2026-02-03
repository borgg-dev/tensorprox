// SPDX-License-Identifier: GPL-2.0
// WireGuard ingress - SNAT to private IP for AWS return traffic

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct wg_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} wg2priv_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct syncookie_pending_key);
    __type(value, struct syncookie_pending_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syncookie_pending_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256000);
    __type(key, struct syncookie_flow_key);
    __type(value, struct syncookie_allow_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syncookie_allow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct syncookie_flow_key);
    __type(value, struct syncookie_forward_stats_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syncookie_reverse_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct syncookie_flow_key);
    __type(value, struct syncookie_seq_delta_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syncookie_seq_delta_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct bypass_key);
    __type(value, struct bypass_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} bypass_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);
    __type(value, struct syncookie_metrics);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syncookie_metrics_map SEC(".maps");

/* Shared map with tc_ingress_wan.c for origin statistics */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);  /* origin_ip */
    __type(value, struct origin_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} origin_stats_map SEC(".maps");

/*
 * AWS Billing: Per-origin egress statistics (PERCPU for scalability)
 *
 * Shared map with wg_egress_monitor.c via pinning:
 * - wg_egress_monitor: updates to_origin_* (requests TO origin)
 * - tc_ingress_wg: updates to_client_* (responses TO client)
 *
 * Key: origin_ip - join with origins table to get EIP in ecp-agent
 * Bytes: L3 (iph->tot_len) - matches AWS data transfer billing
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
 * Shared with wg_egress_monitor.c via pinning.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);      /* wg_ifindex */
    __type(value, __be32);   /* origin_ip */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} wg_ifindex_to_origin_map SEC(".maps");

/* ===== QoS Bandwidth Enforcement Maps ===== */
/* Scrubber-level capacity and configuration (shared with tc_ingress_wan.c) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scrubber_capacity);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} scrubber_capacity_map SEC(".maps");

/* Per-origin bandwidth quota and token bucket state (shared with tc_ingress_wan.c) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);  /* origin_ip */
    __type(value, struct origin_bandwidth);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} origin_bandwidth_map SEC(".maps");

/* Scrubber-level QoS statistics (shared with tc_ingress_wan.c) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, QOS_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_stats_map SEC(".maps");

enum {
    WG_STAT_TOTAL = 0,
    WG_STAT_MAP_HIT = 1,
    WG_STAT_MAP_MISS = 2,
    WG_STAT_SNAT = 3,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} wg_ingress_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 9);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} wan_ingress_stats SEC(".maps");


static __always_inline void bump_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&wg_ingress_stats, &idx);
    if (!val)
        return;
    (*val)++;
}

static __always_inline void bump_wan_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&wan_ingress_stats, &idx);
    if (!val)
        return;
    (*val)++;
}

static __always_inline struct syncookie_metrics *
get_or_init_syncookie_metrics(__be32 dst_eip)
{
    struct syncookie_metrics *metrics =
        bpf_map_lookup_elem(&syncookie_metrics_map, &dst_eip);
    if (!metrics) {
        struct syncookie_metrics zero = {};
        bpf_map_update_elem(&syncookie_metrics_map, &dst_eip, &zero, BPF_NOEXIST);
        metrics = bpf_map_lookup_elem(&syncookie_metrics_map, &dst_eip);
    }
    return metrics;
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return (__u16)(~csum);
}

static __always_inline int send_origin_ack_clone(struct __sk_buff *skb,
                                                 __be32 client_ip,
                                                 __be16 client_port,
                                                 __be16 vip_port,
                                                 __u32 client_seq,
                                                 __u32 origin_seq,
                                                 __be32 origin_ip,
                                                 __u32 redirect_ifindex)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return -1;

    struct tcphdr *tcp = (void *)iph + iph->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return -1;

    int old_tot_len = bpf_ntohs(iph->tot_len);
    int new_tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    int delta = new_tot_len - old_tot_len;

    if (delta != 0) {
        if (bpf_skb_adjust_room(skb, delta, BPF_ADJ_ROOM_NET, 0))
            return -1;
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        iph = data;
        if ((void *)(iph + 1) > data_end)
            return -1;
        tcp = (void *)iph + sizeof(*iph);
        if ((void *)(tcp + 1) > data_end)
            return -1;
    }

    iph->ihl = sizeof(*iph) >> 2;
    iph->tot_len = bpf_htons(new_tot_len);
    iph->ttl = 64;
    iph->tos = 0;
    iph->frag_off = bpf_htons(0x4000);
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = client_ip;
    iph->daddr = origin_ip;

    tcp->source = client_port;
    tcp->dest = vip_port;
    tcp->doff = sizeof(*tcp) >> 2;
    tcp->res1 = 0;
    tcp->fin = 0;
    tcp->syn = 0;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->ack = 1;
    tcp->urg = 0;
    tcp->ece = 0;
    tcp->cwr = 0;
    tcp->window = tcp->window ? tcp->window : bpf_htons(29200);
    tcp->urg_ptr = 0;
    tcp->seq = bpf_htonl(client_seq + 1);
    tcp->ack_seq = bpf_htonl(origin_seq + 1);
    tcp->check = 0;

    __u32 ip_csum = bpf_csum_diff(NULL, 0, (__be32 *)iph, sizeof(*iph), 0);
    iph->check = csum_fold_helper(ip_csum);

    struct tcphdr tcp_tmp = {};
    tcp_tmp.source = tcp->source;
    tcp_tmp.dest = tcp->dest;
    tcp_tmp.seq = tcp->seq;
    tcp_tmp.ack_seq = tcp->ack_seq;
    tcp_tmp.doff = tcp->doff;
    tcp_tmp.res1 = 0;
    tcp_tmp.fin = 0;
    tcp_tmp.syn = 0;
    tcp_tmp.rst = 0;
    tcp_tmp.psh = 0;
    tcp_tmp.ack = 1;
    tcp_tmp.urg = 0;
    tcp_tmp.ece = 0;
    tcp_tmp.cwr = 0;
    tcp_tmp.window = tcp->window;
    tcp_tmp.urg_ptr = 0;

    __u32 pseudo = bpf_htonl((__u32)IPPROTO_TCP << 16 | sizeof(tcp_tmp));
    __u32 tcp_csum = 0;
    tcp_csum = bpf_csum_diff(NULL, 0, &iph->saddr, sizeof(iph->saddr), tcp_csum);
    tcp_csum = bpf_csum_diff(NULL, 0, &iph->daddr, sizeof(iph->daddr), tcp_csum);
    tcp_csum = bpf_csum_diff(NULL, 0, &pseudo, sizeof(pseudo), tcp_csum);
    tcp_csum = bpf_csum_diff(NULL, 0, (__be32 *)&tcp_tmp, sizeof(tcp_tmp), tcp_csum);
    tcp->check = csum_fold_helper(tcp_csum);

    return bpf_clone_redirect(skb, redirect_ifindex, 0);
}
SEC("tc/ingress")
int tc_ingress_wg(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    bump_stat(WG_STAT_TOTAL);

    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->version != 4) return TC_ACT_OK;

    __u32 ifindex = skb->ifindex;
    struct wg_entry *entry = bpf_map_lookup_elem(&wg2priv_map, &ifindex);
    if (!entry) {
        bump_stat(WG_STAT_MAP_MISS);
        return TC_ACT_SHOT;
    }

    bump_stat(WG_STAT_MAP_HIT);
    __be32 origin_ip = iph->saddr;
    __be32 priv_vip_ip = entry->priv_ip;
    __be32 client_ip = iph->daddr;
    __u8 proto = iph->protocol;

    /*
     * AWS Billing: Track egress to client (Egress Path #2)
     *
     * This is traffic FROM origin TO client (responses).
     * Add WireGuard overhead to match AWS billing at ens5 (outer packet).
     * PERCPU map: no atomics, each CPU updates its own counters.
     *
     * Use ifindex lookup to attribute ALL traffic on this WG interface
     * to the same origin (including WG keepalive responses).
     */
    {
        __be32 *billing_origin_ptr = bpf_map_lookup_elem(&wg_ifindex_to_origin_map, &ifindex);
        if (billing_origin_ptr) {
            __be32 billing_origin = *billing_origin_ptr;
            /* L3 bytes + WG overhead = what AWS actually bills */
            __u32 billable_bytes = bpf_ntohs(iph->tot_len) + WIREGUARD_OVERHEAD_BYTES;
            struct egress_billing_stats *billing = bpf_map_lookup_elem(&egress_billing_map, &billing_origin);

            if (billing) {
                /* Fast path: origin already tracked */
                billing->to_client_packets++;
                billing->to_client_bytes += billable_bytes;
            } else {
                /* New origin - initialize (rare, once per origin per CPU) */
                struct egress_billing_stats init = {
                    .to_origin_packets = 0,
                    .to_origin_bytes = 0,
                    .to_client_packets = 1,
                    .to_client_bytes = billable_bytes,
                };
                bpf_map_update_elem(&egress_billing_map, &billing_origin, &init, BPF_ANY);
            }
        }
    }

    if (proto == IPPROTO_TCP) {
        struct tcphdr *th = (void *)iph + iph->ihl * 4;
        if ((void *)(th + 1) <= data_end) {
            __u8 tcp_flags = *((__u8 *)th + 13);
            if ((tcp_flags & (0x12)) == 0x12) {
                __be16 client_port = th->dest;
                __be16 vip_port = th->source;

                struct syncookie_pending_key pending_key = {
                    .client_ip = client_ip,
                    .vip_ip = priv_vip_ip,
                    .client_port = client_port,
                    .vip_port = vip_port,
                };

                struct syncookie_pending_entry *pending =
                    bpf_map_lookup_elem(&syncookie_pending_map, &pending_key);

                if (pending) {
                    __be32 dst_eip = pending_key.vip_ip;
                    bpf_debug("wg pending hit client=%x vip=%x\n",
                               bpf_ntohl(client_ip), bpf_ntohl(dst_eip));
                    bpf_debug("wg pending ports c=%u v=%u\n",
                               bpf_ntohs(client_port), bpf_ntohs(vip_port));
                    __u64 now_ns = bpf_ktime_get_ns();
                    __u32 now_sec = (__u32)(now_ns / NS_PER_SEC);
                    if (now_sec > pending->expires_at) {
                        pending->state = SYNCOOKIE_PENDING_EXPIRED;
                        bpf_map_delete_elem(&syncookie_pending_map, &pending_key);
                    } else {
                        struct syncookie_metrics *metrics =
                            get_or_init_syncookie_metrics(pending->origin_ip);
                        if (metrics)
                            metrics->last_update_ts = now_sec;
                        __u32 redirect_ifindex = pending->wg_ifindex ? pending->wg_ifindex : skb->ifindex;

                        __u32 pending_client_seq = pending->client_seq;
                        __u32 origin_seq = bpf_ntohl(th->seq);

                        int ack_ret = send_origin_ack_clone(skb,
                                                            client_ip,
                                                            client_port,
                                                            vip_port,
                                                            pending_client_seq,
                                                            origin_seq,
                                                            pending->origin_ip,
                                                            redirect_ifindex);
                        bpf_debug("wg ack clone ret=%d\n", ack_ret);
                        if (ack_ret < 0) {
                            bpf_debug("wg ack clone ifindex=%u\n", redirect_ifindex);
                            return ack_ret;
                        }

                        struct syncookie_flow_key flow = {
                            .src_ip = client_ip,
                            .dst_eip = dst_eip,
                            .src_port = client_port,
                            .dst_port = vip_port
                        };
                        struct syncookie_allow_entry allow_entry = {
                            .expires_at = now_sec + 90,
                            .validated_at = now_sec
                        };

                        bpf_debug("wg allow insert src=%x dst=%x ttl=%u\n",
                                   bpf_ntohl(flow.src_ip),
                                   bpf_ntohl(flow.dst_eip),
                                   allow_entry.expires_at - now_sec);
                        bpf_debug("wg allow insert sport=%u dport=%u\n",
                                   bpf_ntohs(flow.src_port),
                                   bpf_ntohs(flow.dst_port));

                        int allow_ret = bpf_map_update_elem(&syncookie_allow_map, &flow, &allow_entry, BPF_ANY);
                        bpf_debug("wg allow ret=%d\n", allow_ret);

                        struct bypass_key bkey = {
                            .src_ip = client_ip,
                            .src_port = client_port,
                            .vip_ip = dst_eip,
                            .dst_port = vip_port
                        };
                        struct bypass_entry bentry = {
                            .expires_at_ns = now_ns + (BYPASS_TTL_SEC * NS_PER_SEC),
                            .validated_ts = now_sec,
                            .reserved = 0
                        };
                        int bypass_ret = bpf_map_update_elem(&bypass_map, &bkey, &bentry, BPF_ANY);
                        bpf_debug("wg bypass ret=%d\n", bypass_ret);

                        struct syncookie_seq_delta_entry delta_entry = {
                            .client_delta = 0,
                            .server_delta = (__s32)((__s64)pending->cookie_value - (__s64)origin_seq),
                            .expires_at = now_sec + 90,
                        };
                        bpf_map_update_elem(&syncookie_seq_delta_map, &flow, &delta_entry, BPF_ANY);

                        if (metrics)
                            __sync_fetch_and_add(&metrics->handshake_completes, 1);

                        pending->state = SYNCOOKIE_PENDING_COMPLETED;
                        bpf_map_delete_elem(&syncookie_pending_map, &pending_key);
                        bump_wan_stat(WAN_STAT_SYNCOOKIE_ACK_OK);

                        bpf_debug("wg pending promoted client=%x vip=%x\n",
                                   bpf_ntohl(client_ip), bpf_ntohl(dst_eip));
                        return TC_ACT_SHOT;
                    }
                } else {
                    bpf_debug("wg pending miss client=%x vip=%x\n",
                               bpf_ntohl(client_ip), bpf_ntohl(priv_vip_ip));
                    bpf_debug("wg pending miss ports c=%u v=%u\n",
                               bpf_ntohs(client_port), bpf_ntohs(vip_port));
                }
            }
        } else {
            return TC_ACT_OK;
        }
    }

    /* ===== QoS Egress Bandwidth ENFORCEMENT ===== */
    /*
     * ENFORCE on egress - Origin responses are TRUSTED clean traffic.
     * Safe to drop here if origin is over-using allocated bandwidth.
     * Origin can't "attack" its own quota - this protects the scrubber.
     */
    {
        __u32 cap_key = 0;
        struct scrubber_capacity *cap = bpf_map_lookup_elem(&scrubber_capacity_map, &cap_key);

        int qos_result = qos_enforce_egress_inline(
            origin_ip,            /* origin_ip as key */
            skb->len,             /* packet size in bytes */
            cap,
            &origin_bandwidth_map,
            &qos_stats_map);

        if (qos_result == 0) {
            /* Over quota in enforce mode - drop origin response */
            return TC_ACT_SHOT;
        }
    }

    iph->saddr = priv_vip_ip;
    bpf_l3_csum_replace(skb, (long)&iph->check - (long)data, origin_ip, priv_vip_ip, sizeof(__be32));

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    iph = data;
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    bump_stat(WG_STAT_SNAT);

    if (proto == IPPROTO_TCP) {
        /* Extract TCP flags BEFORE checksum replace (for BPF verifier) */
        struct tcphdr *th = (void *)iph + iph->ihl * 4;
        __u8 tcp_flags = 0;
            if ((void *)(th + 1) <= data_end) {
                tcp_flags = *((__u8 *)th + 13);

                struct syncookie_flow_key delta_key = {
                    .src_ip = client_ip,
                    .dst_eip = priv_vip_ip,
                    .src_port = th->dest,
                    .dst_port = th->source,
                };
                struct syncookie_seq_delta_entry *delta =
                    bpf_map_lookup_elem(&syncookie_seq_delta_map, &delta_key);
                if (delta) {
                    __u32 now_sec_delta = (__u32)(bpf_ktime_get_ns() / NS_PER_SEC);
                    if (now_sec_delta > delta->expires_at) {
                        bpf_map_delete_elem(&syncookie_seq_delta_map, &delta_key);
                    } else if (delta->server_delta) {
                        __s64 seq_host = (__s64)bpf_ntohl(th->seq);
                        seq_host += (__s64)delta->server_delta;
                        __be32 old_seq = th->seq;
                        __be32 new_seq = bpf_htonl((__u32)seq_host);
                        th->seq = new_seq;
                        bpf_l4_csum_replace(skb,
                                            (long)&th->check - (long)data,
                                            old_seq,
                                            new_seq,
                                            sizeof(old_seq));
                    }
                }

                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                iph = data;
                if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
                th = (void *)iph + iph->ihl * 4;
                if ((void *)(th + 1) > data_end) return TC_ACT_OK;

            int total_len = bpf_ntohs(iph->tot_len);
            int ip_header_len = iph->ihl * 4;
            int tcp_header_len = th->doff * 4;
            int payload_len = total_len - ip_header_len - tcp_header_len;
            if (payload_len > 0) {
                struct syncookie_flow_key flow_key = {
                    .src_ip = client_ip,
                    .dst_eip = priv_vip_ip,
                    .src_port = th->dest,
                    .dst_port = th->source,
                };

                __u32 now_sec = (__u32)(bpf_ktime_get_ns() / NS_PER_SEC);
                struct syncookie_forward_stats_entry *stat =
                    bpf_map_lookup_elem(&syncookie_reverse_stats_map, &flow_key);
                if (stat) {
                    __sync_fetch_and_add(&stat->packets, 1);
                    __sync_fetch_and_add(&stat->bytes, (__u64)payload_len);
                    stat->last_seen = now_sec;
                } else {
                    struct syncookie_forward_stats_entry init = {
                        .packets = 1,
                        .bytes = (__u64)payload_len,
                        .last_seen = now_sec,
                        .reserved = 0,
                    };
                    bpf_map_update_elem(&syncookie_reverse_stats_map, &flow_key, &init, BPF_ANY);
                    bpf_debug("wg payload egress src=%x sport=%u len=%d\n",
                               bpf_ntohl(flow_key.src_ip),
                               bpf_ntohs(flow_key.src_port),
                               payload_len);
                }
            }

            bpf_l4_csum_replace(skb, (void *)&th->check - (void *)iph, origin_ip, priv_vip_ip,
                                sizeof(__be32) | BPF_F_PSEUDO_HDR);
        }

        /* CRITICAL FIX: Track SYN-ACK on egress (origin→client) for REAL attack detection */
        __u8 syn = tcp_flags & 0x02;
        __u8 ack = tcp_flags & 0x10;

        if (syn && ack) {
            /* This is a SYN-ACK from origin to client - the REAL legitimacy indicator! */
            struct origin_stats *stats = bpf_map_lookup_elem(&origin_stats_map, &origin_ip);
            if (stats) {
                __sync_fetch_and_add(&stats->egress_synack_count, 1);
            }
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *uh = (void *)iph + iph->ihl * 4;
        if ((void *)(uh + 1) <= data_end && uh->check)
            bpf_l4_csum_replace(skb, (void *)&uh->check - (void *)iph, origin_ip, priv_vip_ip,
                                sizeof(__be32) | BPF_F_PSEUDO_HDR);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
