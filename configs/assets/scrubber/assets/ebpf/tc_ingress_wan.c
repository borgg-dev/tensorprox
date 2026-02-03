// SPDX-License-Identifier: GPL-2.0
// WAN ingress (ens5) - DNAT and hand back to kernel routing

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

#ifndef BPF_F_EGRESS
#define BPF_F_EGRESS (1ULL << 1)
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);
    __type(value, struct eip_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} eip_map SEC(".maps");

/* Connection tracking: maps 5-tuple to origin_ip */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1048576);  /* 1M connections after optimization */
    __type(key, struct conn_key);
    __type(value, __be32);  /* origin_ip */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} active_conns SEC(".maps");

/* Per-origin lifetime statistics (monotonic counters) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);  /* max origins */
    __type(key, __be32);  /* origin_ip */
    __type(value, struct origin_stats);  /* 8 x u64 = 64 bytes */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} origin_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syncookie_mode_map SEC(".maps");

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
    __type(key, struct syncookie_pending_key);
    __type(value, struct syncookie_pending_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syncookie_pending_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);
    __type(value, struct syncookie_metrics);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syncookie_metrics_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct fingerprint_key);
    __type(value, struct tcp_fingerprint);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_fingerprint_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct bypass_key);
    __type(value, struct bypass_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} bypass_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct syncookie_flow_key);
    __type(value, struct syncookie_forward_stats_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syncookie_forward_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct syncookie_flow_key);
    __type(value, struct syncookie_seq_delta_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syncookie_seq_delta_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50000);
    __type(key, struct cookie_failure_key);
    __type(value, struct cookie_failure_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} cookie_failure_map SEC(".maps");

/* ===== QoS Bandwidth Monitoring Maps ===== */
/*
 * INGRESS: Monitor only, signal XDP to increase defense.
 * NEVER drop ingress traffic here - let XDP defense do its job.
 */

/* Per-origin bandwidth quota and token bucket state */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);  /* origin_ip */
    __type(value, struct origin_bandwidth);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} origin_bandwidth_map SEC(".maps");

/* Scrubber-level QoS statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, QOS_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_stats_map SEC(".maps");

/* Per-origin challenge level - signals XDP to increase defense aggressiveness */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);  /* origin_ip */
    __type(value, __u32); /* challenge level 0-4 */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} origin_challenge_map SEC(".maps");

enum syncookie_debug_state {
    SYNCDBG_NONE = 0,
    SYNCDBG_MODE_DISABLED = 1,
    SYNCDBG_SYN_BYPASS = 2,
    SYNCDBG_SYN_REDIRECT = 3,
    SYNCDBG_SYN_REDIRECT_FAIL = 4,
    SYNCDBG_ACK_CONVERT_OK = 5,
    SYNCDBG_ACK_CONVERT_FAIL = 6,
    SYNCDBG_ACK_INVALID = 7,
};

struct syn_cookie_debug {
    __u32 syn_cookie;
    __u32 syn_now_sec;
    __u32 last_ack;
    __u32 ack_now_sec;
    __s32 syn_redirect_ret;
    __u32 last_dst_eip;
    __u32 last_redirect_ifindex;
    __u32 last_origin_ip;
    __u32 last_mode_value;
    __u32 last_tcp_flags;
    __s32 last_result;
    __u32 pending_state;
    __u32 pending_expires_at;
    __u32 last_client_ip;
    __u32 last_client_port;
    __u32 last_vip_port;
    __u32 last_wg_ifindex;
    __u32 last_convert_seq;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct syn_cookie_debug);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syncookie_debug_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 9);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} wan_ingress_stats SEC(".maps");

enum convert_stats_idx {
    CONVERT_STAT_ATTEMPT = 0,
    CONVERT_STAT_SUCCESS = 1,
    CONVERT_STAT_FAIL = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syncookie_convert_stats SEC(".maps");

static __always_inline void bump_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&wan_ingress_stats, &idx);
    if (!val)
        return;
    (*val)++;
}

static __always_inline void bump_convert_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&syncookie_convert_stats, &idx);
    if (!val)
        return;
    (*val)++;
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return (__u16)(~csum);
}

static __always_inline int convert_ack_to_syn(struct __sk_buff *skb, __u32 wg_ifindex,
                                              __be32 origin_ip, __u32 client_seq_host)
{
    (void)wg_ifindex;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    struct tcphdr *tcp = (void *)iph + iph->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return -1;

    __be32 client_ip = iph->saddr;
    __be16 client_port = tcp->source;
    __be16 vip_port = tcp->dest;

    __u32 new_seq_host = client_seq_host;

    int old_tot_len = bpf_ntohs(iph->tot_len);
    int new_tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    int delta = new_tot_len - old_tot_len;

    if (delta != 0) {
        if (bpf_skb_adjust_room(skb, delta, BPF_ADJ_ROOM_MAC, 0))
            return -1;
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            return -1;
        iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return -1;
        tcp = (void *)iph + sizeof(*iph);
        if ((void *)(tcp + 1) > data_end)
            return -1;
    }

    iph->ihl = sizeof(*iph) >> 2;
    iph->tot_len = bpf_htons(new_tot_len);
    iph->tos = 0;
    iph->frag_off = bpf_htons(0x4000);
    iph->protocol = IPPROTO_TCP;
    iph->saddr = client_ip;
    iph->daddr = origin_ip;
    iph->check = 0;

    tcp->source = client_port;
    tcp->dest = vip_port;
    tcp->doff = sizeof(*tcp) >> 2;
    tcp->res1 = 0;
    tcp->urg_ptr = 0;
    __u8 *flags_ptr = (__u8 *)tcp + 13;
    *flags_ptr = 0x02; /* SYN */
    tcp->window = tcp->window ? tcp->window : bpf_htons(29200);
    tcp->seq = bpf_htonl(new_seq_host);
    tcp->ack_seq = 0;
    tcp->check = 0;

    __u32 ip_csum = bpf_csum_diff(NULL, 0, (__be32 *)iph, sizeof(*iph), 0);
    iph->check = csum_fold_helper(ip_csum);

    struct tcphdr tcp_tmp = {};
    tcp_tmp.source = tcp->source;
    tcp_tmp.dest = tcp->dest;
    tcp_tmp.seq = tcp->seq;
    tcp_tmp.ack_seq = 0;
    tcp_tmp.doff = tcp->doff;
    tcp_tmp.res1 = 0;
    tcp_tmp.window = tcp->window;
    tcp_tmp.urg_ptr = 0;
    *((__u8 *)&tcp_tmp + 13) = 0x02;

    __u32 tcp_len = sizeof(tcp_tmp);
    __u32 pseudo = bpf_htonl((__u32)IPPROTO_TCP << 16 | tcp_len);
    __u32 tcp_csum = 0;
    tcp_csum = bpf_csum_diff(NULL, 0, &iph->saddr, sizeof(iph->saddr), tcp_csum);
    tcp_csum = bpf_csum_diff(NULL, 0, &origin_ip, sizeof(origin_ip), tcp_csum);
    tcp_csum = bpf_csum_diff(NULL, 0, (__be32 *)&pseudo, sizeof(pseudo), tcp_csum);
    tcp_csum = bpf_csum_diff(NULL, 0, (__be32 *)&tcp_tmp, tcp_len, tcp_csum);
    tcp->check = csum_fold_helper(tcp_csum);

    return TC_ACT_OK;
}

static __always_inline int issue_synack(struct __sk_buff *skb, __be32 dst_eip,
                                        __u32 now_sec, __u32 cookie)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    struct tcphdr *tcp = (void *)iph + iph->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return -1;

    __be32 client_ip = iph->saddr;
    __be32 vip_ip = iph->daddr;
    __be16 client_port = tcp->source;
    __be16 vip_port = tcp->dest;
    __u32 client_seq = bpf_ntohl(tcp->seq);

    int old_tot_len = bpf_ntohs(iph->tot_len);
    int new_tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    int delta = new_tot_len - old_tot_len;

    if (delta != 0) {
        if (bpf_skb_adjust_room(skb, delta, BPF_ADJ_ROOM_NET, 0))
            return -1;
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            return -1;
        iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return -1;
        tcp = (void *)iph + sizeof(*iph);
        if ((void *)(tcp + 1) > data_end)
            return -1;
    }

    __u8 tmp_mac[ETH_ALEN];
#pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp_mac[i] = eth->h_source[i];
        eth->h_source[i] = eth->h_dest[i];
        eth->h_dest[i] = tmp_mac[i];
    }
    eth->h_proto = bpf_htons(ETH_P_IP);

    iph->ihl = sizeof(*iph) >> 2;
    iph->tot_len = bpf_htons(new_tot_len);
    iph->ttl = 64;
    iph->tos = 0;
    iph->frag_off = bpf_htons(0x4000);
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;

    iph->saddr = vip_ip;
    iph->daddr = client_ip;

    tcp->source = vip_port;
    tcp->dest = client_port;
    tcp->doff = sizeof(*tcp) >> 2;
    tcp->res1 = 0;
    tcp->fin = 0;
    tcp->syn = 1;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->ack = 1;
    tcp->urg = 0;
    tcp->ece = 0;
    tcp->cwr = 0;
    tcp->window = bpf_htons(29200);
    tcp->urg_ptr = 0;

    tcp->seq = bpf_htonl(cookie);
    tcp->ack_seq = bpf_htonl(client_seq + 1);
    tcp->check = 0;

    __u32 debug_key = 0;
    struct syn_cookie_debug *dbg = bpf_map_lookup_elem(&syncookie_debug_map, &debug_key);
    if (dbg) {
        dbg->syn_cookie = cookie;
        dbg->syn_now_sec = now_sec;
    }

    __u32 ip_csum = bpf_csum_diff(NULL, 0, (__be32 *)iph, sizeof(*iph), 0);
    iph->check = csum_fold_helper(ip_csum);

    __u32 tcp_len = sizeof(*tcp);
    struct tcphdr tcp_tmp = {};
    tcp_tmp.source = tcp->source;
    tcp_tmp.dest = tcp->dest;
    tcp_tmp.seq = tcp->seq;
    tcp_tmp.ack_seq = tcp->ack_seq;
    tcp_tmp.doff = tcp->doff;
    tcp_tmp.window = tcp->window;
    tcp_tmp.urg_ptr = tcp->urg_ptr;
    tcp_tmp.fin = tcp->fin;
    tcp_tmp.syn = tcp->syn;
    tcp_tmp.rst = tcp->rst;
    tcp_tmp.psh = tcp->psh;
    tcp_tmp.ack = tcp->ack;
    tcp_tmp.urg = tcp->urg;
    tcp_tmp.ece = tcp->ece;
    tcp_tmp.cwr = tcp->cwr;

    __u32 pseudo = bpf_htonl((__u32)IPPROTO_TCP << 16 | tcp_len);
    __u32 tcp_csum = 0;
    tcp_csum = bpf_csum_diff(NULL, 0, &iph->saddr, sizeof(iph->saddr), tcp_csum);
    tcp_csum = bpf_csum_diff(NULL, 0, &iph->daddr, sizeof(iph->daddr), tcp_csum);
    tcp_csum = bpf_csum_diff(NULL, 0, (__be32 *)&pseudo, sizeof(pseudo), tcp_csum);
    tcp_csum = bpf_csum_diff(NULL, 0, (__be32 *)&tcp_tmp, sizeof(tcp_tmp), tcp_csum);
    tcp->check = csum_fold_helper(tcp_csum);

    int redirect_code = bpf_redirect(skb->ifindex, 0);

    if (dbg) {
        dbg->syn_redirect_ret = redirect_code;
        dbg->last_redirect_ifindex = skb->ifindex;
    }

    if (redirect_code != TC_ACT_REDIRECT)
        return -1;

    return TC_ACT_REDIRECT;
}

static __always_inline void update_cookie_failure(__be32 src_ip, __be32 vip_ip,
                                                  __u32 now_sec, int success)
{
    struct cookie_failure_key key = {
        .src_ip = src_ip,
        .vip_ip = vip_ip
    };

    struct cookie_failure_entry *entry = bpf_map_lookup_elem(&cookie_failure_map, &key);
    if (entry) {
        if (success) {
            __sync_fetch_and_add(&entry->success_count, 1);
            entry->failure_count = 0;
        } else {
            __sync_fetch_and_add(&entry->failure_count, 1);
            entry->last_failure_ts = now_sec;
        }
    } else if (!success) {
        struct cookie_failure_entry new_entry = {
            .failure_count = 1,
            .success_count = 0,
            .first_seen_ts = now_sec,
            .last_failure_ts = now_sec
        };
        bpf_map_update_elem(&cookie_failure_map, &key, &new_entry, BPF_ANY);
    } else {
        struct cookie_failure_entry new_entry = {
            .failure_count = 0,
            .success_count = 1,
            .first_seen_ts = now_sec,
            .last_failure_ts = 0
        };
        bpf_map_update_elem(&cookie_failure_map, &key, &new_entry, BPF_ANY);
    }
}

static __always_inline struct syncookie_metrics *
get_or_init_syncookie_metrics(__be32 dst_eip)
{
    struct syncookie_metrics *metrics =
        bpf_map_lookup_elem(&syncookie_metrics_map, &dst_eip);
    if (!metrics) {
        struct syncookie_metrics empty = {};
        bpf_map_update_elem(&syncookie_metrics_map, &dst_eip, &empty, BPF_NOEXIST);
        metrics = bpf_map_lookup_elem(&syncookie_metrics_map, &dst_eip);
    }
    return metrics;
}

static __always_inline int handle_syncookie(struct __sk_buff *skb, struct iphdr *iph,
                                            struct tcphdr *tcp, __u8 tcp_flags,
                                            __be32 dst_eip, struct eip_entry *eip_entry,
                                            __u32 now_sec)
{
    if (!eip_entry)
        return -1;

    __be32 origin_ip = eip_entry->origin_ip;
    __u32 debug_key = 0;
    struct syn_cookie_debug *dbg = bpf_map_lookup_elem(&syncookie_debug_map, &debug_key);
    if (dbg) {
        dbg->last_origin_ip = origin_ip;
        dbg->last_dst_eip = dst_eip;
        dbg->last_tcp_flags = tcp_flags;
        dbg->last_mode_value = 0;
        dbg->last_result = SYNCDBG_NONE;
    }

    __u32 *mode = bpf_map_lookup_elem(&syncookie_mode_map, &origin_ip);
    __u32 mode_value = mode ? *mode : 0;
    if (dbg)
        dbg->last_mode_value = mode_value;

    if (!mode_value) {
        if (dbg)
            dbg->last_result = SYNCDBG_MODE_DISABLED;
        if (tcp_flags & (0x02 | 0x10))
            bpf_debug("syncookie skip vip=%x mode=0 flags=0x%x\n",
                       bpf_ntohl(origin_ip), tcp_flags);
        return -1;
    }

    if (tcp_flags == 0x02 || (tcp_flags & 0x10))
        bpf_debug("syncookie key=%x mode=%u flags=0x%x\n",
                   bpf_ntohl(origin_ip), mode_value, tcp_flags);

    struct syncookie_metrics *metrics = get_or_init_syncookie_metrics(origin_ip);
    if (metrics)
        metrics->last_update_ts = now_sec;
    if (dbg) {
        dbg->syn_cookie = mode_value;
        dbg->syn_now_sec = now_sec;
        dbg->last_redirect_ifindex = eip_entry->wg_ifindex;
        dbg->syn_redirect_ret = -1;
    }

    if (tcp_flags == 0x02) {
        bump_stat(WAN_STAT_SYNCOOKIE_SYN);

        struct syncookie_flow_key flow = {
            .src_ip = iph->saddr,
            .dst_eip = dst_eip,
            .src_port = tcp->source,
            .dst_port = tcp->dest
        };

        bpf_debug("wan allow key syn src=%x dst=%x\n",
                   bpf_ntohl(flow.src_ip),
                   bpf_ntohl(flow.dst_eip));
        bpf_debug("wan allow key syn sport=%u dport=%u\n",
                   bpf_ntohs(flow.src_port),
                   bpf_ntohs(flow.dst_port));

        struct syncookie_allow_entry *allow = bpf_map_lookup_elem(&syncookie_allow_map, &flow);
        if (allow && now_sec < allow->expires_at) {
            if (metrics)
                __sync_fetch_and_add(&metrics->handshake_completes, 1);
            if (dbg)
                dbg->last_result = SYNCDBG_SYN_BYPASS;
            return -1;
        }

        struct fingerprint_key fp_key = {
            .src_ip = iph->saddr,
            .dst_port = tcp->dest,
            .pad = 0
        };

        struct tcp_fingerprint *fp = bpf_map_lookup_elem(&tcp_fingerprint_map, &fp_key);
        if (fp) {
            __sync_fetch_and_add(&fp->syn_count, 1);
            fp->last_seen_ts = now_sec;
        } else {
            struct tcp_fingerprint new_fp = {0};
            extract_tcp_fingerprint(tcp, (void *)(long)skb->data_end, &new_fp, iph->ttl);
            new_fp.first_seen_ts = now_sec;
            new_fp.last_seen_ts = now_sec;
            new_fp.syn_count = 1;
            bpf_map_update_elem(&tcp_fingerprint_map, &fp_key, &new_fp, BPF_ANY);
        }

        if (metrics) {
            __sync_fetch_and_add(&metrics->incoming_syn_pps, 1);
            __sync_fetch_and_add(&metrics->challenged_clients, 1);
        }

        __be32 client_ip = iph->saddr;
        __be16 client_port = tcp->source;
        __be16 vip_port = tcp->dest;
        __u32 client_seq = bpf_ntohl(tcp->seq);
        __u32 cookie = generate_syncookie(client_ip, dst_eip, client_port, vip_port, now_sec);

        struct syncookie_pending_key pending_key = {
            .client_ip = client_ip,
            .vip_ip = dst_eip,
            .client_port = client_port,
            .vip_port = vip_port,
        };

        struct syncookie_pending_entry pending_entry = {
            .client_seq = client_seq,
            .cookie_value = cookie,
            .origin_ip = origin_ip,
            .wg_ifindex = eip_entry->wg_ifindex,
            .expires_at = now_sec + SYNCOOKIE_PENDING_TTL_SEC,
            .state = SYNCOOKIE_PENDING_WAIT_ACK,
            .reserved = {0},
        };

        bpf_map_update_elem(&syncookie_pending_map, &pending_key, &pending_entry, BPF_ANY);

        if (dbg) {
            dbg->syn_cookie = cookie;
            dbg->pending_state = pending_entry.state;
            dbg->pending_expires_at = pending_entry.expires_at;
        }

        int syn_ret = issue_synack(skb, dst_eip, now_sec, cookie);
        if (metrics && syn_ret == TC_ACT_REDIRECT)
            __sync_fetch_and_add(&metrics->outgoing_synack_pps, 1);

        if (dbg) {
            dbg->syn_redirect_ret = syn_ret;
            dbg->last_result = (syn_ret == TC_ACT_REDIRECT)
                ? SYNCDBG_SYN_REDIRECT
                : SYNCDBG_SYN_REDIRECT_FAIL;
        }

        bpf_debug("syncookie syn ret=%d\n", syn_ret);

        if (syn_ret == TC_ACT_REDIRECT)
            return TC_ACT_REDIRECT;

        bpf_map_delete_elem(&syncookie_pending_map, &pending_key);
        return TC_ACT_SHOT;
    }

    if (tcp_flags & 0x10) {
        __be32 client_ip = iph->saddr;
        __be16 client_port = tcp->source;
        __be16 vip_port = tcp->dest;

        struct syncookie_flow_key flow_lookup = {
            .src_ip = client_ip,
            .dst_eip = dst_eip,
            .src_port = client_port,
            .dst_port = vip_port
        };

        bpf_debug("wan allow key ack src=%x dst=%x\n",
                   bpf_ntohl(flow_lookup.src_ip),
                   bpf_ntohl(flow_lookup.dst_eip));
        bpf_debug("wan allow key ack sport=%u dport=%u\n",
                   bpf_ntohs(flow_lookup.src_port),
                   bpf_ntohs(flow_lookup.dst_port));

        struct syncookie_allow_entry *allow_existing =
            bpf_map_lookup_elem(&syncookie_allow_map, &flow_lookup);
        if (allow_existing && now_sec < allow_existing->expires_at)
            return -1;

        struct syncookie_pending_key pending_key = {
            .client_ip = client_ip,
            .vip_ip = dst_eip,
            .client_port = client_port,
            .vip_port = vip_port,
        };

        struct syncookie_pending_entry *pending =
            bpf_map_lookup_elem(&syncookie_pending_map, &pending_key);
        bool pending_expired = false;
        if (pending && now_sec > pending->expires_at) {
            pending->state = SYNCOOKIE_PENDING_EXPIRED;
            pending_expired = true;
            bpf_map_delete_elem(&syncookie_pending_map, &pending_key);
        }

        __u32 ack_seq_net = tcp->ack_seq;
        __u32 ack_seq_host = bpf_ntohl(ack_seq_net);
        if (!dbg)
            dbg = bpf_map_lookup_elem(&syncookie_debug_map, &debug_key);
        if (dbg) {
            dbg->last_ack = ack_seq_host;
            dbg->ack_now_sec = now_sec;
            dbg->pending_state = pending ? pending->state : SYNCOOKIE_PENDING_EXPIRED;
            dbg->pending_expires_at = pending ? pending->expires_at : 0;
        }

        if (!pending || pending_expired) {
            update_cookie_failure(client_ip, origin_ip, now_sec, 0);
            bump_stat(WAN_STAT_SYNCOOKIE_ACK_FAIL);
            if (metrics)
                __sync_fetch_and_add(&metrics->cookie_rejects, 1);
            if (dbg)
                dbg->last_result = SYNCDBG_ACK_INVALID;
            return TC_ACT_SHOT;
        }

        if (validate_syncookie(ack_seq_net, iph->saddr, dst_eip,
                               tcp->source, tcp->dest, now_sec)) {
            pending->state = SYNCOOKIE_PENDING_WAIT_SYNACK;
            pending->expires_at = now_sec + SYNCOOKIE_PENDING_TTL_SEC;
            if (dbg) {
                dbg->pending_state = pending->state;
                dbg->pending_expires_at = pending->expires_at;
            }

            bump_convert_stat(CONVERT_STAT_ATTEMPT);
            if (dbg) {
                dbg->last_client_ip = bpf_ntohl(client_ip);
                dbg->last_client_port = bpf_ntohs(client_port);
                dbg->last_vip_port = bpf_ntohs(vip_port);
                dbg->last_wg_ifindex = pending->wg_ifindex;
                dbg->last_convert_seq = pending->client_seq;
            }

            int conv_ret = convert_ack_to_syn(skb, pending->wg_ifindex,
                                              pending->origin_ip, pending->client_seq);

            if (dbg) {
                dbg->syn_redirect_ret = conv_ret;
                dbg->last_redirect_ifindex = pending->wg_ifindex;
                dbg->last_result = (conv_ret == TC_ACT_REDIRECT)
                    ? SYNCDBG_ACK_CONVERT_OK
                    : SYNCDBG_ACK_CONVERT_FAIL;
            }

            bpf_debug("syncookie ack ret=%d\n", conv_ret);

            if (conv_ret == TC_ACT_OK) {
                bump_convert_stat(CONVERT_STAT_SUCCESS);
                update_cookie_failure(client_ip, origin_ip, now_sec, 1);
                if (metrics)
                    __sync_fetch_and_add(&metrics->cookie_validates, 1);
                return TC_ACT_OK;
            }

            bump_convert_stat(CONVERT_STAT_FAIL);
            pending->state = SYNCOOKIE_PENDING_EXPIRED;
            bpf_map_delete_elem(&syncookie_pending_map, &pending_key);
            update_cookie_failure(client_ip, origin_ip, now_sec, 0);
            return conv_ret;
        }

        pending->state = SYNCOOKIE_PENDING_EXPIRED;
        bpf_map_delete_elem(&syncookie_pending_map, &pending_key);
        update_cookie_failure(client_ip, origin_ip, now_sec, 0);

        bump_stat(WAN_STAT_SYNCOOKIE_ACK_FAIL);

        if (dbg)
            dbg->last_result = SYNCDBG_ACK_INVALID;

        if (metrics)
            __sync_fetch_and_add(&metrics->cookie_rejects, 1);

        return TC_ACT_SHOT;
    }

    return -1;
}

SEC("tc/ingress")
int tc_ingress_wan(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    bump_stat(WAN_STAT_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != __bpf_constant_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    __be32 eip = iph->daddr;
    struct eip_entry *v = bpf_map_lookup_elem(&eip_map, &eip);
    if (!v) {
        bump_stat(WAN_STAT_MAP_MISS);
        return TC_ACT_OK;
    }

    bump_stat(WAN_STAT_MAP_HIT);

    __be32 dst_eip = iph->daddr;
    __u8 proto = iph->protocol;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *th = (void *)iph + iph->ihl * 4;
        if ((void *)(th + 1) > data_end)
            return TC_ACT_OK;

        __u8 tcp_flags = *((__u8 *)th + 13);
        __u32 now_sec = (__u32)(bpf_ktime_get_ns() / NS_PER_SEC);

        int syncookie_action = handle_syncookie(skb, iph, th, tcp_flags, dst_eip, v, now_sec);
        if (syncookie_action == TC_ACT_SHOT)
            return TC_ACT_SHOT;
        if (syncookie_action == TC_ACT_REDIRECT)
            return TC_ACT_REDIRECT;
        if (syncookie_action == TC_ACT_OK)
            return TC_ACT_OK;
    }

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    dst_eip = iph->daddr;
    proto = iph->protocol;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *pending_th = (void *)iph + iph->ihl * 4;
        if ((void *)(pending_th + 1) <= data_end) {
            struct syncookie_pending_key pending_key = {
                .client_ip = iph->saddr,
                .vip_ip = dst_eip,
                .client_port = pending_th->source,
                .vip_port = pending_th->dest,
            };

            struct syncookie_pending_entry *pending_entry =
                bpf_map_lookup_elem(&syncookie_pending_map, &pending_key);
            if (pending_entry) {
                __u32 pending_now_sec = (__u32)(bpf_ktime_get_ns() / NS_PER_SEC);
                if (pending_now_sec > pending_entry->expires_at) {
                    pending_entry->state = SYNCOOKIE_PENDING_EXPIRED;
                    bpf_map_delete_elem(&syncookie_pending_map, &pending_key);
                } else if (pending_entry->state != SYNCOOKIE_PENDING_COMPLETED) {
                    return TC_ACT_SHOT;
                }
            }
        }
    }

    __be32 old = dst_eip;
    __be32 new_dst = v->origin_ip;

    /* Extract connection info BEFORE modifying packet (for BPF verifier) */
    __be32 src_ip = iph->saddr;
    __u8 tcp_flags = 0;
    __be16 src_port = 0;
    __be16 dst_port = 0;
    int tcp_payload_len = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *th = (void *)iph + iph->ihl * 4;
        if ((void *)(th + 1) <= data_end) {
            tcp_flags = *((__u8 *)th + 13);  /* TCP flags byte */
            src_port = th->source;
            dst_port = th->dest;
            int total_len = bpf_ntohs(iph->tot_len);
            int ip_header_len = iph->ihl * 4;
            int tcp_header_len = th->doff * 4;
            int payload = total_len - ip_header_len - tcp_header_len;
            if (payload > 0)
                tcp_payload_len = payload;
        }
    }

    if (proto == IPPROTO_TCP && tcp_payload_len > 0 && src_port && dst_port) {
        struct syncookie_flow_key flow_key = {
            .src_ip = src_ip,
            .dst_eip = dst_eip,
            .src_port = src_port,
            .dst_port = dst_port,
        };

        __u32 now_sec = (__u32)(bpf_ktime_get_ns() / NS_PER_SEC);
        struct syncookie_allow_entry *allow_entry =
            bpf_map_lookup_elem(&syncookie_allow_map, &flow_key);
        if (allow_entry && now_sec <= allow_entry->expires_at) {
            struct syncookie_forward_stats_entry *stat =
                bpf_map_lookup_elem(&syncookie_forward_stats_map, &flow_key);
            if (stat) {
                __sync_fetch_and_add(&stat->packets, 1);
                __sync_fetch_and_add(&stat->bytes, (__u64)tcp_payload_len);
                stat->last_seen = now_sec;
            } else {
                struct syncookie_forward_stats_entry init = {
                    .packets = 1,
                    .bytes = (__u64)tcp_payload_len,
                    .last_seen = now_sec,
                    .reserved = 0,
                };
                bpf_map_update_elem(&syncookie_forward_stats_map, &flow_key, &init, BPF_ANY);
                bpf_debug("wan payload pass src=%x dst=%x len=%d\n",
                           bpf_ntohl(flow_key.src_ip),
                           bpf_ntohl(flow_key.dst_eip),
                           tcp_payload_len);
                bpf_debug("wan payload ports sport=%u dport=%u\n",
                           bpf_ntohs(flow_key.src_port),
                           bpf_ntohs(flow_key.dst_port));
            }
        }
    }

    /* ===== QoS Ingress Bandwidth MONITORING ===== */
    /*
     * MONITOR ONLY - Never drop ingress traffic here!
     * If under bandwidth pressure, signal XDP to increase defense aggressiveness.
     * This allows fine-grained XDP defense to filter attacks, not blind quota drops.
     */
    qos_monitor_ingress_inline(
        new_dst,                  /* origin_ip as key */
        skb->len,                 /* packet size in bytes */
        &origin_bandwidth_map,
        &origin_challenge_map,    /* signals XDP to increase defense */
        &qos_stats_map);

    /* Perform DNAT */
    iph->daddr = new_dst;
    bump_stat(WAN_STAT_DNAT);

    bpf_l3_csum_replace(skb, (long)&iph->check - (long)data, old, new_dst, sizeof(__be32));

    /* Reload packet pointers after L3 checksum update */
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    /* Update L4 checksums */
    if (proto == IPPROTO_TCP) {
        struct tcphdr *th = (void *)iph + iph->ihl * 4;
        if ((void *)(th + 1) <= data_end) {
            bpf_l4_csum_replace(skb, (long)&th->check - (long)data, old, new_dst,
                                sizeof(__be32) | BPF_F_PSEUDO_HDR);
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *uh = (void *)iph + iph->ihl * 4;
        if ((void *)(uh + 1) <= data_end && uh->check)
            bpf_l4_csum_replace(skb, (long)&uh->check - (long)data, old, new_dst,
                                sizeof(__be32) | BPF_F_PSEUDO_HDR);
    }

    /* Track TCP connections and update lifetime statistics */
    if (proto == IPPROTO_TCP && tcp_flags != 0) {
        struct conn_key conn = {
            .src_ip = src_ip,
            .dst_ip = new_dst,
            .src_port = src_port,
            .dst_port = dst_port,
            .protocol = IPPROTO_TCP,
        };

        /* Check TCP flags: SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04 */
        __u8 syn_flag = tcp_flags & 0x02;
        __u8 ack_flag = tcp_flags & 0x10;
        __u8 fin_flag = tcp_flags & 0x01;
        __u8 rst_flag = tcp_flags & 0x04;

        /* Get or initialize origin stats */
        struct origin_stats *stats = bpf_map_lookup_elem(&origin_stats_map, &new_dst);
        if (!stats) {
            struct origin_stats init = {0};
            bpf_map_update_elem(&origin_stats_map, &new_dst, &init, BPF_ANY);
            stats = bpf_map_lookup_elem(&origin_stats_map, &new_dst);
        }

        if (stats) {
            /* Update packet counter for ALL TCP packets */
            __sync_fetch_and_add(&stats->packets_total, 1);

            /* NEW CONNECTION: TCP SYN without ACK */
            if (syn_flag && !ack_flag) {
                __be32 *existing = bpf_map_lookup_elem(&active_conns, &conn);
                if (!existing) {
                    /* Add to connection tracking */
                    bpf_map_update_elem(&active_conns, &conn, &new_dst, BPF_ANY);

                    /* Increment lifetime counters (monotonic) */
                    __sync_fetch_and_add(&stats->conn_opened_total, 1);
                    __sync_fetch_and_add(&stats->ingress_syn_count, 1);
                    bump_stat(WAN_STAT_CONN_NEW);
                }
            }

            /* Note: SYN-ACK tracking moved to tc_ingress_wg.c (egress path) */

            /* CONNECTION CLOSE: TCP FIN or RST */
            if (fin_flag || rst_flag) {
                __be32 *existing = bpf_map_lookup_elem(&active_conns, &conn);
                if (existing) {
                    bpf_map_delete_elem(&active_conns, &conn);

                    /* Increment close counter (monotonic) */
                    __sync_fetch_and_add(&stats->conn_closed_total, 1);
                    if (fin_flag) {
                        __sync_fetch_and_add(&stats->fin_count, 1);
                    }
                    if (rst_flag) {
                        __sync_fetch_and_add(&stats->rst_count, 1);
                    }
                    bump_stat(WAN_STAT_CONN_CLOSE);
                }
            }
        }
    }

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    if (proto == IPPROTO_TCP && src_port && dst_port) {
        struct tcphdr *ack_th = (void *)iph + iph->ihl * 4;
        if ((void *)(ack_th + 1) <= data_end) {
            struct syncookie_flow_key delta_key = {
                .src_ip = src_ip,
                .dst_eip = dst_eip,
                .src_port = src_port,
                .dst_port = dst_port,
            };
            struct syncookie_seq_delta_entry *delta =
                bpf_map_lookup_elem(&syncookie_seq_delta_map, &delta_key);
            if (delta) {
                __u32 now_sec_delta = (__u32)(bpf_ktime_get_ns() / NS_PER_SEC);
                if (now_sec_delta > delta->expires_at) {
                    bpf_map_delete_elem(&syncookie_seq_delta_map, &delta_key);
                } else if ((tcp_flags & 0x10) && delta->server_delta) {
                    __s64 ack_host = (__s64)bpf_ntohl(ack_th->ack_seq);
                    ack_host -= (__s64)delta->server_delta;
                    __be32 old_ack = ack_th->ack_seq;
                    __be32 new_ack = bpf_htonl((__u32)ack_host);
                    ack_th->ack_seq = new_ack;
                    bpf_l4_csum_replace(skb,
                                        (long)&ack_th->check - (long)data,
                                        old_ack,
                                        new_ack,
                                        sizeof(old_ack));
                }
            }
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
