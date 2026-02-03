// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 32);  // Increased for new DROP_TEMP_BLACKLIST counter
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} audit_xdp_stats SEC(".maps");

/* Ring buffer for cryptographic audit proofs
 * Each processed packet logs: timestamp, HMAC suffix, seq_num, action, reason
 * Validator reads this to verify miner actually processed packets correctly
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB ring buffer (~6000 proofs)
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} audit_proof_ringbuf SEC(".maps");

/* Audit mode configuration - controlled by validator via bpftool */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct audit_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} audit_config_map SEC(".maps");

/* Blacklist: LPM Trie for CIDR-aware matching (Spamhaus + EmergingThreats) */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __uint(key_size, sizeof(struct lpm_key));
    __uint(value_size, sizeof(__u8));  // Reputation score 0-100 (lower=worse)
    __uint(map_flags, BPF_F_NO_PREALLOC);  // Required for LPM_TRIE
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blacklist_map SEC(".maps");

/* Whitelist: VIP IPs that bypass all checks (HASH - individual IPs only) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __be32);
    __type(value, __u8);  // Always 1
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} whitelist_map SEC(".maps");

/* Rate limiting: per-source IP token buckets (LRU auto-evicts idle IPs) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __be32);
    __type(value, struct ratelimit_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ratelimit_map SEC(".maps");

/* Machine limits: calculated from CPU/RAM during bootstrap */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct machine_limits);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} machine_limits_map SEC(".maps");

/* Challenge level: adaptive multiplier (0=NORMAL to 4=EMERGENCY) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);  // 0-4: NORMAL, SOFT, ACTIVE, STRICT, EMERGENCY
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} challenge_level_map SEC(".maps");

/* PHASE 2: Per-source-IP behavior tracking for attack fingerprinting */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __be32);  // source IP
    __type(value, struct source_ip_behavior);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} source_ip_behavior_map SEC(".maps");

/* PHASE 4: Temporary blacklist with auto-expiration (Layer 2 mitigation) */
/* CHANGED: temp_blacklist now uses compound key for per-origin blocking */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, struct origin_rep_key);    // {src_ip, dst_eip} - CHANGED from __be32
    __type(value, struct origin_rep_value); // CHANGED from struct temp_blacklist_entry
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} temp_blacklist_map SEC(".maps");

/* PHASE 4: Per-origin challenge levels for targeted rate limiting */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);  // origin_ip
    __type(value, __u32);  // challenge level 0-4
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} origin_challenge_map SEC(".maps");

/* Per-origin whitelist: client-controlled bypass */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, struct origin_rep_key);    // {src_ip, dst_eip}
    __type(value, struct origin_rep_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} origin_whitelist_map SEC(".maps");

/* Per-origin blacklist: client-controlled block */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, struct origin_rep_key);    // {src_ip, dst_eip}
    __type(value, struct origin_rep_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} origin_blacklist_map SEC(".maps");

/* Per-origin blacklist override: client unblocks global threat */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct origin_rep_key);    // {src_ip, dst_eip}
    __type(value, struct origin_rep_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} origin_override_map SEC(".maps");

/* PART 6: Reference to eip_map from TC layer (shared pinned map) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);
    __type(value, struct eip_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} eip_map SEC(".maps");

/* LAYER 0: VIP state tracking - Per-origin mitigation state */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);  // origin_ip (VIP)
    __type(value, struct vip_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} vip_state_map SEC(".maps");

/* LAYER 0: Quarantine map - Per-source penalty for cookie failures */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50000);  // Auto-evicts old entries
    __type(key, struct quarantine_key);
    __type(value, struct quarantine_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} quarantine_map SEC(".maps");

/* LAYER 0: Bypass map - Fast path for validated flows */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);  // High volume for active connections
    __type(key, struct bypass_key);
    __type(value, struct bypass_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} bypass_map SEC(".maps");

/* Per-EIP security statistics for incident reporting */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __be32);  // EIP (destination IP before DNAT)
    __type(value, struct eip_security_stats);
} eip_security_stats_map SEC(".maps");

/* Real-time scrubber load metrics - updated by ECP agent via bpftool
 * Single entry (key=0), read by check_rate_limit() for load-aware decisions
 * Stale if (now - last_update_ns) > 30 seconds
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scrubber_load);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} scrubber_load_map SEC(".maps");

/* Per-source IP reputation tracking - LRU to auto-evict idle sources
 * Key: src_ip (__be32)
 * Value: trust level, request counters, timestamps
 * 500K entries supports large-scale traffic with automatic cleanup
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 500000);
    __type(key, __be32);
    __type(value, struct source_reputation);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} source_reputation_map SEC(".maps");

/* Per-origin rate limit configuration - pre-configured on standby
 * Key: origin_ip (__be32)
 * Value: derived rate limits from bandwidth quota
 * CRITICAL: Must be pre-configured for fast failover
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);
    __type(value, struct origin_rate_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} origin_rate_config_map SEC(".maps");

#define TOKEN_BUCKET_CAPACITY 1000
#define TOKEN_REFILL_RATE 100
#define NS_PER_SEC 1000000000ULL
#define BYPASS_TTL_SEC 60

/* Trust level multipliers (divide by 100 for actual multiplier)
 * Higher trust = more permissive rate limits
 */
#define TRUST_NEW_MULT          100     // 1.0x - unknown source, base rate
#define TRUST_REPEAT_MULT       500     // 5.0x - seen before, some history
#define TRUST_ESTABLISHED_MULT  1000    // 10.0x - many successful requests
#define TRUST_VALIDATED_MULT    10000   // 100.0x - cookie validated, nearly unlimited

/* Trust level thresholds for promotion */
#define TRUST_PROMOTE_TO_REPEAT      10    // successful_requests >= 10 -> REPEAT
#define TRUST_PROMOTE_TO_ESTABLISHED 100   // successful_requests >= 100 -> ESTABLISHED
#define TRUST_PROMOTE_TO_VALIDATED   1000  // successful_requests >= 1000 -> VALIDATED

/* Load-based multipliers (divide by 100 for actual multiplier)
 * Low load = generous limits, high load = strict limits
 */
#define LOAD_LOW_MULT           200     // 2.0x - CPU < 30%, plenty of headroom
#define LOAD_NORMAL_MULT        100     // 1.0x - CPU 30-60%, normal operations
#define LOAD_HIGH_MULT          50      // 0.5x - CPU 60-80%, tightening
#define LOAD_CRITICAL_MULT      20      // 0.2x - CPU > 80%, protection mode

/* Load thresholds (percentage) */
#define LOAD_THRESHOLD_LOW      30
#define LOAD_THRESHOLD_NORMAL   60
#define LOAD_THRESHOLD_HIGH     80

/* Protocol-based multipliers (divide by 100 for actual multiplier)
 * SYN packets are attack vectors, established connections are trusted
 */
#define PROTO_SYN_MULT          10      // 0.1x - SYN packets (attack vector)
#define PROTO_ESTABLISHED_MULT  200     // 2.0x - established connections (trusted)
#define PROTO_NEUTRAL_MULT      100     // 1.0x - other packets

/* Absolute rate limit bounds (packets per second per source)
 * These are hard limits regardless of multipliers
 */
#define ABSOLUTE_MIN_PPS        10      // Never below 10 PPS per source
#define ABSOLUTE_MAX_PPS        100000  // Never above 100K PPS per source

/* Scrubber load map staleness threshold (nanoseconds) */
#define LOAD_MAP_STALE_NS       (30ULL * NS_PER_SEC)  // 30 seconds

static __always_inline int vip_cookie_enabled(__be32 vip_ip)
{
    struct eip_entry *eip = bpf_map_lookup_elem(&eip_map, &vip_ip);
    if (!eip)
        return 0;

    struct vip_state *state = bpf_map_lookup_elem(&vip_state_map, &eip->origin_ip);
    if (!state)
        return 0;

    return (state->flags & 0x1) != 0;
}

static __always_inline void xdp_bump_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&audit_xdp_stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

/*
 * log_audit_proof - Log cryptographic proof to ring buffer
 *
 * Called after every XDP decision during audit mode.
 * Extracts HMAC suffix and sequence number from payload to prove
 * the packet was actually seen and processed.
 *
 * Parameters:
 *   payload: Pointer to payload start
 *   payload_end: Pointer to packet data end
 *   action: XDP action taken (XDP_DROP=0, XDP_PASS=1)
 *   drop_reason: If dropped, which stat counter (from enum xdp_stats)
 *   now_ns: Current timestamp
 */
static __always_inline void log_audit_proof(
    __u8 *payload,
    void *payload_end,
    int action,
    __u8 drop_reason,
    __u64 now_ns)
{
    // Check if audit mode is enabled
    __u32 key = 0;
    struct audit_config *cfg = bpf_map_lookup_elem(&audit_config_map, &key);
    if (!cfg || !cfg->enabled)
        return;

    // Check if within audit time window
    if (now_ns < cfg->start_time_ns || now_ns > cfg->end_time_ns)
        return;

    // Reserve space in ring buffer
    struct audit_proof *proof = bpf_ringbuf_reserve(&audit_proof_ringbuf, sizeof(*proof), 0);
    if (!proof)
        return;

    // Initialize with defaults
    proof->timestamp_ns = now_ns;
    proof->action = (action == XDP_PASS) ? 1 : 0;
    proof->drop_reason = drop_reason;
    proof->seq_num = 0;
    proof->payload_len = 0;

    // Zero HMAC suffix
    #pragma unroll
    for (int i = 0; i < 8; i++)
        proof->hmac_suffix[i] = 0;

    // Calculate payload length
    if (payload && payload_end && (__u8 *)payload_end > payload) {
        __u64 len = (__u64)payload_end - (__u64)payload;
        proof->payload_len = len > 0xFFFF ? 0xFFFF : (__u16)len;
    }

    // Try to parse audit packet metadata
    if (payload && payload_end) {
        parse_audit_packet_inline(payload, payload_end, proof);
    }

    // Submit to ring buffer
    bpf_ringbuf_submit(proof, 0);
}

static __always_inline void bump_eip_security_stat(__be32 eip, int stat_type) {
    struct eip_security_stats *stats = bpf_map_lookup_elem(&eip_security_stats_map, &eip);
    if (!stats) {
        // Initialize new entry
        struct eip_security_stats new_stats = {0};
        bpf_map_update_elem(&eip_security_stats_map, &eip, &new_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&eip_security_stats_map, &eip);
        if (!stats) return;
    }

    switch (stat_type) {
        case 0: __sync_fetch_and_add(&stats->drop_blacklist, 1); break;
        case 1: __sync_fetch_and_add(&stats->drop_temp_blacklist, 1); break;
        case 2: __sync_fetch_and_add(&stats->drop_ratelimit, 1); break;
        case 3: __sync_fetch_and_add(&stats->drop_quarantine, 1); break;
        case 4: __sync_fetch_and_add(&stats->drop_bogon, 1); break;
        case 5: __sync_fetch_and_add(&stats->drop_origin_blacklist, 1); break;
        case 6: __sync_fetch_and_add(&stats->origin_whitelist_bypass, 1); break;
        case 7: __sync_fetch_and_add(&stats->origin_override_used, 1); break;
    }
}

/* PHASE 2: Track per-IP behavior for attack fingerprinting (BEFORE any drops) */
static __always_inline void track_source_ip_behavior(__be32 src_ip, __u8 proto, __u8 tcp_flags, __u64 now_ns)
{
    __u32 now_sec = (__u32)(now_ns / NS_PER_SEC);

    struct source_ip_behavior *beh = bpf_map_lookup_elem(&source_ip_behavior_map, &src_ip);
    if (beh) {
        // Update existing entry
        __sync_fetch_and_add(&beh->packets_total, 1);

        // Track TCP flags
        if (proto == IPPROTO_TCP) {
            if (tcp_flags & 0x02) {  // SYN
                __sync_fetch_and_add(&beh->syn_count, 1);
            }
            if (tcp_flags & 0x04) {  // RST
                __sync_fetch_and_add(&beh->rst_count, 1);
            }
        }

        // Burst detection: increment if within 1 second of last packet
        if (now_sec == beh->last_seen_ts) {
            beh->burst_count++;
        } else {
            beh->burst_count = 1;  // Reset burst counter
        }

        beh->last_seen_ts = now_sec;
    } else {
        // First packet from this IP - create entry
        struct source_ip_behavior new_beh = {
            .syn_count = (proto == IPPROTO_TCP && (tcp_flags & 0x02)) ? 1 : 0,
            .rst_count = (proto == IPPROTO_TCP && (tcp_flags & 0x04)) ? 1 : 0,
            .packets_total = 1,
            .first_seen_ts = now_sec,
            .last_seen_ts = now_sec,
            .burst_count = 1,
            .pad1 = 0,
            .pad2 = 0  // Pad to 40 bytes for BPF verifier
        };
        bpf_map_update_elem(&source_ip_behavior_map, &src_ip, &new_beh, BPF_ANY);
    }
}

/* Layer 0: Bypass check - Fast path for cookie-validated flows */
static __always_inline int is_bypassed(__be32 src_ip, __u16 src_port,
                                        __be32 vip_ip, __u16 dst_port,
                                        __u64 now_ns)
{
    struct bypass_key bkey = {
        .src_ip = src_ip,
        .src_port = src_port,
        .vip_ip = vip_ip,
        .dst_port = dst_port
    };

    struct bypass_entry *bypass = bpf_map_lookup_elem(&bypass_map, &bkey);
    if (bypass) {
        if (now_ns < bypass->expires_at_ns) {
            return 1;  // Bypassed - skip quarantine and rate limiting
        } else {
            // Expired - delete (best effort, cleanup thread handles bulk)
            bpf_map_delete_elem(&bypass_map, &bkey);
        }
    }
    return 0;  // Not bypassed
}

/* Layer 0: Quarantine check - Per-source penalty for cookie failures */
static __always_inline int is_quarantined(__be32 src_ip, __be32 vip_ip, __u64 now_ns)
{
    struct quarantine_key qkey = {
        .src_ip = src_ip,
        .vip_ip = vip_ip
    };

    struct quarantine_entry *qentry = bpf_map_lookup_elem(&quarantine_map, &qkey);
    if (qentry) {
        if (now_ns < qentry->expires_at_ns) {
            return 1;  // Quarantined - drop packet
        } else {
            // Expired - delete (best effort)
            bpf_map_delete_elem(&quarantine_map, &qkey);
        }
    }
    return 0;  // Not quarantined
}

/* Layer 2: Comprehensive bogon filtering (RFC 1918 + reserved ranges) */
static __always_inline int check_bogon_source(__be32 saddr)
{
    // 0.0.0.0/8 - "This network"
    if ((saddr & __bpf_constant_htonl(0xFF000000)) == 0)
        return XDP_DROP;

    // 10.0.0.0/8 - RFC 1918 private
    if ((saddr & __bpf_constant_htonl(0xFF000000)) == __bpf_constant_htonl(0x0A000000))
        return XDP_DROP;

    // 127.0.0.0/8 - Loopback
    if ((saddr & __bpf_constant_htonl(0xFF000000)) == __bpf_constant_htonl(0x7F000000))
        return XDP_DROP;

    // 169.254.0.0/16 - Link-local (EXCEPT AWS IMDS at 169.254.169.254)
    // AWS Instance Metadata Service must be allowed for bandwidth capacity discovery
    if ((saddr & __bpf_constant_htonl(0xFFFF0000)) == __bpf_constant_htonl(0xA9FE0000)) {
        // Allow 169.254.169.254 (AWS IMDS) - hex: 0xA9FEA9FE
        if (saddr != __bpf_constant_htonl(0xA9FEA9FE))
            return XDP_DROP;
    }

    // 172.16.0.0/12 - RFC 1918 private
    if ((saddr & __bpf_constant_htonl(0xFFF00000)) == __bpf_constant_htonl(0xAC100000))
        return XDP_DROP;

    // 192.0.2.0/24 - TEST-NET-1
    if ((saddr & __bpf_constant_htonl(0xFFFFFF00)) == __bpf_constant_htonl(0xC0000200))
        return XDP_DROP;

    // 192.168.0.0/16 - RFC 1918 private
    if ((saddr & __bpf_constant_htonl(0xFFFF0000)) == __bpf_constant_htonl(0xC0A80000))
        return XDP_DROP;

    // 198.51.100.0/24 - TEST-NET-2
    if ((saddr & __bpf_constant_htonl(0xFFFFFF00)) == __bpf_constant_htonl(0xC6336400))
        return XDP_DROP;

    // 203.0.113.0/24 - TEST-NET-3
    if ((saddr & __bpf_constant_htonl(0xFFFFFF00)) == __bpf_constant_htonl(0xCB007100))
        return XDP_DROP;

    // 224.0.0.0/4 - Multicast
    if ((saddr & __bpf_constant_htonl(0xF0000000)) == __bpf_constant_htonl(0xE0000000))
        return XDP_DROP;

    // 240.0.0.0/4 - Reserved/future use
    if ((saddr & __bpf_constant_htonl(0xF0000000)) == __bpf_constant_htonl(0xF0000000))
        return XDP_DROP;

    // 255.255.255.255 - Broadcast
    if (saddr == __bpf_constant_htonl(0xFFFFFFFF))
        return XDP_DROP;

    return XDP_PASS;
}

static __always_inline int validate_ip_header(struct iphdr *iph)
{
    // RFC 791: IP version must be 4
    if (iph->version != 4)
        return XDP_DROP;

    // IHL (Internet Header Length) must be >= 5 (20 bytes minimum)
    if (iph->ihl < 5)
        return XDP_DROP;

    // TTL must not be 0
    if (iph->ttl == 0)
        return XDP_DROP;

    return XDP_PASS;
}

static __always_inline int validate_tcp_flags(__u8 flags)
{
    // NULL scan (all flags 0)
    if (flags == 0)
        return XDP_DROP;

    // Xmas scan (FIN+PSH+URG = 0x29)
    if ((flags & 0x29) == 0x29)
        return XDP_DROP;

    // SYN+FIN (invalid combination)
    if ((flags & 0x03) == 0x03)
        return XDP_DROP;

    // SYN+RST (invalid combination)
    if ((flags & 0x06) == 0x06)
        return XDP_DROP;

    return XDP_PASS;
}

/* PART 6: Extract TCP options for fingerprinting */
// Functions now in common.h

/**
 * intelligent_rate_limit - Context-aware rate limiting
 *
 * @src_ip: Source IP address (network byte order)
 * @vip_ip: VIP/EIP address for origin lookup (network byte order)
 * @tcp_flags: TCP flags from packet header
 * @now_ns: Current timestamp from bpf_ktime_get_ns()
 *
 * Returns: XDP_PASS if allowed, XDP_DROP if rate limited
 *
 * This function implements 5-phase context-aware rate limiting:
 * 1. Trust classification (new vs repeat vs established vs validated)
 * 2. Origin context (derive limits from origin's bandwidth quota)
 * 3. Load awareness (adjust based on CPU/bandwidth utilization)
 * 4. Protocol budget (SYN packets get stricter limits)
 * 5. Token bucket enforcement (final decision with penalty integration)
 *
 * Replaces static 45-90 PPS limit with context-aware 10-100K PPS limits.
 */
static __always_inline int intelligent_rate_limit(
    __be32 src_ip,
    __be32 vip_ip,
    __u8 tcp_flags,
    __u64 now_ns)
{
    // === PHASE 1: Trust Classification ===
    __u32 trust_mult = TRUST_NEW_MULT;  // Default: new source, 1.0x

    struct source_reputation *rep = bpf_map_lookup_elem(&source_reputation_map, &src_ip);
    if (rep) {
        // Update last seen timestamp
        rep->last_seen_ns = now_ns;

        // Apply trust multiplier based on level
        if (rep->trust_level >= 3) {
            trust_mult = TRUST_VALIDATED_MULT;  // 100x for validated
        } else if (rep->trust_level == 2) {
            trust_mult = TRUST_ESTABLISHED_MULT;  // 10x for established
        } else if (rep->trust_level == 1) {
            trust_mult = TRUST_REPEAT_MULT;  // 5x for repeat
        }
        // trust_level 0 = TRUST_NEW_MULT (1x)
    }

    // === PHASE 2: Origin Context ===
    // First, resolve VIP/EIP to origin_ip
    struct eip_entry *eip_entry = bpf_map_lookup_elem(&eip_map, &vip_ip);
    __be32 origin_ip = eip_entry ? eip_entry->origin_ip : 0;

    __u32 origin_derived_pps = 10000;  // Default: 10K PPS if no config
    __u8 challenge_level = 0;

    if (origin_ip) {
        struct origin_rate_config *orc = bpf_map_lookup_elem(&origin_rate_config_map, &origin_ip);
        if (orc) {
            origin_derived_pps = orc->per_source_budget_pps;
            challenge_level = orc->challenge_level;

            // Check for manual override
            if (orc->override_enabled && orc->override_pps > 0) {
                origin_derived_pps = orc->override_pps;
            }
        }
    }

    // === PHASE 3: Load Awareness ===
    __u32 load_mult = LOAD_NORMAL_MULT;  // Default: 1.0x
    __u32 k = 0;
    struct scrubber_load *load = bpf_map_lookup_elem(&scrubber_load_map, &k);
    if (load) {
        // Check staleness (> 30 seconds = stale, use conservative)
        if ((now_ns - load->last_update_ns) > LOAD_MAP_STALE_NS) {
            load_mult = LOAD_HIGH_MULT;  // Conservative if stale
        } else {
            // Use max of CPU and bandwidth utilization
            __u8 combined_load = (load->cpu_pct > load->bw_utilization_pct)
                                 ? load->cpu_pct : load->bw_utilization_pct;

            if (combined_load < LOAD_THRESHOLD_LOW) {
                load_mult = LOAD_LOW_MULT;      // 2.0x - plenty of headroom
            } else if (combined_load < LOAD_THRESHOLD_NORMAL) {
                load_mult = LOAD_NORMAL_MULT;   // 1.0x - normal ops
            } else if (combined_load < LOAD_THRESHOLD_HIGH) {
                load_mult = LOAD_HIGH_MULT;     // 0.5x - tightening
            } else {
                load_mult = LOAD_CRITICAL_MULT; // 0.2x - protection mode
            }
        }
    }

    // === PHASE 4: Protocol Budget ===
    __u32 proto_mult = PROTO_NEUTRAL_MULT;  // Default: 1.0x
    if (tcp_flags & 0x02) {  // SYN flag set
        if (!(tcp_flags & 0x10)) {  // Not ACK (pure SYN)
            proto_mult = PROTO_SYN_MULT;  // 0.1x for SYN flood protection
        }
    } else if (tcp_flags & 0x10) {  // ACK without SYN = established
        proto_mult = PROTO_ESTABLISHED_MULT;  // 2.0x for trusted connections
    }

    // === PHASE 5A: Challenge Level Adjustment ===
    // Set by anomaly detector and copied to origin_rate_config_map
    __u32 challenge_mult = 100;  // Default: 100%
    if (challenge_level == 1) challenge_mult = 80;       // SOFT
    else if (challenge_level == 2) challenge_mult = 60;  // ACTIVE
    else if (challenge_level == 3) challenge_mult = 40;  // STRICT
    else if (challenge_level == 4) challenge_mult = 20;  // EMERGENCY

    // === PHASE 5B: Calculate Effective Rate ===
    // All multipliers are /100, combine carefully to avoid overflow
    __u64 effective = origin_derived_pps;
    effective = (effective * trust_mult) / 100;
    effective = (effective * load_mult) / 100;
    effective = (effective * proto_mult) / 100;
    effective = (effective * challenge_mult) / 100;

    // Apply absolute bounds
    if (effective < ABSOLUTE_MIN_PPS) effective = ABSOLUTE_MIN_PPS;
    if (effective > ABSOLUTE_MAX_PPS) effective = ABSOLUTE_MAX_PPS;

    __u32 final_rate = (__u32)effective;
    __u32 final_capacity = final_rate * 10;  // 10-second burst window

    // === PHASE 6: Token Bucket with Penalty Enforcement ===
    // CRITICAL: Must check penalty_level from automated_mitigation
    struct ratelimit_state *st = bpf_map_lookup_elem(&ratelimit_map, &src_ip);
    if (st) {
        // PHASE 6A: Apply per-IP penalty from automated_mitigation
        // Use MIN of challenge and penalty (don't double-punish)
        __u32 now_sec = (__u32)(now_ns / NS_PER_SEC);
        __u32 combined_mult = challenge_mult;

        if (st->penalty_level > 0 && now_sec < st->penalty_expires) {
            // Apply penalty multiplier: 1=50%, 2=20%, 3=5%
            __u32 pm = 100;
            if (st->penalty_level == 1) pm = 50;
            else if (st->penalty_level == 2) pm = 20;
            else if (st->penalty_level == 3) pm = 5;

            // Use the MORE restrictive multiplier
            combined_mult = (pm < challenge_mult) ? pm : challenge_mult;
        } else if (st->penalty_level > 0 && now_sec >= st->penalty_expires) {
            // Penalty expired - reset
            st->penalty_level = 0;
            st->penalty_expires = 0;
        }

        // Apply combined multiplier if different from challenge
        if (combined_mult != challenge_mult) {
            // Recalculate with new multiplier
            final_capacity = (final_capacity * combined_mult) / challenge_mult;
            final_rate = (final_rate * combined_mult) / challenge_mult;

            // Re-apply bounds after penalty adjustment
            if (final_rate < ABSOLUTE_MIN_PPS) final_rate = ABSOLUTE_MIN_PPS;
            if (final_capacity < ABSOLUTE_MIN_PPS * 10) final_capacity = ABSOLUTE_MIN_PPS * 10;
        }

        // PHASE 6B: Refill tokens based on elapsed time
        __u64 dt = now_ns - st->last_refill_ns;
        __u64 tokens_to_add = (dt * (__u64)final_rate) / NS_PER_SEC;

        if (tokens_to_add > 0) {
            st->tokens = (st->tokens + tokens_to_add > final_capacity)
                        ? final_capacity : st->tokens + tokens_to_add;
            st->last_refill_ns = now_ns;
        }

        // Check if tokens available
        if (st->tokens >= 1) {
            st->tokens--;

            // Update reputation on success
            if (rep) {
                rep->successful_requests++;
                // Promote trust level based on successful requests
                if (rep->trust_level < 1 && rep->successful_requests >= TRUST_PROMOTE_TO_REPEAT) {
                    rep->trust_level = 1;  // Promote to REPEAT
                }
                if (rep->trust_level < 2 && rep->successful_requests >= TRUST_PROMOTE_TO_ESTABLISHED) {
                    rep->trust_level = 2;  // Promote to ESTABLISHED
                }
                if (rep->trust_level < 3 && rep->successful_requests >= TRUST_PROMOTE_TO_VALIDATED) {
                    rep->trust_level = 3;  // Promote to VALIDATED
                }
            }
            return XDP_PASS;
        }

        // Rate limited - update stats
        st->blocked_count++;
        if (rep) {
            rep->blocked_requests++;
            // Trust DEMOTION: If blocked too many times, reduce trust level
            if (rep->blocked_requests > rep->successful_requests * 2) {
                // More than 2:1 blocked:success ratio -> suspicious
                if (rep->trust_level > 0) {
                    rep->trust_level--;  // Demote one level
                    rep->blocked_requests = 0;  // Reset counters
                    rep->successful_requests = 0;
                }
            }
        }
        return XDP_DROP;
    }

    // First packet from this IP - create token bucket with full capacity
    struct ratelimit_state new_state = {
        .tokens = final_capacity - 1,  // Consume one for this packet
        .last_refill_ns = now_ns,
        .blocked_count = 0,
        .penalty_expires = 0,
        .penalty_level = 0,
        .pad = {0}  // Pad to 32 bytes for BPF verifier
    };
    bpf_map_update_elem(&ratelimit_map, &src_ip, &new_state, BPF_ANY);

    // Initialize reputation if not exists
    if (!rep) {
        struct source_reputation new_rep = {
            .successful_requests = 1,
            .blocked_requests = 0,
            .first_seen_ns = now_ns,
            .last_seen_ns = now_ns,
            .trust_level = 0,
            .reserved1 = 0,
            .reserved2 = 0,
            .reserved3 = 0  // Pad to 32 bytes for BPF verifier
        };
        bpf_map_update_elem(&source_reputation_map, &src_ip, &new_rep, BPF_ANY);
    }

    return XDP_PASS;
}

/* DEPRECATED: Static rate limiting - superseded by intelligent_rate_limit()
 *
 * This function used machine_limits_map values calculated at bootstrap,
 * assuming 10,000 concurrent attackers. Result: 45-90 PPS per source,
 * which blocked 94% of legitimate traffic at 742 PPS.
 *
 * Kept for emergency rollback. To restore:
 *   1. #define USE_LEGACY_RATE_LIMIT 1
 *   2. Replace intelligent_rate_limit() call with check_rate_limit()
 *   3. Re-enable 37-machine-limits.sh
 */
static __always_inline int check_rate_limit(__be32 src_ip, __be32 vip_ip, __u64 now_ns)
{
    // Read machine limits (calculated during bootstrap)
    __u32 k = 0;
    struct machine_limits *lim = bpf_map_lookup_elem(&machine_limits_map, &k);
    __u32 cap = lim ? lim->token_capacity : TOKEN_BUCKET_CAPACITY;
    __u32 rate = lim ? lim->token_refill_rate : TOKEN_REFILL_RATE;

    // Apply per-origin challenge level multiplier (adaptive rate limiting per VIP)
    // First, resolve EIP to origin_ip
    struct eip_entry *eip_entry = bpf_map_lookup_elem(&eip_map, &vip_ip);
    __be32 origin_ip = eip_entry ? eip_entry->origin_ip : 0;

    __u32 challenge_level = 0;
    if (origin_ip) {
        // Look up per-origin challenge level
        __u32 *lvl = bpf_map_lookup_elem(&origin_challenge_map, &origin_ip);
        if (lvl) {
            challenge_level = *lvl;
        }
    }

    // If no per-origin level, fall back to global challenge level
    if (challenge_level == 0) {
        __u32 *global_lvl = bpf_map_lookup_elem(&challenge_level_map, &k);
        if (global_lvl) {
            challenge_level = *global_lvl;
        }
    }

    // Apply challenge level multipliers: 0=100%, 1=80%, 2=50%, 3=20%, 4=10%
    if (challenge_level > 0) {
        __u32 m = 100;
        if (challenge_level == 1) m = 80;
        else if (challenge_level == 2) m = 50;
        else if (challenge_level == 3) m = 20;
        else if (challenge_level == 4) m = 10;
        cap = (cap * m) / 100;
        rate = (rate * m) / 100;
    }

    // Lookup or create token bucket for this source IP
    struct ratelimit_state *st = bpf_map_lookup_elem(&ratelimit_map, &src_ip);
    if (st) {
        // PHASE 4: Check and apply per-IP penalty (Layer 1 mitigation)
        __u32 now_sec = (__u32)(now_ns / NS_PER_SEC);
        if (st->penalty_level > 0 && now_sec < st->penalty_expires) {
            // Apply penalty multiplier: 1=50%, 2=20%, 3=5%
            __u32 pm = 100;
            if (st->penalty_level == 1) pm = 50;
            else if (st->penalty_level == 2) pm = 20;
            else if (st->penalty_level == 3) pm = 5;
            cap = (cap * pm) / 100;
            rate = (rate * pm) / 100;
        } else if (st->penalty_level > 0 && now_sec >= st->penalty_expires) {
            // Penalty expired - reset
            st->penalty_level = 0;
            st->penalty_expires = 0;
        }

        // Refill tokens based on elapsed time
        __u64 dt = now_ns - st->last_refill_ns;
        __u64 tokens_to_add = (dt * (__u64)rate) / NS_PER_SEC;

        if (tokens_to_add > 0) {
            st->tokens = (st->tokens + tokens_to_add > cap) ? cap : st->tokens + tokens_to_add;
            st->last_refill_ns = now_ns;
        }

        // Check if tokens available
        if (st->tokens >= 1) {
            st->tokens--;
            return XDP_PASS;
        }

        // Rate limited
        st->blocked_count++;
        return XDP_DROP;
    }

    // First packet from this IP - create bucket with initial tokens
    struct ratelimit_state new_state = {
        .tokens = cap - 1,  // Consume one token for this packet
        .last_refill_ns = now_ns,
        .blocked_count = 0,
        .penalty_expires = 0,
        .penalty_level = 0,
        .pad = {0}  // Pad to 32 bytes for BPF verifier
    };
    bpf_map_update_elem(&ratelimit_map, &src_ip, &new_state, BPF_ANY);
    return XDP_PASS;
}

SEC("xdp")
int xdp_audit_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __bpf_constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u64 now = bpf_ktime_get_ns();
    __u8 proto = iph->protocol;
    __u8 tcp_flags = 0;

    // Pointer to payload for audit proof extraction
    __u8 *payload_start = NULL;
    void *payload_end = data_end;

    // Extract TCP flags early for behavior tracking
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(iph + 1);
        if ((void *)(tcp + 1) <= data_end) {
            tcp_flags = *((__u8 *)tcp + 13);
            // Calculate payload start (after TCP header)
            __u32 tcp_hdr_len = tcp->doff * 4;
            if (tcp_hdr_len >= 20 && tcp_hdr_len <= 60) {
                payload_start = (__u8 *)tcp + tcp_hdr_len;
                if (payload_start > (__u8 *)data_end)
                    payload_start = NULL;
            }
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(iph + 1);
        if ((void *)(udp + 1) <= data_end) {
            payload_start = (__u8 *)(udp + 1);
            if (payload_start > (__u8 *)data_end)
                payload_start = NULL;
        }
    }

    // PHASE 2: Track source IP behavior (BEFORE any drops - captures attack patterns)
    track_source_ip_behavior(iph->saddr, proto, tcp_flags, now);

    // Build compound key once (reused for all per-origin lookups)
    struct origin_rep_key origin_key = {
        .src_ip = iph->saddr,
        .dst_eip = iph->daddr
    };
    __u32 now_sec_rep = (__u32)(now / NS_PER_SEC);

    // LAYER 0.5: Per-Origin Whitelist (HIGHEST PRIORITY for client traffic)
    struct origin_rep_value *origin_wl = bpf_map_lookup_elem(&origin_whitelist_map, &origin_key);
    if (origin_wl && origin_wl->active) {
        if (origin_wl->expires_at == 0 || now_sec_rep < origin_wl->expires_at) {
            bump_eip_security_stat(iph->daddr, STAT_ORIGIN_WHITELIST_BYPASS);
            return XDP_PASS;
        }
    }

    // STEP 1: Global Whitelist (existing code)
    __u8 *wl = bpf_map_lookup_elem(&whitelist_map, &iph->saddr);
    if (wl && *wl == 1) {
        xdp_bump_stat(XDP_STAT_WHITELIST_BYPASS);
        return XDP_PASS;
    }

    // LAYER 1.5: Per-Origin Override (skip global blacklist for this origin)
    int skip_global_blacklist = 0;
    struct origin_rep_value *override = bpf_map_lookup_elem(&origin_override_map, &origin_key);
    if (override && override->active) {
        skip_global_blacklist = 1;
        bump_eip_security_stat(iph->daddr, STAT_ORIGIN_OVERRIDE_USED);
    }

    // LAYER 2: Temp Blacklist (NOW PER-ORIGIN - uses compound key)
    struct origin_rep_value *temp_bl = bpf_map_lookup_elem(&temp_blacklist_map, &origin_key);
    if (temp_bl && temp_bl->active) {
        if (temp_bl->expires_at == 0 || now_sec_rep < temp_bl->expires_at) {
            xdp_bump_stat(XDP_STAT_DROP_TEMP_BLACKLIST);
            bump_eip_security_stat(iph->daddr, STAT_DROP_TEMP_BLACKLIST);
            log_audit_proof(payload_start, payload_end, XDP_DROP, XDP_STAT_DROP_TEMP_BLACKLIST, now);
            return XDP_DROP;
        }
        // Entry expired - could delete here or let cleanup handle it
    }

    // LAYER 3: Global Blacklist (skip if overridden)
    if (!skip_global_blacklist) {
        struct lpm_key key = {
            .prefixlen = 32,
            .ip = iph->saddr
        };
        __u8 *rep = bpf_map_lookup_elem(&blacklist_map, &key);
        if (rep && *rep < 20) {
            xdp_bump_stat(XDP_STAT_DROP_BLACKLIST);
            bump_eip_security_stat(iph->daddr, STAT_DROP_BLACKLIST);
            log_audit_proof(payload_start, payload_end, XDP_DROP, XDP_STAT_DROP_BLACKLIST, now);
            return XDP_DROP;
        }
    }

    // LAYER 4: Per-Origin Blacklist (client-controlled block)
    struct origin_rep_value *origin_bl = bpf_map_lookup_elem(&origin_blacklist_map, &origin_key);
    if (origin_bl && origin_bl->active) {
        if (origin_bl->expires_at == 0 || now_sec_rep < origin_bl->expires_at) {
            xdp_bump_stat(XDP_STAT_DROP_BLACKLIST);
            bump_eip_security_stat(iph->daddr, STAT_DROP_ORIGIN_BLACKLIST);
            log_audit_proof(payload_start, payload_end, XDP_DROP, XDP_STAT_DROP_BLACKLIST, now);
            return XDP_DROP;
        }
    }

    // STEP 2.5: Layer 2 - Bogon source filtering (before protocol validation)
    if (check_bogon_source(iph->saddr) == XDP_DROP) {
        xdp_bump_stat(XDP_STAT_DROP_BOGON);
        bump_eip_security_stat(iph->daddr, 4);
        log_audit_proof(payload_start, payload_end, XDP_DROP, XDP_STAT_DROP_BOGON, now);
        return XDP_DROP;
    }

    // STEP 3: Invalid IP header validation (protocol compliance)
    if (validate_ip_header(iph) == XDP_DROP) {
        xdp_bump_stat(XDP_STAT_DROP_INVALID_IP);
        log_audit_proof(payload_start, payload_end, XDP_DROP, XDP_STAT_DROP_INVALID_IP, now);
        return XDP_DROP;
    }

    // STEP 4: Invalid TCP flags validation (use already-extracted tcp_flags)
    if (proto == IPPROTO_TCP && tcp_flags != 0) {
        if (validate_tcp_flags(tcp_flags) == XDP_DROP) {
            xdp_bump_stat(XDP_STAT_DROP_INVALID_TCP);
            log_audit_proof(payload_start, payload_end, XDP_DROP, XDP_STAT_DROP_INVALID_TCP, now);
            return XDP_DROP;
        }
    }

    // STEP 4.5: Layer 0 - Bypass check (4-tuple fast path for validated flows)
    // Extract destination info (need VIP and port for bypass/quarantine lookup)
    __be32 dst_ip = iph->daddr;  // This is the EIP before DNAT
    __u16 src_port = 0, dst_port = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(iph + 1);
        if ((void *)(tcp + 1) <= data_end) {
            src_port = tcp->source;
            dst_port = tcp->dest;

            // Check bypass map (cookie-validated flows skip quarantine + rate limiting)
            if (is_bypassed(iph->saddr, src_port, dst_ip, dst_port, now)) {
                xdp_bump_stat(XDP_STAT_BYPASS_ALLOWED);
                return XDP_PASS;
            }
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(iph + 1);
        if ((void *)(udp + 1) <= data_end) {
            src_port = udp->source;
            dst_port = udp->dest;

            // UDP bypass check (for QUIC or other UDP-based protocols)
            if (is_bypassed(iph->saddr, src_port, dst_ip, dst_port, now)) {
                xdp_bump_stat(XDP_STAT_BYPASS_ALLOWED);
                return XDP_PASS;
            }
        }
    }

    int cookie_mode_enabled = 0;
    if (proto == IPPROTO_TCP)
        cookie_mode_enabled = vip_cookie_enabled(dst_ip);

    // STEP 4.6: Layer 0 - Quarantine check (per-source penalty for cookie failures)
    // Check if this source IP is quarantined for this VIP
    int is_syn = (tcp_flags & 0x02) && !(tcp_flags & 0x10);
    int is_ack = (tcp_flags & 0x10);

    if (cookie_mode_enabled && proto == IPPROTO_TCP) {
        if (is_syn) {
            xdp_bump_stat(XDP_STAT_SYNCOOKIE_CHALLENGE);
            return XDP_PASS;
        }
        if (is_ack) {
            xdp_bump_stat(XDP_STAT_SYNCOOKIE_VALIDATED);
            return XDP_PASS;
        }
    }

    if (is_quarantined(iph->saddr, dst_ip, now)) {
        xdp_bump_stat(XDP_STAT_DROP_QUARANTINE);
        bump_eip_security_stat(iph->daddr, 3);
        log_audit_proof(payload_start, payload_end, XDP_DROP, XDP_STAT_DROP_QUARANTINE, now);
        return XDP_DROP;
    }

    // === LAYER 11: Rate Limiting (Intelligent) ===
    // UPGRADED: Now uses context-aware intelligent rate limiting
    // instead of static machine_limits-based limiting.
    // Factors: trust level, origin bandwidth, scrubber load, protocol type
    int rl_result = intelligent_rate_limit(iph->saddr, dst_ip, tcp_flags, now);
    if (rl_result == XDP_DROP) {
        xdp_bump_stat(XDP_STAT_DROP_RATELIMIT);
        bump_eip_security_stat(iph->daddr, STAT_DROP_RATELIMIT);
        log_audit_proof(payload_start, payload_end, XDP_DROP, XDP_STAT_DROP_RATELIMIT, now);
        return XDP_DROP;
    }

    // Default: pass (no match in any filter)
    xdp_bump_stat(XDP_STAT_PASS);
    log_audit_proof(payload_start, payload_end, XDP_PASS, XDP_STAT_PASS, now);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
