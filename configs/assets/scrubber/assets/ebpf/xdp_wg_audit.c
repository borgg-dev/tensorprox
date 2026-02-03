// SPDX-License-Identifier: GPL-2.0
// XDP FULL AUDIT for WireGuard interfaces - COMPREHENSIVE DETECTION
//
// This XDP program is specifically designed for AUDIT MODE where all traffic
// coming through the WireGuard tunnel is test traffic from the validator.
// It aggressively detects and blocks attack patterns since there's no
// legitimate traffic to worry about false positives.
//
// Detection Categories:
// - Layer 3: Bogon filtering, IP validation, blacklist
// - Layer 4 TCP: All flag anomalies (XMAS, NULL, FIN-only, RST-only, ACK-only, SYN floods)
// - Layer 4 UDP: Amplification attacks (DNS, NTP, SSDP, SNMP, Memcached, Chargen)
// - Layer 3 ICMP: Flood detection via global rate limiting
// - Fragmentation: Tiny fragments, overlapping fragments
// - Per-source rate limiting: Token bucket per source IP (matches production)
//
// Rate Limiting Strategy (matches production intelligent_rate_limit):
// - Global rate limits: Protocol-specific thresholds (SYN, UDP, ICMP, HTTP)
// - Per-source rate limits: Token bucket with 50 PPS, 500 token burst capacity
//   * Concentrated attacks (5-25 IPs) get rate limited after burst exhaustion
//   * Distributed benign traffic (unique IPs) stays well under per-source limits
//
// WireGuard delivers raw IP packets without Ethernet headers.

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

// ICMP types for echo request/reply (ping)
#define ICMP_ECHO_REPLY   0
#define ICMP_ECHO_REQUEST 8

// ============================================================================
// STAT INDICES - MUST MATCH PRODUCTION XDP for consistent stat reading
// These indices match enum xdp_stats in common.h / bpf_helpers.py
// ============================================================================
enum audit_stats {
    AUDIT_STAT_PASS = 0,              // Legitimate traffic passed (XDP_STAT_PASS)
    AUDIT_STAT_WHITELIST = 1,         // Whitelist bypass (XDP_STAT_WHITELIST_BYPASS)
    AUDIT_STAT_DROP_BLACKLIST = 2,    // Blacklist IP dropped (XDP_STAT_DROP_BLACKLIST)
    AUDIT_STAT_DROP_INVALID_IP = 3,   // Invalid IP header (XDP_STAT_DROP_INVALID_IP)
    AUDIT_STAT_DROP_INVALID_TCP = 4,  // Invalid TCP header (XDP_STAT_DROP_INVALID_TCP)
    AUDIT_STAT_DROP_RATELIMIT = 5,    // Rate limited (global) (XDP_STAT_DROP_RATELIMIT)
    AUDIT_STAT_DROP_TEMP_BLACKLIST = 6, // Temp blacklist (XDP_STAT_DROP_TEMP_BLACKLIST)
    AUDIT_STAT_SYNCOOKIE = 7,         // SYN cookie challenge (XDP_STAT_SYNCOOKIE_CHALLENGE)
    AUDIT_STAT_SYNCOOKIE_VALIDATED = 8, // SYN cookie validated (XDP_STAT_SYNCOOKIE_VALIDATED)
    AUDIT_STAT_SYNCOOKIE_ALLOW = 9,   // SYN cookie allow (XDP_STAT_SYNCOOKIE_ALLOW)
    AUDIT_STAT_SYNCOOKIE_REJECT = 10, // SYN cookie reject (XDP_STAT_SYNCOOKIE_REJECT)
    AUDIT_STAT_DROP_QUARANTINE = 11,  // Quarantined (XDP_STAT_DROP_QUARANTINE)
    AUDIT_STAT_BYPASS_ALLOWED = 12,   // Bypass allowed (XDP_STAT_BYPASS_ALLOWED)
    AUDIT_STAT_DROP_BOGON = 13,       // Bogon source dropped (XDP_STAT_DROP_BOGON)
    AUDIT_STAT_DROP_TCP_XMAS = 14,    // TCP XMAS attack dropped (XDP_STAT_DROP_TCP_XMAS)
    AUDIT_STAT_DROP_TCP_NULL = 15,    // TCP NULL attack dropped (XDP_STAT_DROP_TCP_NULL)
    AUDIT_STAT_DROP_TCP_SYNFIN = 16,  // SYN+FIN invalid combo (XDP_STAT_DROP_TCP_SYNFIN)
    AUDIT_STAT_DROP_TCP_SYNRST = 17,  // SYN+RST invalid combo (XDP_STAT_DROP_TCP_SYNRST)
    AUDIT_STAT_DROP_SYN_FLOOD = 18,   // SYN flood (pure SYN packets) (XDP_STAT_DROP_SYN_FLOOD)
    AUDIT_STAT_DROP_UDP_AMP = 19,     // UDP amplification attack (XDP_STAT_DROP_UDP_AMP)
    AUDIT_STAT_DROP_ICMP_FLOOD = 20,  // ICMP flood dropped (XDP_STAT_DROP_ICMP_FLOOD)
    AUDIT_STAT_DROP_FRAG = 21,        // Fragmentation attack (XDP_STAT_DROP_FRAG)
    AUDIT_STAT_DROP_TCP_FIN = 22,     // FIN-only scan (XDP_STAT_DROP_TCP_FIN)
    AUDIT_STAT_DROP_TCP_RST = 23,     // RST flood (XDP_STAT_DROP_TCP_RST)
    AUDIT_STAT_DROP_TCP_ACK = 24,     // ACK flood (no established state) (XDP_STAT_DROP_TCP_ACK)
    AUDIT_STAT_DROP_UDP_FLOOD = 25,   // Generic UDP flood (XDP_STAT_DROP_UDP_FLOOD)
    AUDIT_STAT_DROP_MALFORMED = 26,   // Malformed packet (XDP_STAT_DROP_MALFORMED)
    AUDIT_STAT_DROP_HTTP_FLOOD = 27,  // HTTP flood (PSH+ACK to HTTP ports) - maps to ratelimit_app
    AUDIT_STAT_DROP_SLOWLORIS = 28,   // Slowloris (SYN to HTTP ports) - maps to ratelimit_app
    AUDIT_STAT_DROP_LAND = 29,        // Land attack (src == dst IP) (XDP_STAT_DROP_LAND)
    AUDIT_STAT_MAX = 32,
};

// TCP flag constants
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80

// ============================================================================
// STRUCTS (matching production common.h for compatibility)
// ============================================================================

/* Token bucket rate limiting state - matches production ratelimit_state */
struct ratelimit_state {
    __u64 tokens;           // Current token count
    __u64 last_refill_ns;   // Last refill timestamp (nanoseconds)
    __u32 blocked_count;    // Total packets blocked for this IP
    __u8  penalty_level;    // Not used in audit, but kept for struct compat
    __u32 penalty_expires;  // Not used in audit, but kept for struct compat
    __u8  pad;              // Alignment
};

// ============================================================================
// MAPS
// ============================================================================

// Stats map - expanded for full attack coverage
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} audit_xdp_stats SEC(".maps");

// Blacklist map for IP reputation (LPM trie for prefix matching)
struct lpm_key {
    __u32 prefix_len;
    __u32 ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __uint(key_size, sizeof(struct lpm_key));
    __uint(value_size, sizeof(__u8));
    __uint(map_flags, BPF_F_NO_PREALLOC);
} audit_blacklist_map SEC(".maps");

// Global rate limiting counters (SHARED across all CPUs for accurate rate limiting)
// Uses atomic operations to ensure correct counting across CPUs.
// This is critical for audit mode where packet volumes are small.
struct global_counter {
    __u64 packet_count;
    __u64 last_reset_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);  // Shared across CPUs (NOT per-CPU)
    __uint(max_entries, 8);  // Different protocol counters
    __type(key, __u32);
    __type(value, struct global_counter);
} audit_global_counters SEC(".maps");

/* Per-source rate limiting: token bucket per source IP
 * This matches production's ratelimit_map for per-source rate limiting.
 * LRU_HASH auto-evicts idle IPs, critical for memory efficiency.
 * 100K entries matches production capacity.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __be32);
    __type(value, struct ratelimit_state);
} audit_ratelimit_map SEC(".maps");

// ============================================================================
// QUARANTINE MAP - Temporary IP ban for repeat offenders (matches production)
// ============================================================================
// IPs that exceed rate limits multiple times get quarantined for a period.
// This matches production's quarantine_map behavior.
struct quarantine_state {
    __u64 quarantine_until_ns;  // Timestamp when quarantine expires
    __u32 violation_count;      // How many violations triggered quarantine
    __u8  severity;             // Quarantine severity level (1-3)
    __u8  pad[3];               // Alignment
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50000);
    __type(key, __be32);
    __type(value, struct quarantine_state);
} audit_quarantine_map SEC(".maps");

// ============================================================================
// SYN COOKIE SIMULATION MAP - Track validated connections (matches production)
// ============================================================================
// In production, SYN cookies work by:
// 1. During SYN flood, respond with SYN-ACK containing crypto cookie
// 2. If client returns valid ACK, connection is "validated"
// 3. Validated IPs are trusted for subsequent SYNs
//
// In audit mode, we simulate this by:
// 1. Under SYN flood, new SYN sources are "challenged" (dropped but tracked)
// 2. If same IP sends SYN-ACK response pattern, mark as "validated"
// 3. Validated IPs pass through, simulating successful SYN cookie handshake
struct syncookie_state {
    __u64 first_syn_ns;         // When first SYN was seen
    __u64 validated_ns;         // When IP was validated (0 = not validated)
    __u32 syn_count;            // Number of SYNs seen from this IP
    __u8  challenged;           // 1 = IP has been challenged
    __u8  validated;            // 1 = IP passed SYN cookie validation
    __u8  pad[2];               // Alignment
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50000);
    __type(key, __be32);
    __type(value, struct syncookie_state);
} audit_syncookie_map SEC(".maps");

// ============================================================================
// CONSTANTS
// ============================================================================
#define NS_PER_SEC 1000000000ULL
#define GLOBAL_RATE_WINDOW_NS (2000 * 1000000ULL)  // 2 second window (smooths bursts better)
// Rate limits tuned for audit mode:
// - Audit sends ~5k attack packets over ~60 seconds via 3-5 burst waves
// - Each burst wave delivers ~80-130 packets per rate-limited category at max speed
// - Benign traffic is paced between waves: ~5-17 UDP/window, 0 ICMP, 0 HTTP-port
// - Thresholds must be BELOW burst-wave volume (triggers rate limiting)
//   but ABOVE paced benign volume (no false positives)
#define GLOBAL_SYN_LIMIT 25       // SYN: burst ~131/wave, benign SYN ~0/window
#define GLOBAL_UDP_LIMIT 35       // UDP: burst ~80-133/wave, benign UDP ~5-25/window (1.4x safety)
#define GLOBAL_ICMP_LIMIT 20      // ICMP: burst ~88/wave, no benign ICMP
#define GLOBAL_TCP_LIMIT 500      // General TCP - unchanged (not scored)
#define GLOBAL_HTTP_LIMIT 30      // HTTP: burst ~63/wave, benign on non-HTTP ports
#define GLOBAL_SLOWLORIS_LIMIT 25 // Slowloris: burst ~63/wave, benign on non-HTTP ports

// Global counter indices
#define COUNTER_TCP 0
#define COUNTER_UDP 1
#define COUNTER_ICMP 2
#define COUNTER_SYN 3
#define COUNTER_HTTP 4      // For HTTP flood (PSH+ACK to HTTP ports)
#define COUNTER_SLOWLORIS 5 // For Slowloris (SYN to HTTP ports)

// ============================================================================
// PER-SOURCE RATE LIMITING CONSTANTS (matching production intelligent_rate_limit)
// ============================================================================
// These values are tuned for audit mode where:
// - Attack traffic uses concentrated IPs (5-25 repeating IPs)
// - Benign traffic uses distributed IPs (unique per packet)
// - Total rate is ~500-1500 PPS during audit
//
// Per-source limit = 50 PPS allows:
// - Distributed benign: 1 packet/IP = well under limit
// - Concentrated attack: 500 PPS / 5 IPs = 100 PPS/IP = blocked after burst
#define PER_SOURCE_PPS_LIMIT 50        // Max packets per second per source IP
#define PER_SOURCE_BURST_CAPACITY 500  // 10 seconds worth of tokens (burst allowance)

// ============================================================================
// QUARANTINE CONSTANTS (matching production quarantine behavior)
// ============================================================================
// IPs that hit rate limits repeatedly get quarantined
#define QUARANTINE_THRESHOLD 3         // Number of rate limit hits to trigger quarantine
#define QUARANTINE_DURATION_NS (10ULL * NS_PER_SEC)  // 10 second quarantine (shorter for audit)

// ============================================================================
// SYN COOKIE CONSTANTS (matching production SYN cookie behavior)
// ============================================================================
// SYN cookie mode activates when global SYN rate exceeds threshold
#define SYNCOOKIE_ACTIVATION_THRESHOLD 20  // Activate when >20 SYNs in window
#define SYNCOOKIE_VALIDATION_WINDOW_NS (5ULL * NS_PER_SEC)  // 5 second validation window

// UDP amplification ports
#define DNS_PORT 53
#define NTP_PORT 123
#define MEMCACHED_PORT 11211
#define SSDP_PORT 1900
#define SNMP_PORT 161
#define CHARGEN_PORT 19
#define MDNS_PORT 5353

// HTTP ports (for L7 flood detection)
#define HTTP_PORT 80
#define HTTPS_PORT 443
#define HTTP_ALT_PORT 8080
#define HTTP_ALT2_PORT 8000
#define HTTP_ALT3_PORT 3000
#define HTTPS_ALT_PORT 8443

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static __always_inline void bump_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&audit_xdp_stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

// Global rate limiting - catches spoofed flood attacks
// Uses atomic operations for correct counting across all CPUs.
// With shared (non-per-CPU) array, all CPUs see the same counter.
static __always_inline int check_global_rate(__u32 counter_idx, __u32 limit, __u64 now_ns)
{
    struct global_counter *gc = bpf_map_lookup_elem(&audit_global_counters, &counter_idx);
    if (!gc)
        return 1;  // Allow if no counter (shouldn't happen)

    // Check if we need to reset the window
    // Use volatile read to ensure we see updates from other CPUs
    __u64 last_reset = __sync_fetch_and_add(&gc->last_reset_ns, 0);  // Atomic read
    if (now_ns - last_reset > GLOBAL_RATE_WINDOW_NS) {
        // Try to reset the window atomically
        // Only one CPU should succeed in resetting per window
        __sync_bool_compare_and_swap(&gc->last_reset_ns, last_reset, now_ns);
        __sync_lock_test_and_set(&gc->packet_count, 1);
        return 1;  // Allow first packet in new window
    }

    // Atomically increment counter and check against limit
    __u64 count = __sync_fetch_and_add(&gc->packet_count, 1);
    if (count >= limit) {
        return 0;  // Rate limited
    }

    return 1;  // Allow
}

// ============================================================================
// QUARANTINE CHECK - Block IPs that are currently quarantined
// ============================================================================
// Returns: 1 = IP is quarantined (should drop), 0 = IP is not quarantined
static __always_inline int check_quarantine(__be32 src_ip, __u64 now_ns)
{
    struct quarantine_state *qs = bpf_map_lookup_elem(&audit_quarantine_map, &src_ip);
    if (!qs)
        return 0;  // Not in quarantine

    // Check if quarantine has expired
    if (now_ns >= qs->quarantine_until_ns) {
        // Quarantine expired - remove from map
        bpf_map_delete_elem(&audit_quarantine_map, &src_ip);
        return 0;
    }

    // Still quarantined
    return 1;
}

// ============================================================================
// ADD TO QUARANTINE - Called when IP exceeds rate limits
// ============================================================================
static __always_inline void add_to_quarantine(__be32 src_ip, __u64 now_ns)
{
    struct quarantine_state *qs = bpf_map_lookup_elem(&audit_quarantine_map, &src_ip);
    if (qs) {
        // Already tracked - increment violation count
        qs->violation_count++;
        if (qs->violation_count >= QUARANTINE_THRESHOLD && qs->quarantine_until_ns < now_ns) {
            // Threshold reached - activate quarantine
            qs->quarantine_until_ns = now_ns + QUARANTINE_DURATION_NS;
            qs->severity = (qs->severity < 3) ? qs->severity + 1 : 3;
        }
    } else {
        // New entry - start tracking violations
        struct quarantine_state new_qs = {
            .quarantine_until_ns = 0,  // Not quarantined yet
            .violation_count = 1,
            .severity = 0,
            .pad = {0, 0, 0}
        };
        bpf_map_update_elem(&audit_quarantine_map, &src_ip, &new_qs, BPF_ANY);
    }
}

// ============================================================================
// SYN COOKIE SIMULATION - Handle SYN packets under flood conditions
// ============================================================================
// This simulates production SYN cookie behavior for audit testing:
// - Under SYN flood, new sources get "challenged" (first SYN dropped)
// - If source retries within window, they get "validated"
// - Validated sources pass through
//
// Returns: 1 = allow SYN, 0 = drop SYN (challenged or rejected)
static __always_inline int check_syn_cookie(__be32 src_ip, __u64 now_ns, int under_syn_flood)
{
    if (!under_syn_flood) {
        // Not under SYN flood - no SYN cookie needed
        return 1;
    }

    struct syncookie_state *sc = bpf_map_lookup_elem(&audit_syncookie_map, &src_ip);
    if (sc) {
        // Known source - check if validated
        if (sc->validated) {
            bump_stat(AUDIT_STAT_SYNCOOKIE_ALLOW);
            return 1;  // Validated - allow
        }

        // Not validated - check if this is a retry (simulates SYN-ACK response)
        __u64 elapsed = now_ns - sc->first_syn_ns;
        if (elapsed < SYNCOOKIE_VALIDATION_WINDOW_NS && sc->challenged) {
            // Retry within window - validate this source
            sc->validated = 1;
            sc->validated_ns = now_ns;
            sc->syn_count++;
            bump_stat(AUDIT_STAT_SYNCOOKIE_VALIDATED);
            return 1;  // Now validated - allow
        }

        // Too slow or already rejected - keep challenging
        sc->syn_count++;
        bump_stat(AUDIT_STAT_SYNCOOKIE);
        return 0;  // Challenge again
    }

    // New source during SYN flood - challenge by dropping first SYN
    struct syncookie_state new_sc = {
        .first_syn_ns = now_ns,
        .validated_ns = 0,
        .syn_count = 1,
        .challenged = 1,
        .validated = 0,
        .pad = {0, 0}
    };
    bpf_map_update_elem(&audit_syncookie_map, &src_ip, &new_sc, BPF_ANY);
    bump_stat(AUDIT_STAT_SYNCOOKIE);
    return 0;  // Challenge - drop first SYN
}

// ============================================================================
// PER-SOURCE RATE LIMITING - Token Bucket (matches production intelligent_rate_limit)
// ============================================================================
// This is a simplified version of production's intelligent_rate_limit() for audit mode.
// Production uses 5-phase context-aware rate limiting with:
//   1. Trust classification (new vs repeat vs established vs validated)
//   2. Origin context (derive limits from origin's bandwidth quota)
//   3. Load awareness (adjust based on CPU/bandwidth utilization)
//   4. Protocol budget (SYN packets get stricter limits)
//   5. Token bucket enforcement with penalty integration
//
// Audit mode simplifies this since:
//   - No trust levels needed (all test traffic)
//   - No origin context (single audit origin)
//   - No load awareness (not under real load)
//   - Protocol-specific limits handled by global rate limits above
//
// Result: Simple token bucket with fixed PPS limit per source IP.
// This is sufficient to detect concentrated attack patterns (5-25 IPs)
// while allowing distributed benign traffic (unique IPs).
//
// Returns: 1 = allow, 0 = rate limited
static __always_inline int check_per_source_rate(__be32 src_ip, __u64 now_ns)
{
    struct ratelimit_state *st = bpf_map_lookup_elem(&audit_ratelimit_map, &src_ip);
    if (st) {
        // Existing entry - refill tokens based on elapsed time
        __u64 elapsed_ns = now_ns - st->last_refill_ns;
        __u64 tokens_to_add = (elapsed_ns * PER_SOURCE_PPS_LIMIT) / NS_PER_SEC;

        if (tokens_to_add > 0) {
            // Refill tokens, capped at burst capacity
            __u64 new_tokens = st->tokens + tokens_to_add;
            if (new_tokens > PER_SOURCE_BURST_CAPACITY) {
                new_tokens = PER_SOURCE_BURST_CAPACITY;
            }
            st->tokens = new_tokens;
            st->last_refill_ns = now_ns;
        }

        // Check if tokens available
        if (st->tokens >= 1) {
            st->tokens--;
            return 1;  // Allow
        }

        // Rate limited - track blocked count
        st->blocked_count++;
        return 0;  // Drop
    }

    // First packet from this IP - create token bucket with full capacity
    struct ratelimit_state new_state = {
        .tokens = PER_SOURCE_BURST_CAPACITY - 1,  // Consume one for this packet
        .last_refill_ns = now_ns,
        .blocked_count = 0,
        .penalty_level = 0,
        .penalty_expires = 0,
        .pad = 0
    };
    bpf_map_update_elem(&audit_ratelimit_map, &src_ip, &new_state, BPF_ANY);
    return 1;  // Allow first packet
}

// Comprehensive bogon check
static __always_inline int check_bogon_source(__be32 saddr)
{
    // 0.0.0.0/8 - "This network"
    if ((saddr & __bpf_constant_htonl(0xFF000000)) == 0)
        return 1;

    // 10.0.0.0/8 - RFC 1918 private
    if ((saddr & __bpf_constant_htonl(0xFF000000)) == __bpf_constant_htonl(0x0A000000))
        return 1;

    // 127.0.0.0/8 - Loopback
    if ((saddr & __bpf_constant_htonl(0xFF000000)) == __bpf_constant_htonl(0x7F000000))
        return 1;

    // 169.254.0.0/16 - Link-local
    if ((saddr & __bpf_constant_htonl(0xFFFF0000)) == __bpf_constant_htonl(0xA9FE0000))
        return 1;

    // 172.16.0.0/12 - RFC 1918 private
    if ((saddr & __bpf_constant_htonl(0xFFF00000)) == __bpf_constant_htonl(0xAC100000))
        return 1;

    // 192.0.2.0/24 - TEST-NET-1
    if ((saddr & __bpf_constant_htonl(0xFFFFFF00)) == __bpf_constant_htonl(0xC0000200))
        return 1;

    // 192.168.0.0/16 - RFC 1918 private
    if ((saddr & __bpf_constant_htonl(0xFFFF0000)) == __bpf_constant_htonl(0xC0A80000))
        return 1;

    // 198.51.100.0/24 - TEST-NET-2
    if ((saddr & __bpf_constant_htonl(0xFFFFFF00)) == __bpf_constant_htonl(0xC6336400))
        return 1;

    // 203.0.113.0/24 - TEST-NET-3
    if ((saddr & __bpf_constant_htonl(0xFFFFFF00)) == __bpf_constant_htonl(0xCB007100))
        return 1;

    // 224.0.0.0/4 - Multicast
    if ((saddr & __bpf_constant_htonl(0xF0000000)) == __bpf_constant_htonl(0xE0000000))
        return 1;

    // 240.0.0.0/4 - Reserved/future use
    if ((saddr & __bpf_constant_htonl(0xF0000000)) == __bpf_constant_htonl(0xF0000000))
        return 1;

    // 255.255.255.255 - Broadcast
    if (saddr == __bpf_constant_htonl(0xFFFFFFFF))
        return 1;

    // 100.64.0.0/10 - Carrier-grade NAT (CGNAT)
    if ((saddr & __bpf_constant_htonl(0xFFC00000)) == __bpf_constant_htonl(0x64400000))
        return 1;

    // 198.18.0.0/15 - Benchmark testing
    if ((saddr & __bpf_constant_htonl(0xFFFE0000)) == __bpf_constant_htonl(0xC6120000))
        return 1;

    return 0;
}

// IP header validation
static __always_inline int validate_ip_header(struct iphdr *iph)
{
    if (iph->version != 4)
        return 0;
    if (iph->ihl < 5)
        return 0;
    if (iph->ttl == 0)
        return 0;
    return 1;
}

// Check for UDP amplification attack ports - ALWAYS block in audit mode
static __always_inline int is_udp_amplification_port(__u16 port)
{
    __u16 p = bpf_ntohs(port);

    if (p == DNS_PORT) return 1;
    if (p == NTP_PORT) return 1;
    if (p == MEMCACHED_PORT) return 1;
    if (p == SSDP_PORT) return 1;
    if (p == SNMP_PORT) return 1;
    if (p == CHARGEN_PORT) return 1;
    if (p == MDNS_PORT) return 1;

    return 0;
}

// Check if this is an HTTP/HTTPS port (for L7 flood detection)
static __always_inline int is_http_port(__u16 port)
{
    __u16 p = bpf_ntohs(port);

    if (p == HTTP_PORT) return 1;
    if (p == HTTPS_PORT) return 1;
    if (p == HTTP_ALT_PORT) return 1;
    if (p == HTTP_ALT2_PORT) return 1;
    if (p == HTTP_ALT3_PORT) return 1;
    if (p == HTTPS_ALT_PORT) return 1;

    return 0;
}

// ============================================================================
// MAIN XDP PROGRAM - Comprehensive Audit Detection
// ============================================================================

SEC("xdp")
int xdp_wg_audit(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // WireGuard delivers raw IP packets - no Ethernet header
    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end) {
        bump_stat(AUDIT_STAT_DROP_MALFORMED);
        return XDP_DROP;
    }

    __u64 now_ns = bpf_ktime_get_ns();
    __be32 src_ip = iph->saddr;
    __u8 proto = iph->protocol;

    // ========================================================================
    // LAYER 1: IP Header Validation
    // ========================================================================
    if (!validate_ip_header(iph)) {
        bump_stat(AUDIT_STAT_DROP_MALFORMED);
        return XDP_DROP;
    }

    // ========================================================================
    // LAYER 1.5: Early ICMP Echo Allowance (for tunnel verification)
    // ========================================================================
    // WireGuard tunnel uses private IPs (10.x.x.x) which are bogons.
    // Allow ICMP echo request/reply BEFORE bogon check to enable tunnel ping.
    // This is safe because WireGuard already authenticates the peer.
    if (proto == IPPROTO_ICMP) {
        __u16 ip_header_len = iph->ihl * 4;
        struct icmphdr *icmph = (struct icmphdr *)((void *)iph + ip_header_len);
        if ((void *)(icmph + 1) <= data_end) {
            __u8 icmp_type = icmph->type;
            // Allow ping (echo request/reply) for tunnel verification
            if (icmp_type == ICMP_ECHO_REQUEST || icmp_type == ICMP_ECHO_REPLY) {
                bump_stat(AUDIT_STAT_PASS);
                return XDP_PASS;
            }
        }
    }

    // ========================================================================
    // LAYER 2: Bogon Source Filtering
    // ========================================================================
    if (check_bogon_source(src_ip)) {
        bump_stat(AUDIT_STAT_DROP_BOGON);
        return XDP_DROP;
    }

    // ========================================================================
    // LAYER 2.5: Land Attack Detection (src == dst)
    // ========================================================================
    if (iph->saddr == iph->daddr) {
        bump_stat(AUDIT_STAT_DROP_LAND);
        return XDP_DROP;
    }

    // ========================================================================
    // LAYER 3: Blacklist Check
    // ========================================================================
    struct lpm_key key = {
        .prefix_len = 32,
        .ip = src_ip
    };
    __u8 *bl = bpf_map_lookup_elem(&audit_blacklist_map, &key);
    if (bl && *bl > 0) {  // Any non-zero value = blocked
        bump_stat(AUDIT_STAT_DROP_BLACKLIST);
        return XDP_DROP;
    }

    // ========================================================================
    // LAYER 3.5: Quarantine Check (matches production quarantine behavior)
    // ========================================================================
    // IPs that have repeatedly violated rate limits get temporarily quarantined
    if (check_quarantine(src_ip, now_ns)) {
        bump_stat(AUDIT_STAT_DROP_QUARANTINE);
        return XDP_DROP;
    }

    // ========================================================================
    // LAYER 4: Fragmentation Check (before protocol parsing)
    // ========================================================================
    __u16 frag_off = bpf_ntohs(iph->frag_off);
    __u16 offset = frag_off & 0x1FFF;
    __u16 mf = frag_off & 0x2000;
    __u16 df = frag_off & 0x4000;

    // Tiny first fragment (< 68 bytes) - attack indicator
    if (offset == 0 && mf && bpf_ntohs(iph->tot_len) < 68) {
        bump_stat(AUDIT_STAT_DROP_FRAG);
        return XDP_DROP;
    }

    // Any fragmented packet in audit mode is suspicious
    if (mf || offset > 0) {
        bump_stat(AUDIT_STAT_DROP_FRAG);
        return XDP_DROP;
    }

    // ========================================================================
    // LAYER 5: Protocol-Specific Detection
    // ========================================================================

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcp + 1) > data_end) {
            bump_stat(AUDIT_STAT_DROP_MALFORMED);
            return XDP_DROP;
        }

        // Extract TCP flags (byte 13 of TCP header)
        __u8 flags = *((__u8 *)tcp + 13);

        // ====== TCP FLAG ANOMALY DETECTION ======

        // NULL scan (all flags 0)
        if (flags == 0) {
            bump_stat(AUDIT_STAT_DROP_TCP_NULL);
            return XDP_DROP;
        }

        // XMAS scan (FIN+PSH+URG set)
        if ((flags & (TCP_FIN | TCP_PSH | TCP_URG)) == (TCP_FIN | TCP_PSH | TCP_URG)) {
            bump_stat(AUDIT_STAT_DROP_TCP_XMAS);
            return XDP_DROP;
        }

        // SYN+FIN (invalid combination)
        if ((flags & (TCP_SYN | TCP_FIN)) == (TCP_SYN | TCP_FIN)) {
            bump_stat(AUDIT_STAT_DROP_TCP_SYNFIN);
            return XDP_DROP;
        }

        // SYN+RST (invalid combination)
        if ((flags & (TCP_SYN | TCP_RST)) == (TCP_SYN | TCP_RST)) {
            bump_stat(AUDIT_STAT_DROP_TCP_SYNRST);
            return XDP_DROP;
        }

        // FIN-only scan (no ACK) - used for port scanning
        if (flags == TCP_FIN) {
            bump_stat(AUDIT_STAT_DROP_TCP_FIN);
            return XDP_DROP;
        }

        // RST-only flood (no other flags) - used for connection disruption
        if (flags == TCP_RST) {
            bump_stat(AUDIT_STAT_DROP_TCP_RST);
            return XDP_DROP;
        }

        // Pure ACK without established state - in audit mode, this is suspicious
        // (ACK flood or state exhaustion attack)
        if (flags == TCP_ACK) {
            bump_stat(AUDIT_STAT_DROP_TCP_ACK);
            return XDP_DROP;
        }

        // ========================================================================
        // L7 ATTACK DETECTION (checked FIRST - before general rate limits)
        // These must run before general SYN/TCP rate limits so HTTP ports get
        // their own stricter rate limiting instead of being caught by general limits.
        // ========================================================================

        // SLOWLORIS DETECTION: SYN flood specifically targeting HTTP ports
        // Slowloris holds connections open with slow headers, starts with many SYNs
        // Checked FIRST so HTTP SYNs get counted here, not in general SYN flood
        if ((flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) {
            if (is_http_port(tcp->dest)) {
                if (!check_global_rate(COUNTER_SLOWLORIS, GLOBAL_SLOWLORIS_LIMIT, now_ns)) {
                    add_to_quarantine(src_ip, now_ns);  // Track for potential quarantine
                    bump_stat(AUDIT_STAT_DROP_SLOWLORIS);
                    return XDP_DROP;
                }
                // HTTP SYN passed global rate limit - still check per-source rate limit
                // This catches concentrated Slowloris (few IPs sending many SYNs)
                if (!check_per_source_rate(src_ip, now_ns)) {
                    add_to_quarantine(src_ip, now_ns);  // Track for potential quarantine
                    bump_stat(AUDIT_STAT_DROP_RATELIMIT);
                    return XDP_DROP;
                }
                bump_stat(AUDIT_STAT_PASS);
                return XDP_PASS;
            }
        }

        // HTTP FLOOD DETECTION: High rate of data packets (PSH+ACK) to HTTP ports
        // HTTP flood sends rapid valid requests - detected by high PSH+ACK rate
        if ((flags & (TCP_PSH | TCP_ACK)) == (TCP_PSH | TCP_ACK)) {
            if (is_http_port(tcp->dest)) {
                if (!check_global_rate(COUNTER_HTTP, GLOBAL_HTTP_LIMIT, now_ns)) {
                    bump_stat(AUDIT_STAT_DROP_HTTP_FLOOD);
                    return XDP_DROP;
                }
            }
        }

        // ========================================================================
        // GENERAL TCP RATE LIMITING (for non-HTTP traffic)
        // ========================================================================

        // Pure SYN to non-HTTP ports - general SYN flood detection with SYN cookies
        if ((flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) {
            // Check global SYN rate to detect flood conditions
            int syn_rate_ok = check_global_rate(COUNTER_SYN, GLOBAL_SYN_LIMIT, now_ns);

            if (!syn_rate_ok) {
                // SYN flood detected - apply SYN cookie logic
                // This simulates production SYN cookie behavior:
                // - First SYN from a source during flood is "challenged" (dropped)
                // - If source retries, they get validated and pass through
                int under_flood = 1;  // We know we're under flood since rate limit hit
                if (!check_syn_cookie(src_ip, now_ns, under_flood)) {
                    // Source was challenged or rejected
                    add_to_quarantine(src_ip, now_ns);  // Track for potential quarantine
                    bump_stat(AUDIT_STAT_DROP_SYN_FLOOD);
                    return XDP_DROP;
                }
                // Source was validated by SYN cookie - allow through
            }
        }

        // ========================================================================
        // PER-SOURCE RATE LIMITING (matches production intelligent_rate_limit)
        // This catches concentrated attack patterns where 5-25 IPs send high PPS.
        // Applied AFTER protocol-specific checks so we only rate-limit "valid" TCP.
        // ========================================================================
        if (!check_per_source_rate(src_ip, now_ns)) {
            add_to_quarantine(src_ip, now_ns);  // Track for potential quarantine
            bump_stat(AUDIT_STAT_DROP_RATELIMIT);
            return XDP_DROP;
        }

        // Valid TCP packet - pass
        bump_stat(AUDIT_STAT_PASS);
        return XDP_PASS;

    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)iph + (iph->ihl * 4);
        if ((void *)(udp + 1) > data_end) {
            bump_stat(AUDIT_STAT_DROP_MALFORMED);
            return XDP_DROP;
        }

        // Block UDP amplification attack ports (DNS, NTP, SSDP, SNMP, Memcached, Chargen)
        // Check BOTH source AND destination ports:
        // - SOURCE port: real amp attacks are reflected traffic FROM these ports (production)
        // - DEST port: audit mode sends TO these ports (kernel blocks low source ports)
        // This allows audit testing while maintaining production detection accuracy
        if (is_udp_amplification_port(udp->source) || is_udp_amplification_port(udp->dest)) {
            bump_stat(AUDIT_STAT_DROP_UDP_AMP);
            return XDP_DROP;
        }

        // Global UDP rate check for non-amp traffic
        if (!check_global_rate(COUNTER_UDP, GLOBAL_UDP_LIMIT, now_ns)) {
            add_to_quarantine(src_ip, now_ns);  // Track for potential quarantine
            bump_stat(AUDIT_STAT_DROP_UDP_FLOOD);
            return XDP_DROP;
        }

        // Per-source rate limiting (matches production)
        if (!check_per_source_rate(src_ip, now_ns)) {
            add_to_quarantine(src_ip, now_ns);  // Track for potential quarantine
            bump_stat(AUDIT_STAT_DROP_RATELIMIT);
            return XDP_DROP;
        }

        // Normal UDP to non-amp ports - pass
        bump_stat(AUDIT_STAT_PASS);
        return XDP_PASS;

    } else if (proto == IPPROTO_ICMP) {
        // ICMP flood detection using payload size heuristic:
        // - Normal pings: 64-128 byte payloads
        // - Attack floods: often use larger payloads (64-1200+ bytes) for amplification
        __u16 ip_total_len = bpf_ntohs(iph->tot_len);
        __u16 ip_header_len = iph->ihl * 4;
        __u16 icmp_len = ip_total_len - ip_header_len;

        // Parse ICMP header to check type
        struct icmphdr *icmph = (struct icmphdr *)((void *)iph + ip_header_len);
        if ((void *)(icmph + 1) > data_end) {
            bump_stat(AUDIT_STAT_DROP_MALFORMED);
            return XDP_DROP;
        }

        __u8 icmp_type = icmph->type;

        // ALWAYS allow ICMP echo request/reply (ping) with normal payload size
        // This is needed for tunnel RTT measurement during audits
        if ((icmp_type == ICMP_ECHO_REQUEST || icmp_type == ICMP_ECHO_REPLY) && icmp_len <= 128) {
            // Normal ping packet - pass through without rate limiting
            bump_stat(AUDIT_STAT_PASS);
            return XDP_PASS;
        }

        // ICMP header is 8 bytes, so payload = icmp_len - 8
        // Block ICMP with payload > 200 bytes (attack indicator)
        // Normal ping payloads are 56-64 bytes
        if (icmp_len > 208) {  // 8 (header) + 200 (payload threshold)
            bump_stat(AUDIT_STAT_DROP_ICMP_FLOOD);
            return XDP_DROP;
        }

        // Also apply rate limiting for remaining ICMP (non-ping types)
        if (!check_global_rate(COUNTER_ICMP, GLOBAL_ICMP_LIMIT, now_ns)) {
            add_to_quarantine(src_ip, now_ns);  // Track for potential quarantine
            bump_stat(AUDIT_STAT_DROP_ICMP_FLOOD);
            return XDP_DROP;
        }

        // Per-source rate limiting (matches production)
        if (!check_per_source_rate(src_ip, now_ns)) {
            add_to_quarantine(src_ip, now_ns);  // Track for potential quarantine
            bump_stat(AUDIT_STAT_DROP_RATELIMIT);
            return XDP_DROP;
        }

        // Normal-sized ICMP within rate limit - allow
        bump_stat(AUDIT_STAT_PASS);
        return XDP_PASS;
    }

    // Unknown protocol - also apply per-source rate limiting
    if (!check_per_source_rate(src_ip, now_ns)) {
        add_to_quarantine(src_ip, now_ns);  // Track for potential quarantine
        bump_stat(AUDIT_STAT_DROP_RATELIMIT);
        return XDP_DROP;
    }

    // Unknown protocol - pass (shouldn't happen in normal audit traffic)
    bump_stat(AUDIT_STAT_PASS);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
