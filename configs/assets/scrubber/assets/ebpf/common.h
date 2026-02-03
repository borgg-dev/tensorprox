#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/types.h>

// Time constants
#define NS_PER_SEC 1000000000ULL
#define BYPASS_TTL_SEC 60
#define SYNCOOKIE_PENDING_TTL_SEC 8

// Required headers for shared functions
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifdef ENABLE_BPF_DEBUG
#define bpf_debug(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...) do { } while (0)
#endif

struct eip_entry {
    __be32 origin_ip;
    __u32  wg_ifindex;
    __u32  flags;
};

struct wg_entry {
    __be32 priv_ip;
};

enum origin_flags {
    ORIGIN_FLAG_ENABLED  = 0x1,
    ORIGIN_FLAG_DISABLED = 0x2,
};

/* Connection tracking structures for per-origin counting */
struct conn_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   protocol;
    __u8   pad[3];  /* Alignment */
} __attribute__((packed));

/* XDP statistics counters */
enum xdp_stats {
    XDP_STAT_PASS = 0,
    XDP_STAT_WHITELIST_BYPASS = 1,
    XDP_STAT_DROP_BLACKLIST = 2,
    XDP_STAT_DROP_INVALID_IP = 3,
    XDP_STAT_DROP_INVALID_TCP = 4,
    XDP_STAT_DROP_RATELIMIT = 5,
    XDP_STAT_DROP_TEMP_BLACKLIST = 6,
    XDP_STAT_SYNCOOKIE_CHALLENGE = 7,
    XDP_STAT_SYNCOOKIE_VALIDATED = 8,
    XDP_STAT_SYNCOOKIE_ALLOW = 9,
    XDP_STAT_SYNCOOKIE_REJECT = 10,
    XDP_STAT_DROP_QUARANTINE = 11,
    XDP_STAT_BYPASS_ALLOWED = 12,
    XDP_STAT_DROP_BOGON = 13,           // Layer 2: Bogon source addresses
    // Attack-specific detections (aligned with audit XDP)
    XDP_STAT_DROP_TCP_XMAS = 14,        // TCP XMAS attack (all flags)
    XDP_STAT_DROP_TCP_NULL = 15,        // TCP NULL attack (no flags)
    XDP_STAT_DROP_TCP_SYNFIN = 16,      // SYN+FIN invalid combo
    XDP_STAT_DROP_TCP_SYNRST = 17,      // SYN+RST invalid combo
    XDP_STAT_DROP_SYN_FLOOD = 18,       // SYN flood rate limit
    XDP_STAT_DROP_UDP_AMP = 19,         // UDP amplification attack
    XDP_STAT_DROP_ICMP_FLOOD = 20,      // ICMP flood
    XDP_STAT_DROP_FRAG = 21,            // Fragmentation attack
    XDP_STAT_DROP_TCP_FIN = 22,         // FIN-only scan
    XDP_STAT_DROP_TCP_RST = 23,         // RST flood
    XDP_STAT_DROP_TCP_ACK = 24,         // ACK flood
    XDP_STAT_DROP_UDP_FLOOD = 25,       // UDP flood rate limit
    XDP_STAT_DROP_MALFORMED = 26,       // Malformed packet
    XDP_STAT_DROP_HTTP_FLOOD = 27,      // L7 HTTP flood (PSH+ACK to HTTP ports) - maps to ratelimit_app
    XDP_STAT_DROP_SLOWLORIS = 28,       // L7 Slowloris (SYN flood to HTTP ports) - maps to ratelimit_app
    XDP_STAT_DROP_LAND = 29,            // Land attack (src == dst IP)
    XDP_STAT_MAX = 32,
};

enum wan_ingress_stats_idx {
    WAN_STAT_TOTAL = 0,
    WAN_STAT_MAP_HIT = 1,
    WAN_STAT_MAP_MISS = 2,
    WAN_STAT_DNAT = 3,
    WAN_STAT_CONN_NEW = 4,
    WAN_STAT_CONN_CLOSE = 5,
    WAN_STAT_SYNCOOKIE_SYN = 6,
    WAN_STAT_SYNCOOKIE_ACK_OK = 7,
    WAN_STAT_SYNCOOKIE_ACK_FAIL = 8,
};

/* LPM Trie key for CIDR-aware blacklist */
struct lpm_key {
    __u32 prefixlen;  // Prefix length (32 for /32, 24 for /24, etc.)
    __be32 ip;        // IP address in network byte order
};

/* Token bucket rate limiting with penalty support */
struct ratelimit_state {
    __u64 tokens;           // Current token count
    __u64 last_refill_ns;   // Last refill timestamp (nanoseconds)
    __u32 blocked_count;    // Total packets blocked for this IP
    __u8  penalty_level;    // 0=normal, 1=soft(50%), 2=medium(20%), 3=hard(5%)
    __u32 penalty_expires;  // Unix timestamp (seconds)
    __u8  pad;              // Alignment
};

struct machine_limits {
    __u32 token_capacity;     // Max tokens (burst size)
    __u32 token_refill_rate;  // Tokens/second
};

/* Scrubber real-time load metrics - updated by ECP agent every 5s
 * XDP reads this to adjust rate limits based on actual system load
 */
struct scrubber_load {
    __u8  cpu_pct;              // 0-100, CPU utilization percentage
    __u8  bw_utilization_pct;   // 0-100, bandwidth utilization percentage
    __u16 active_origin_count;  // Number of origins with active traffic
    __u32 total_pps;            // Aggregate PPS across all origins
    __u64 last_update_ns;       // bpf_ktime_get_ns() timestamp for staleness check
};

/* Per-source reputation tracking - combines manual + auto-detected
 * Key: src_ip (__be32)
 * Tracks trust level for graduated rate limiting
 */
struct source_reputation {
    __u32 successful_requests;  // Requests that reached origin (not blocked)
    __u32 blocked_requests;     // Requests blocked by any layer
    __u64 first_seen_ns;        // First packet timestamp (bpf_ktime_get_ns)
    __u64 last_seen_ns;         // Most recent packet timestamp
    __u8  trust_level;          // 0=new, 1=repeat, 2=established, 3=validated
    __u8  reserved1;            // Alignment padding
    __u16 reserved2;            // Alignment padding
};

/* Per-origin rate limit configuration - derived from bandwidth quota
 * Key: origin_ip (__be32)
 * Pre-configured on standby for fast failover
 */
struct origin_rate_config {
    __u64 quota_bps;              // Origin's bandwidth quota (from origin_bandwidth_map)
    __u32 derived_max_pps;        // quota_bps / (1500 * 8) - max packets/sec
    __u32 per_source_budget_pps;  // derived_max_pps / 100 - each source gets 1%
    __u32 current_pps;            // Aggregated from ecp-agent (updated every 30s)
    __u8  challenge_level;        // 0-4, from anomaly_detector (copied here for XDP access)
    __u8  override_enabled;       // 1 = use manual override values
    __u16 override_pps;           // If override_enabled, use this instead of derived
};

/* Per-source-IP behavior tracking for attack fingerprinting (PHASE 2) */
struct source_ip_behavior {
    __u64 syn_count;        // SYNs sent by this IP
    __u64 rst_count;        // RSTs sent by this IP
    __u64 packets_total;    // Total packets from this IP
    __u32 first_seen_ts;    // First packet timestamp (seconds)
    __u32 last_seen_ts;     // Last packet timestamp (seconds)
    __u16 burst_count;      // Packets in last 1 second (burst detection)
    __u16 pad;              // Alignment
};

/* Temporary blacklist entry with auto-expiration (PHASE 4) */
struct temp_blacklist_entry {
    __u32 expires_at;  // Unix timestamp (seconds)
    __u32 origin_id;   // 0 = global, >0 = origin-specific (future: hash of origin_id)
};

/* Per-origin reputation key: {src_ip, dst_eip} compound key */
struct origin_rep_key {
    __be32 src_ip;      // Source IP being checked
    __be32 dst_eip;     // Destination EIP (identifies origin)
} __attribute__((packed));

/* Per-origin reputation value */
struct origin_rep_value {
    __u8 active;        // 1=active, 0=expired/disabled
    __u8 reason_code;   // 0=manual, 1=auto, 2=tpm, 3=api
    __u16 cidr_prefix;  // For future CIDR support (32 = /32)
    __u32 expires_at;   // Unix timestamp, 0=permanent
} __attribute__((packed));

/* Origin statistics - lifetime counters for rate calculation */
struct origin_stats {
    __u64 conn_opened_total;   // Total connections opened (monotonic)
    __u64 conn_closed_total;   // Total connections closed (monotonic)
    __u64 packets_total;       // Total packets (monotonic)
    __u64 ingress_syn_count;   // Client → Origin SYNs (attack indicator)
    __u64 egress_synack_count; // Origin → Client SYN-ACKs (REAL legitimacy indicator)
    __u64 fin_count;           // FIN packets (graceful closes)
    __u64 rst_count;           // RST packets (attack indicator)
};

/* Per-EIP security drop counters for incident reporting */
struct eip_security_stats {
    __u64 drop_blacklist;        // Layer 1: Permanent blacklist hits
    __u64 drop_temp_blacklist;   // Layer 1: Temp blacklist hits
    __u64 drop_ratelimit;        // Layer 3: Rate limit drops
    __u64 drop_quarantine;       // Layer 4: Quarantine drops
    __u64 drop_bogon;            // Layer 2: Bogon source drops
    __u64 drop_origin_blacklist; // Per-origin blacklist hits
    __u64 origin_whitelist_bypass; // Per-origin whitelist bypasses
    __u64 origin_override_used;  // Per-origin override usage
};

/* Extended stats for per-origin reputation */
enum eip_security_stat_type {
    STAT_DROP_BLACKLIST = 0,
    STAT_DROP_TEMP_BLACKLIST = 1,
    STAT_DROP_RATELIMIT = 2,
    STAT_DROP_QUARANTINE = 3,
    STAT_DROP_BOGON = 4,
    STAT_DROP_ORIGIN_BLACKLIST = 5,    // NEW
    STAT_ORIGIN_WHITELIST_BYPASS = 6,  // NEW
    STAT_ORIGIN_OVERRIDE_USED = 7,     // NEW
};

/* Part 6: SYN cookie flow tracking */
struct syncookie_flow_key {
    __be32 src_ip;
    __be32 dst_eip;      // Pre-DNAT EIP
    __be16 src_port;
    __be16 dst_port;
} __attribute__((packed));

struct syncookie_allow_entry {
    __u32 expires_at;    // Unix timestamp (5s TTL)
    __u32 validated_at;  // When validated
};

struct syncookie_forward_stats_entry {
    __u64 packets;       // Data packets forwarded post-cookie
    __u64 bytes;         // TCP payload bytes forwarded
    __u32 last_seen;     // Last packet timestamp (seconds)
    __u32 reserved;
};

struct syncookie_seq_delta_entry {
    __s32 client_delta;  // client_seq adjustment: real_client_seq = client_seq + delta
    __s32 server_delta;  // server_seq adjustment: real_server_seq = server_seq + delta
    __u32 expires_at;    // Unix seconds TTL
};

enum syncookie_pending_state {
    SYNCOOKIE_PENDING_WAIT_ACK = 0,
    SYNCOOKIE_PENDING_WAIT_SYNACK = 1,
    SYNCOOKIE_PENDING_COMPLETED = 2,
    SYNCOOKIE_PENDING_EXPIRED = 3,
};

struct syncookie_pending_key {
    __be32 client_ip;
    __be32 vip_ip;
    __be16 client_port;
    __be16 vip_port;
} __attribute__((packed));

struct syncookie_pending_entry {
    __u32 client_seq;      // Client ISN (host order)
    __u32 cookie_value;    // Cookie issued to client
    __be32 origin_ip;      // Origin IP for SYN replay
    __u32 wg_ifindex;      // WireGuard interface for redirect
    __u32 expires_at;      // Unix seconds TTL
    __u8 state;            // enum syncookie_pending_state
    __u8 reserved[3];
};

/* Part 6: Per-EIP SYN cookie metrics */
struct syncookie_metrics {
    __u64 incoming_syn_pps;      // SYNs/sec to this EIP
    __u64 outgoing_synack_pps;   // SYN-ACKs sent (XDP_TX, future)
    __u64 cookie_validates;      // Valid cookie ACKs
    __u64 cookie_rejects;        // Invalid cookie ACKs
    __u64 syn_retransmits;       // SYN retransmits seen
    __u64 handshake_completes;   // Successful validations
    __u32 pending_cookies;       // Current challenged flows
    __u32 allow_list_size;       // Current allow-list entries
    __u64 challenged_clients;    // Unique IPs challenged
    __u64 false_positives;       // Legit clients failed
    __u32 last_update_ts;        // For rate calculations
    __u32 pad;
};

/* Part 6: TCP fingerprinting for attacker classification */
struct tcp_fingerprint {
    __u16 mss;               // Maximum Segment Size
    __u8  wscale;            // Window scale
    __u8  ttl;               // IP TTL
    __u8  has_sack;          // SACK permitted
    __u8  has_timestamp;     // Timestamp option
    __u16 window_size;       // TCP window
    __u32 first_seen_ts;
    __u32 last_seen_ts;
    __u32 syn_count;         // SYNs from this fingerprint
};

struct fingerprint_key {
    __be32 src_ip;
    __u16  dst_port;
    __u16  pad;
} __attribute__((packed));

/* Layer 0: VIP State Tracking - Per-origin mitigation state */
struct vip_state {
    __u8 flags;              // Bit 0: COOKIE_ON, Bit 1: UNDER_ATTACK, Bit 2: ESCALATED
    __u8 challenge_level;    // 0-4: NORMAL to EMERGENCY (synced with challenge_level_map)
    __u16 reserved;          // Future: IPv6, encryption flags
    __u32 state_changed_ts;  // Last state transition (for hysteresis)
};

/* Layer 0: Quarantine - Per-source penalty for cookie failures */
struct quarantine_key {
    __be32 src_ip;
    __be32 vip_ip;           // Origin IP (enables per-VIP quarantine)
} __attribute__((packed));

struct quarantine_entry {
    __u64 expires_at_ns;     // Absolute expiration (bpf_ktime_get_ns())
    __u8 score;              // Failure count (doubles TTL each repeat)
    __u8 reason;             // 1=cookie_fail, 2=protocol_anomaly, 3=behavioral
    __u8 reserved[6];
};

/* Layer 0: Bypass - Fast path for validated flows */
struct bypass_key {
    __be32 src_ip;
    __u16 src_port;
    __be32 vip_ip;
    __u16 dst_port;
} __attribute__((packed));

struct bypass_entry {
    __u64 expires_at_ns;     // 30-60s TTL
    __u32 validated_ts;      // When cookie validation succeeded
    __u32 reserved;
};

/* Layer 4: Per-source cookie failure tracking */
struct cookie_failure_key {
    __be32 src_ip;
    __be32 vip_ip;
} __attribute__((packed));

struct cookie_failure_entry {
    __u32 failure_count;     // Number of cookie validation failures
    __u32 success_count;     // Number of successful validations
    __u32 first_seen_ts;     // First interaction timestamp
    __u32 last_failure_ts;   // Last failure timestamp
};

/*
 * AWS Billing: WireGuard encapsulation overhead (generous estimate)
 *
 * Actual overhead per packet:
 *   - Outer IP header:      20 bytes
 *   - UDP header:            8 bytes
 *   - WireGuard header:     16 bytes
 *   - Poly1305 auth tag:    16 bytes
 *   - Total actual:         60 bytes
 *
 * We use 80 bytes to ensure we NEVER under-bill (padding, alignment, edge cases).
 * AWS bills at ens5 (outer encapsulated packet), we track at wgO* (inner packet).
 */
#define WIREGUARD_OVERHEAD_BYTES 80

/*
 * AWS Billing: Per-origin egress statistics (PERCPU for scalability)
 *
 * Tracks L3 bytes (iph->tot_len) + WireGuard overhead for accurate AWS billing.
 * Two egress paths from scrubber:
 *   1. to_origin: Client requests → Origin (via WireGuard, before encryption)
 *   2. to_client: Origin responses → Client (after WireGuard decryption)
 *
 * Key: origin_ip (__be32) - join with origins table to get EIP in ecp-agent
 * Map: BPF_MAP_TYPE_PERCPU_HASH - no atomic contention at line rate
 */
struct egress_billing_stats {
    __u64 to_origin_packets;   // Egress path #1: scrubber → origin (wgO* egress)
    __u64 to_origin_bytes;     // L3 bytes + WG overhead - AWS billing metric
    __u64 to_client_packets;   // Egress path #2: scrubber → client (ens5 egress)
    __u64 to_client_bytes;     // L3 bytes + WG overhead - AWS billing metric
};

/*
 * WireGuard Interface to Origin IP mapping for billing attribution.
 *
 * All traffic on a WireGuard interface (to origin IP or WG peer for keepalives)
 * should be billed to the same origin. This map allows lookup by ifindex.
 *
 * Key: wg_ifindex (__u32) - WireGuard interface index (e.g., wgO1's ifindex)
 * Value: origin_ip (__be32) - Origin IP to attribute billing to
 * Populated by: configure-origin.py when origin is created
 * Cleaned by: bpf_map_cleaner.py when origin is deleted
 */

/*
 * QoS Bandwidth Limiting: Per-scrubber capacity configuration
 *
 * Populated at bootstrap from AWS DescribeInstanceTypes API.
 * Updated by miner when origins added/removed (recalculates quotas).
 */
struct scrubber_capacity {
    __u64 bandwidth_bps;     // Total interface bandwidth (from AWS API)
    __u64 usable_bps;        // After buffer deduction (typically 80%)
    __u32 origin_count;      // Active origins on this scrubber
    __u32 buffer_percent;    // Buffer reservation (default: 20)
    __u8  enforce_mode;      // 0 = monitor only (log), 1 = enforce (drop)
    __u8  pad[7];            // Alignment to 8 bytes
};

/*
 * QoS Bandwidth Limiting: Per-origin quota and token bucket state
 *
 * Key: origin_ip (__be32)
 * Token bucket operates on BYTES (not packets) for bandwidth accuracy.
 *
 * Token refill formula:
 *   elapsed_ns = now - last_refill_ns
 *   tokens_to_add = (elapsed_ns * quota_bps) / NS_PER_SEC
 *   tokens = min(tokens + tokens_to_add, burst_bytes)
 */
struct origin_bandwidth {
    __u64 quota_bps;         // Allocated bandwidth (bytes/sec)
    __u64 tokens;            // Current token balance (bytes)
    __u64 burst_bytes;       // Max token capacity (10x quota for 10s burst)
    __u64 last_refill_ns;    // Last refill timestamp (bpf_ktime_get_ns)
    __u64 _reserved;         // Reserved (was bytes_passed, removed - redundant with volume metrics)
    __u64 bytes_exceeded;    // Total bytes over quota (monotonic counter)
    __u64 packets_dropped;   // Packets dropped in enforce mode (monotonic)
    __u64 pad;               // Alignment
};

/* QoS Statistics indices for scrubber-level counters */
enum qos_stats_idx {
    QOS_STAT_BYTES_EXCEEDED = 0,
    QOS_STAT_PACKETS_DROPPED = 1,
    QOS_STAT_ORIGINS_OVER_QUOTA = 2,
    QOS_STAT_MAX = 3,
};

/* ===== Shared Function Implementations ===== */

/* TCP fingerprinting function */
static __always_inline void extract_tcp_fingerprint(struct tcphdr *tcp, void *data_end,
                                                     struct tcp_fingerprint *fp, __u8 ttl)
{
    fp->ttl = ttl;
    fp->window_size = bpf_ntohs(tcp->window);
    fp->mss = 1460;  // Default
    fp->wscale = 0;
    fp->has_sack = 0;
    fp->has_timestamp = 0;

    __u8 *opt_ptr = (__u8 *)(tcp + 1);
    __u32 tcp_header_len = tcp->doff * 4;
    if (tcp_header_len < sizeof(struct tcphdr) || tcp_header_len > 60)
        return;

    __u32 opt_len = tcp_header_len - sizeof(struct tcphdr);

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (opt_ptr >= (__u8 *)data_end || opt_ptr >= (__u8 *)tcp + tcp_header_len)
            break;

        __u8 kind = *opt_ptr;
        if (kind == 0)  // End of options
            break;
        if (kind == 1) {  // NOP
            opt_ptr++;
            continue;
        }

        if (opt_ptr + 1 >= (__u8 *)data_end)
            break;

        __u8 len = *(opt_ptr + 1);
        if (len < 2 || len > 40 || opt_ptr + len > (__u8 *)data_end)
            break;

        if (kind == 2 && len == 4 && opt_ptr + 3 < (__u8 *)data_end) {  // MSS
            fp->mss = (*(opt_ptr + 2) << 8) | *(opt_ptr + 3);
        } else if (kind == 3 && len == 3 && opt_ptr + 2 < (__u8 *)data_end) {  // Window scale
            fp->wscale = *(opt_ptr + 2);
        } else if (kind == 4 && len == 2) {  // SACK permitted
            fp->has_sack = 1;
        } else if (kind == 8 && len == 10) {  // Timestamp
            fp->has_timestamp = 1;
        }

        opt_ptr += len;
    }
}

/* SYN cookie generation (stateless validation) */
static __always_inline __u32 generate_syncookie(__be32 src_ip, __be32 dst_ip,
                                                __be16 src_port, __be16 dst_port, __u32 now_sec)
{
    // Simple hash-based cookie (production could use SipHash)
    __u32 cookie = (__u32)src_ip ^ (__u32)dst_ip ^
                   ((__u32)src_port << 16 | (__u32)dst_port) ^
                   (now_sec & 0xFFFFFFF0);  // 16-second window
    return cookie;
}

/* SYN cookie validation from ACK sequence number */
static __always_inline int validate_syncookie(__u32 ack_seq, __be32 src_ip, __be32 dst_ip,
                                              __be16 src_port, __be16 dst_port, __u32 now_sec)
{
    // Check 5-second time window for clock skew
    #pragma unroll
    for (int i = 0; i < 5; i++) {
        __u32 expected_cookie = generate_syncookie(src_ip, dst_ip, src_port, dst_port, now_sec - i);
        // ACK should be cookie + 1
        if (ack_seq == bpf_htonl(expected_cookie + 1))
            return 1;
    }
    return 0;
}

/* ===== QoS Bandwidth Architecture ===== */
/*
 * CRITICAL: Defense layers FIRST, quota enforcement LAST.
 *
 * INGRESS (client→origin): MONITOR ONLY
 *   - Track bytes, detect bandwidth pressure
 *   - Signal XDP to increase challenge level when under pressure
 *   - NEVER drop ingress traffic here (let XDP defense do its job)
 *
 * EGRESS (origin→client): ENFORCE
 *   - Origin responses are TRUSTED clean traffic
 *   - Safe to enforce quota on egress
 *   - Origin can't "attack" its own quota
 *
 * This architecture ensures:
 *   1. Fine-grained XDP defense filters attack traffic FIRST
 *   2. Only clean traffic consumes origin's bandwidth quota
 *   3. Attackers can't exhaust quota to block legitimate users
 */

#define NS_PER_SEC_SHIFT 30  /* 2^30 ≈ 10^9, avoids 64-bit division */

/* Bandwidth pressure levels for signaling XDP */
enum qos_pressure_level {
    QOS_PRESSURE_NONE = 0,      /* < 50% quota used */
    QOS_PRESSURE_LOW = 1,       /* 50-70% quota used */
    QOS_PRESSURE_MEDIUM = 2,    /* 70-85% quota used */
    QOS_PRESSURE_HIGH = 3,      /* 85-95% quota used */
    QOS_PRESSURE_CRITICAL = 4,  /* > 95% quota used */
};

/*
 * qos_monitor_ingress_inline - INGRESS monitoring (client→origin)
 *
 * Monitors bandwidth usage and signals XDP to increase defense aggressiveness.
 * NEVER drops traffic - that's XDP's job with fine-grained rules.
 *
 * Parameters:
 *   origin_ip: Origin IP (used as map key)
 *   packet_bytes: Packet size in bytes
 *   origin_bw_map: Pointer to origin_bandwidth_map
 *   origin_challenge_map: Pointer to origin_challenge_map (for signaling XDP)
 *   qos_stats: Pointer to qos_stats_map (optional)
 *
 * Returns: Pressure level (0-4) for logging/debugging
 * Side effect: Updates origin_challenge_map to increase XDP defense
 */
static __always_inline int qos_monitor_ingress_inline(
    __be32 origin_ip,
    __u32 packet_bytes,
    void *origin_bw_map,
    void *origin_challenge_map,
    void *qos_stats)
{
    // Get per-origin bandwidth state
    struct origin_bandwidth *bw = bpf_map_lookup_elem(origin_bw_map, &origin_ip);
    if (!bw) {
        // Origin not in quota map = no monitoring needed
        return QOS_PRESSURE_NONE;
    }

    // Refill tokens based on elapsed time
    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed_ns = now - bw->last_refill_ns;
    __u64 tokens_to_add = (elapsed_ns * bw->quota_bps) >> NS_PER_SEC_SHIFT;

    // Refill tokens, capped at burst_bytes
    __u64 new_tokens = bw->tokens + tokens_to_add;
    if (new_tokens > bw->burst_bytes) {
        new_tokens = bw->burst_bytes;
    }
    bw->last_refill_ns = now;

    // Calculate pressure level based on token bucket fill level
    // Low tokens = high pressure (approaching quota)
    __u32 pressure = QOS_PRESSURE_NONE;
    if (bw->burst_bytes > 0) {
        // Calculate what percentage of burst capacity remains
        __u64 fill_pct = (new_tokens * 100) / bw->burst_bytes;

        if (fill_pct < 5) {
            pressure = QOS_PRESSURE_CRITICAL;  // < 5% remaining
        } else if (fill_pct < 15) {
            pressure = QOS_PRESSURE_HIGH;      // 5-15% remaining
        } else if (fill_pct < 30) {
            pressure = QOS_PRESSURE_MEDIUM;    // 15-30% remaining
        } else if (fill_pct < 50) {
            pressure = QOS_PRESSURE_LOW;       // 30-50% remaining
        }
    }

    // Consume tokens and update counters
    if (new_tokens >= packet_bytes) {
        // Within quota - consume tokens
        bw->tokens = new_tokens - packet_bytes;
    } else {
        // Over quota - track exceeded bytes but DON'T DROP
        // (Egress will enforce, we just monitor)
        bw->tokens = 0;
        bw->bytes_exceeded += packet_bytes;

        if (qos_stats) {
            __u32 stat_key = QOS_STAT_BYTES_EXCEEDED;
            __u64 *stat = bpf_map_lookup_elem(qos_stats, &stat_key);
            if (stat) {
                *stat += packet_bytes;
            }
        }

        // Set maximum pressure
        pressure = QOS_PRESSURE_CRITICAL;
    }

    // Signal XDP to increase defense if under pressure
    // Maps pressure level directly to challenge level
    if (origin_challenge_map && pressure > QOS_PRESSURE_NONE) {
        __u32 *current_level = bpf_map_lookup_elem(origin_challenge_map, &origin_ip);
        __u32 current = current_level ? *current_level : 0;

        // Only increase, never decrease (let miner manage de-escalation)
        if (pressure > current) {
            bpf_map_update_elem(origin_challenge_map, &origin_ip, &pressure, BPF_ANY);
        }
    }

    // ALWAYS return - NEVER drop ingress traffic
    // Let XDP defense layers handle attack traffic with fine-grained rules
    return pressure;
}

/*
 * qos_enforce_egress_inline - EGRESS enforcement (origin→client)
 *
 * Enforces bandwidth quota on origin responses.
 * Origin responses are TRUSTED - they've passed through the origin server.
 * Safe to drop here if origin is over-using allocated bandwidth.
 *
 * Parameters:
 *   origin_ip: Origin IP (used as map key)
 *   packet_bytes: Packet size in bytes
 *   cap: Pointer to scrubber_capacity (for enforce_mode check)
 *   origin_bw_map: Pointer to origin_bandwidth_map
 *   qos_stats: Pointer to qos_stats_map (optional)
 *
 * Returns:
 *   1 = packet allowed (within quota or monitor mode)
 *   0 = packet should be dropped (over quota in enforce mode)
 */
static __always_inline int qos_enforce_egress_inline(
    __be32 origin_ip,
    __u32 packet_bytes,
    struct scrubber_capacity *cap,
    void *origin_bw_map,
    void *qos_stats)
{
    if (!cap) {
        // No capacity config = pass through (QoS not configured)
        return 1;
    }

    // Get per-origin bandwidth state
    struct origin_bandwidth *bw = bpf_map_lookup_elem(origin_bw_map, &origin_ip);
    if (!bw) {
        // Origin not in quota map = pass through (unknown origin)
        return 1;
    }

    // Refill tokens based on elapsed time
    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed_ns = now - bw->last_refill_ns;
    __u64 tokens_to_add = (elapsed_ns * bw->quota_bps) >> NS_PER_SEC_SHIFT;

    // Refill tokens, capped at burst_bytes
    __u64 new_tokens = bw->tokens + tokens_to_add;
    if (new_tokens > bw->burst_bytes) {
        new_tokens = bw->burst_bytes;
    }
    bw->last_refill_ns = now;

    // Check if packet fits in token budget
    if (new_tokens >= packet_bytes) {
        // Within quota - consume tokens
        bw->tokens = new_tokens - packet_bytes;
        return 1;  // Allow
    }

    // Over quota
    bw->tokens = new_tokens;
    bw->bytes_exceeded += packet_bytes;

    if (qos_stats) {
        __u32 stat_key = QOS_STAT_BYTES_EXCEEDED;
        __u64 *stat = bpf_map_lookup_elem(qos_stats, &stat_key);
        if (stat) {
            *stat += packet_bytes;
        }
    }

    // Check enforce mode
    if (cap->enforce_mode == 0) {
        // Monitor mode - log but allow
        return 1;
    }

    // Enforce mode - drop packet (safe for egress, origin is over-using)
    bw->packets_dropped++;

    if (qos_stats) {
        __u32 stat_key = QOS_STAT_PACKETS_DROPPED;
        __u64 *stat = bpf_map_lookup_elem(qos_stats, &stat_key);
        if (stat) {
            (*stat)++;
        }
    }

    return 0;  // Drop
}

#endif /* __COMMON_H__ */
