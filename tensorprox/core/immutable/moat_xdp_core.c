/* 
 * moat_xdp_core.c - XDP-based DDoS protection for TensorProx
 * 
 * This XDP program provides L3/L4 DDoS protection with efficient packet
 * sampling, verdict caching, and direct packet redirection for high-performance
 * traffic processing at the Moat node.
 */

 #include <linux/bpf.h>
 #include <linux/if_ether.h>
 #include <linux/ip.h>
 #include <linux/tcp.h>
 #include <linux/udp.h>
 #include <linux/in.h>
 #include <bpf/bpf_helpers.h>
 #include <bpf/bpf_endian.h>
 
 /* Flow key structure for tracking individual flows */
 struct flow_key {
     __u32 src_ip;
     __u32 dst_ip;
     __u16 src_port;
     __u16 dst_port;
     __u8 protocol;
 };
 
 /* Flow verdict for each tracked flow */
 struct flow_verdict {
     __u8 action;         /* 0=unspecified, 1=allow, 2=block, 3=rate_limit */
     __u8 priority;       /* Priority level 0-255 (higher value = higher priority) */
     __u32 timestamp;     /* Last update timestamp */
     __u32 packet_count;  /* Packet counter for this flow */
     __u32 byte_count;    /* Byte counter for this flow */
     __u32 rate_limit;    /* Rate limit value if action=3 */
 };
 
 /* Sampling configuration */
 struct sampling_config {
     __u32 base_rate;     /* 1 in X packets will be sampled (e.g., 100 = 1%) */
     __u32 syn_rate;      /* Sampling rate for TCP SYN packets */
     __u32 udp_rate;      /* Sampling rate for UDP packets */
     __u32 icmp_rate;     /* Sampling rate for ICMP packets */
     __u32 min_size;      /* Minimum packet size to apply special sampling */
     __u32 max_size;      /* Maximum packet size to apply special sampling */
     __u32 size_rate;     /* Sampling rate for packets of suspicious size */
 };
 
 /* Interface mapping structure */
 struct iface_map {
     __u32 ingress_ifindex;  /* Ingress interface index */
     __u32 egress_ifindex;   /* Egress interface index */
     __u8 enabled;           /* Whether this mapping is enabled */
 };
 
 /* Metrics structure */
 struct metrics {
     __u64 total_packets;    /* Total packets seen */
     __u64 allowed_packets;  /* Packets allowed through */
     __u64 blocked_packets;  /* Packets blocked */
     __u64 sampled_packets;  /* Packets sampled to userspace */
     __u64 syn_packets;      /* TCP SYN packets */
     __u64 udp_packets;      /* UDP packets */
     __u64 icmp_packets;     /* ICMP packets */
     __u64 other_packets;    /* Other protocol packets */
 };
 
 /* Verdict action constants */
 #define VERDICT_UNKNOWN 0
 #define VERDICT_ALLOW 1
 #define VERDICT_BLOCK 2
 #define VERDICT_RATE_LIMIT 3
 
 /* Default sampling rates */
 #define DEFAULT_SAMPLE_RATE 100      /* 1% sampling by default */
 #define DEFAULT_SYN_RATE 10          /* 10% for SYN packets */
 #define DEFAULT_UDP_RATE 50          /* 2% for UDP packets */
 #define DEFAULT_SUSPICIOUS_SIZE 20   /* 5% for suspicious sized packets */
 
 /* eBPF Maps */
 
 /* Flow verdict map - tracks verdict for each flow */
 struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(key_size, sizeof(struct flow_key));
     __uint(value_size, sizeof(struct flow_verdict));
     __uint(max_entries, 1000000);
 } flow_verdict_map SEC(".maps");
 
 /* Interface map - maps ingress interfaces to egress */
 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(key_size, sizeof(__u32));
     __uint(value_size, sizeof(struct iface_map));
     __uint(max_entries, 64);
 } iface_map SEC(".maps");
 
 /* Sampling configuration map */
 struct {
     __uint(type, BPF_MAP_TYPE_ARRAY);
     __uint(key_size, sizeof(__u32));
     __uint(value_size, sizeof(struct sampling_config));
     __uint(max_entries, 1);
 } sampling_config_map SEC(".maps");
 
 /* DevMap for XDP_REDIRECT */
 struct {
     __uint(type, BPF_MAP_TYPE_DEVMAP);
     __uint(key_size, sizeof(__u32));
     __uint(value_size, sizeof(__u32));
     __uint(max_entries, 64);
 } tx_port SEC(".maps");
 
 /* XSK map for AF_XDP sockets */
 struct {
     __uint(type, BPF_MAP_TYPE_XSKMAP);
     __uint(key_size, sizeof(__u32));
     __uint(value_size, sizeof(__u32));
     __uint(max_entries, 64);
 } xsks_map SEC(".maps");
 
 /* Performance metrics */
 struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __uint(key_size, sizeof(__u32));
     __uint(value_size, sizeof(struct metrics));
     __uint(max_entries, 1);
 } metrics_map SEC(".maps");
 
 /* Helper to count packet based on protocol */
 static __always_inline void count_packet_by_proto(__u8 protocol) {
     __u32 key = 0;
     struct metrics *metrics = bpf_map_lookup_elem(&metrics_map, &key);
     if (!metrics)
         return;
     
     metrics->total_packets++;
     
     if (protocol == IPPROTO_TCP)
         metrics->syn_packets++;
     else if (protocol == IPPROTO_UDP)
         metrics->udp_packets++;
     else if (protocol == IPPROTO_ICMP)
         metrics->icmp_packets++;
     else
         metrics->other_packets++;
 }
 
 /* Helper to update metrics for packet verdicts */
 static __always_inline void count_verdict(__u8 verdict) {
     __u32 key = 0;
     struct metrics *metrics = bpf_map_lookup_elem(&metrics_map, &key);
     if (!metrics)
         return;
     
     if (verdict == VERDICT_ALLOW)
         metrics->allowed_packets++;
     else if (verdict == VERDICT_BLOCK)
         metrics->blocked_packets++;
     else if (verdict == VERDICT_RATE_LIMIT) {
         /* Rate limited packets count as blocked */
         metrics->blocked_packets++;
     }
 }
 
 /* Helper to mark packet as sampled */
 static __always_inline void count_sampled_packet() {
     __u32 key = 0;
     struct metrics *metrics = bpf_map_lookup_elem(&metrics_map, &key);
     if (!metrics)
         return;
     
     metrics->sampled_packets++;
 }
 
 /* Get pseudo-random value between 0 and max-1 */
 static __always_inline __u32 bpf_random(__u32 max) {
     return bpf_get_prandom_u32() % max;
 }
 
 /* Parse packet and extract flow key */
 static __always_inline int parse_packet(struct xdp_md *ctx, struct flow_key *flow, 
                                         __u16 *tcp_flags, __u16 *pkt_size) {
     void *data_end = (void *)(long)ctx->data_end;
     void *data = (void *)(long)ctx->data;
     struct ethhdr *eth = data;
     
     /* Verify Ethernet header */
     if (eth + 1 > data_end)
         return -1;
     
     /* Only handle IPv4 packets */
     if (eth->h_proto != bpf_htons(ETH_P_IP))
         return -1;
     
     struct iphdr *iph = (struct iphdr *)(eth + 1);
     if (iph + 1 > data_end)
         return -1;
     
     /* Save packet size for possible sampling based on size */
     *pkt_size = bpf_ntohs(iph->tot_len);
     
     /* Initialize flow key */
     flow->src_ip = iph->saddr;
     flow->dst_ip = iph->daddr;
     flow->protocol = iph->protocol;
     
     /* Extract ports for TCP/UDP */
     if (iph->protocol == IPPROTO_TCP) {
         struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
         if (tcph + 1 > data_end)
             return -1;
         
         flow->src_port = bpf_ntohs(tcph->source);
         flow->dst_port = bpf_ntohs(tcph->dest);
         *tcp_flags = tcph->fin | (tcph->syn << 1) | (tcph->rst << 2) | 
                      (tcph->psh << 3) | (tcph->ack << 4) | (tcph->urg << 5);
     } else if (iph->protocol == IPPROTO_UDP) {
         struct udphdr *udph = (struct udphdr *)(iph + 1);
         if (udph + 1 > data_end)
             return -1;
         
         flow->src_port = bpf_ntohs(udph->source);
         flow->dst_port = bpf_ntohs(udph->dest);
         *tcp_flags = 0;
     } else {
         /* For non-TCP/UDP protocols, use 0 for ports */
         flow->src_port = 0;
         flow->dst_port = 0;
         *tcp_flags = 0;
     }
     
     return 0;
 }
 
 /* Check if packet should be sampled based on characteristics */
 static __always_inline int should_sample(struct flow_key *flow, __u16 tcp_flags, 
                                          __u16 pkt_size, struct sampling_config *config) {
     /* Base random sampling - always check */
     if (bpf_random(config->base_rate) == 0)
         return 1;
     
     /* TCP SYN packet sampling (potential SYN flood detection) */
     if (flow->protocol == IPPROTO_TCP && (tcp_flags & 0x02) && 
         bpf_random(config->syn_rate) == 0)
         return 1;
     
     /* UDP packet sampling (potential UDP flood / amplification attack detection) */
     if (flow->protocol == IPPROTO_UDP && bpf_random(config->udp_rate) == 0)
         return 1;
     
     /* ICMP packet sampling */
     if (flow->protocol == IPPROTO_ICMP && bpf_random(config->icmp_rate) == 0)
         return 1;
     
     /* Suspicious packet size sampling (potential amplification attacks) */
     if (pkt_size > config->min_size && pkt_size < config->max_size && 
         bpf_random(config->size_rate) == 0)
         return 1;
     
     return 0;
 }
 
 /* Main XDP program */
 SEC("xdp")
 int xdp_firewall_func(struct xdp_md *ctx) {
     /* Extract packet metadata */
     __u32 ingress_ifindex = ctx->ingress_ifindex;
     __u16 tcp_flags = 0;
     __u16 pkt_size = 0;
     
     /* Extract flow information */
     struct flow_key flow = {};
     if (parse_packet(ctx, &flow, &tcp_flags, &pkt_size) < 0) {
         /* Parsing failed, pass to kernel */
         return XDP_PASS;
     }
     
     /* Update metrics based on protocol */
     count_packet_by_proto(flow.protocol);
     
     /* Check if we have a verdict for this flow */
     struct flow_verdict *verdict = bpf_map_lookup_elem(&flow_verdict_map, &flow);
     if (verdict) {
         /* We have seen this flow before */
         if (verdict->action == VERDICT_BLOCK) {
             /* Drop this packet */
             count_verdict(VERDICT_BLOCK);
             return XDP_DROP;
         } else if (verdict->action == VERDICT_RATE_LIMIT) {
             /* Implement token bucket rate limiting */
             /* For simplicity, using packet count modulo as basic rate limiting */
             verdict->packet_count++;
             if (verdict->packet_count % verdict->rate_limit != 0) {
                 count_verdict(VERDICT_RATE_LIMIT);
                 return XDP_DROP;
             }
         }
         
         /* Update flow statistics */
         verdict->packet_count++;
         verdict->byte_count += pkt_size;
     }
     
     /* Get the sampling configuration */
     __u32 key = 0;
     struct sampling_config *config = bpf_map_lookup_elem(&sampling_config_map, &key);
     if (!config) {
         /* No config, use safe defaults */
         struct sampling_config default_config = {
             .base_rate = DEFAULT_SAMPLE_RATE,
             .syn_rate = DEFAULT_SYN_RATE,
             .udp_rate = DEFAULT_UDP_RATE,
             .icmp_rate = DEFAULT_UDP_RATE,
             .min_size = 64,
             .max_size = 1500,
             .size_rate = DEFAULT_SUSPICIOUS_SIZE
         };
         config = &default_config;
     }
     
     /* Check if this packet should be sampled for analysis */
     if (should_sample(&flow, tcp_flags, pkt_size, config)) {
         /* Mark packet as sampled in metrics */
         count_sampled_packet();
         
         /* Check if we have an AF_XDP socket on this queue */
         __u32 queue_index = ctx->rx_queue_index;
         if (bpf_map_lookup_elem(&xsks_map, &queue_index)) {
             /* Redirect to AF_XDP socket for analysis */
             return bpf_redirect_map(&xsks_map, queue_index, 0);
         }
     }
     
     /* Look up the interface mapping */
     struct iface_map *iface = bpf_map_lookup_elem(&iface_map, &ingress_ifindex);
     if (iface && iface->enabled) {
         /* Redirect to the configured egress interface */
         count_verdict(VERDICT_ALLOW);
         return bpf_redirect_map(&tx_port, iface->egress_ifindex, 0);
     }
     
     /* Default to allow */
     count_verdict(VERDICT_ALLOW);
     return XDP_PASS;
 }
 
 char _license[] SEC("license") = "GPL";