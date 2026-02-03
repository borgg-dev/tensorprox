#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct snat_entry {
    __be32 new_src_ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);              /* destination IP (origin) */
    __type(value, struct snat_entry); /* replacement source IP    */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} exit_snat_map SEC(".maps");

static __always_inline void rewrite_l4_csum(struct __sk_buff *skb, void *data,
                                            void *data_end, struct iphdr *iph,
                                            __u32 ip_header_len,
                                            __be32 old_src, __be32 new_src)
{
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *th = (void *)iph + ip_header_len;
        if ((void *)(th + 1) > data_end)
            return;
        __u32 tcp_off = (void *)&th->check - data;
        bpf_l4_csum_replace(skb, tcp_off, old_src, new_src,
                            sizeof(__be32) | BPF_F_PSEUDO_HDR);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *uh = (void *)iph + ip_header_len;
        if ((void *)(uh + 1) > data_end)
            return;
        if (uh->check) {
            __u32 udp_off = (void *)&uh->check - data;
            bpf_l4_csum_replace(skb, udp_off, old_src, new_src,
                                sizeof(__be32) | BPF_F_PSEUDO_HDR);
        }
    } else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = (void *)iph + ip_header_len;
        if ((void *)(icmph + 1) > data_end)
            return;
        __u32 icmp_off = (void *)&icmph->checksum - data;
        bpf_l4_csum_replace(skb, icmp_off, old_src, new_src, sizeof(__be32));
    }
}

SEC("tc/egress")
int tc_exit_snat(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __bpf_constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    if (iph->version != 4)
        return TC_ACT_OK;

    if (iph->ihl < 5)
        return TC_ACT_OK;

    __u32 ip_header_len = iph->ihl * 4;
    if ((void *)iph + ip_header_len > data_end)
        return TC_ACT_OK;

    struct snat_entry *entry = bpf_map_lookup_elem(&exit_snat_map, &iph->daddr);
    if (!entry)
        return TC_ACT_OK;

    __be32 old_src = iph->saddr;
    __be32 new_src = entry->new_src_ip;
    if (old_src == new_src)
        return TC_ACT_OK;

    iph->saddr = new_src;

    rewrite_l4_csum(skb, data, data_end, iph, ip_header_len, old_src, new_src);

    __u32 l3_off = (void *)&iph->check - data;
    bpf_l3_csum_replace(skb, l3_off, old_src, new_src, sizeof(__be32));

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
