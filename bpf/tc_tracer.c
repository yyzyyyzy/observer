// bpf/tc_tracer.c
// Traffic Control Hook 追踪器
// 在网络设备 ingress/egress 处捕获完整 L3/L4 包头信息

#include "headers/common.h"

// TC 数据包事件
struct tc_packet {
    __u64 timestamp_ns;
    __u32 ifindex;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u8  direction;
    __u8  tcp_flags;  // SYN/ACK/FIN/RST/PSH/URG 组合
    __u8  _pad;
    __u32 packet_len;
    __u32 ip_header_len;
    __u8  ip_ttl;
    __u8  ip_tos;
    __u16 ip_id;
};

// Perf buffer 输出
// Ring Buffer 输出
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} tc_events SEC(".maps");

// 每协议计数器（统计 TC 层包数/字节数）
struct tc_stats_key {
    __u8 protocol;   // IPPROTO_TCP / IPPROTO_UDP / ...
    __u8 direction;  // FLOW_DIRECTION_INGRESS / EGRESS
    __u16 _pad;
};

struct tc_stats_val {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key,   struct tc_stats_key);
    __type(value, struct tc_stats_val);
} tc_stats_map SEC(".maps");

// ---------- 辅助：解析 L3/L4 头，填充 tc_packet ----------
static __always_inline int parse_packet(
    struct __sk_buff *skb,
    struct tc_packet *pkt,
    __u8 direction)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // ---------- L2：以太网头 ----------
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;  // 只处理 IPv4

    // ---------- L3：IP 头 ----------
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    pkt->saddr         = iph->saddr;
    pkt->daddr         = iph->daddr;
    pkt->protocol      = iph->protocol;
    pkt->ip_ttl        = iph->ttl;
    pkt->ip_tos        = iph->tos;
    pkt->ip_id         = bpf_ntohs(iph->id);
    pkt->ip_header_len = iph->ihl * 4;
    pkt->packet_len    = skb->len;
    pkt->direction     = direction;
    pkt->ifindex       = skb->ifindex;
    pkt->timestamp_ns  = bpf_ktime_get_ns();

    __u32 l4_off = sizeof(*eth) + pkt->ip_header_len;

    // ---------- L4：TCP / UDP ----------
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *th = (struct tcphdr *)((void *)eth + l4_off);
        if ((void *)(th + 1) > data_end)
            return -1;

        pkt->sport = bpf_ntohs(th->source);
        pkt->dport = bpf_ntohs(th->dest);

        // 拼装 TCP flags 字节：URG|ACK|PSH|RST|SYN|FIN
        __u8 flags = 0;
        if (th->fin) flags |= 0x01;
        if (th->syn) flags |= 0x02;
        if (th->rst) flags |= 0x04;
        if (th->psh) flags |= 0x08;
        if (th->ack) flags |= 0x10;
        if (th->urg) flags |= 0x20;
        pkt->tcp_flags = flags;

    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *uh = (struct udphdr *)((void *)eth + l4_off);
        if ((void *)(uh + 1) > data_end)
            return -1;

        pkt->sport = bpf_ntohs(uh->source);
        pkt->dport = bpf_ntohs(uh->dest);
        pkt->tcp_flags = 0;
    }
    // 其他协议只记录 L3 信息，sport/dport 为 0

    return 0;
}

// ---------- 辅助：更新协议统计 ----------
static __always_inline void update_tc_stats(
    __u8 protocol, __u8 direction, __u32 bytes)
{
    struct tc_stats_key k = { .protocol = protocol, .direction = direction };
    struct tc_stats_val *v = bpf_map_lookup_elem(&tc_stats_map, &k);
    if (v) {
        __sync_fetch_and_add(&v->packets, 1);
        __sync_fetch_and_add(&v->bytes,   bytes);
    } else {
        struct tc_stats_val nv = { .packets = 1, .bytes = bytes };
        bpf_map_update_elem(&tc_stats_map, &k, &nv, BPF_ANY);
    }
}

// ---------- TC Ingress Hook ----------
SEC("classifier/tc_ingress")
int tc_ingress(struct __sk_buff *skb)
{
    struct tc_packet pkt = {};
    if (parse_packet(skb, &pkt, FLOW_DIRECTION_INGRESS) < 0)
        return 0; // TC_ACT_OK — 不丢包，只采集

    update_tc_stats(pkt.protocol, FLOW_DIRECTION_INGRESS, pkt.packet_len);

    struct tc_packet *ep = bpf_ringbuf_reserve(&tc_events, sizeof(*ep), 0);
    if (ep) { __builtin_memcpy(ep, &pkt, sizeof(pkt)); bpf_ringbuf_submit(ep, 0); }
    return 0;
}

// ---------- TC Egress Hook ----------
SEC("classifier/tc_egress")
int tc_egress(struct __sk_buff *skb)
{
    struct tc_packet pkt = {};
    if (parse_packet(skb, &pkt, FLOW_DIRECTION_EGRESS) < 0)
        return 0;

    update_tc_stats(pkt.protocol, FLOW_DIRECTION_EGRESS, pkt.packet_len);

    struct tc_packet *ep = bpf_ringbuf_reserve(&tc_events, sizeof(*ep), 0);
    if (ep) { __builtin_memcpy(ep, &pkt, sizeof(pkt)); bpf_ringbuf_submit(ep, 0); }
    return 0;
}

char _license[] SEC("license") = "GPL";
