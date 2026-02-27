// bpf/tc_tracer.c — Traffic Control Hook 追踪器
//
// 设计目标（对标 DeepFlow）：
//   1. 所有包的统计数据通过 BPF map 聚合（不走 ringbuf），零 overhead。
//   2. ringbuf 只上报采样包（默认 1/100），供调试/抓包分析用。
//   3. 采样计数器用 per-CPU array 避免原子竞争。
//
// 这样即使每秒百万包，ringbuf 仅上报 ~1 万包，Go 侧无日志洪泛。

#include "headers/common.h"

// ── TC 包事件（ringbuf 采样用）───────────────────────────

struct tc_packet {
    __u64 timestamp_ns;
    __u32 ifindex;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u8  direction;
    __u8  tcp_flags;
    __u8  ip_version;   // 4 或 6
    __u32 packet_len;
    __u32 ip_header_len;
    __u8  ip_ttl;
    __u8  ip_tos;
    __u16 ip_id;
    __u8  saddr6[16];   // IPv6 src（IPv4 时为 0）
    __u8  daddr6[16];   // IPv6 dst（IPv4 时为 0）
};

// ── 采样 ringbuf：仅转发 1/TC_SAMPLE_RATE 的包 ──────────
// 调大此值减少 ringbuf 压力；调小则采样更密集（用于调试）。
#define TC_SAMPLE_RATE 100

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} tc_events SEC(".maps");

// ── 协议/方向聚合统计（所有包，不采样）──────────────────

struct tc_stats_key {
    __u8  protocol;
    __u8  direction;
    __u8  ip_version;
    __u8  _pad;
};

struct tc_stats_val {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key,   struct tc_stats_key);
    __type(value, struct tc_stats_val);
} tc_stats_map SEC(".maps");

// ── 采样计数器（per-CPU array，避免 atomic 竞争）────────

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u64);
} tc_sample_cnt SEC(".maps");

// ── 解析 L4（TCP/UDP）头 ──────────────────────────────────

static __always_inline void parse_l4(
    void *data_end,
    void *l4_hdr,
    __u8  protocol,
    struct tc_packet *pkt)
{
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *th = l4_hdr;
        if ((void *)(th + 1) > data_end) return;
        pkt->sport = bpf_ntohs(th->source);
        pkt->dport = bpf_ntohs(th->dest);
        __u8 flags = 0;
        if (th->fin) flags |= 0x01;
        if (th->syn) flags |= 0x02;
        if (th->rst) flags |= 0x04;
        if (th->psh) flags |= 0x08;
        if (th->ack) flags |= 0x10;
        if (th->urg) flags |= 0x20;
        pkt->tcp_flags = flags;
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *uh = l4_hdr;
        if ((void *)(uh + 1) > data_end) return;
        pkt->sport     = bpf_ntohs(uh->source);
        pkt->dport     = bpf_ntohs(uh->dest);
        pkt->tcp_flags = 0;
    }
}

// ── 解析入口 ──────────────────────────────────────────────

static __always_inline int parse_packet(
    struct __sk_buff *skb,
    struct tc_packet *pkt,
    __u8 direction)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return -1;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    void *l3_hdr  = (void *)(eth + 1);

    // 解除 VLAN 封装（802.1Q）
    if (h_proto == ETH_P_8021Q) {
        struct vlan_hdr {
            __be16 h_vlan_TCI;
            __be16 h_vlan_encapsulated_proto;
        };
        struct vlan_hdr *vh = l3_hdr;
        if ((void *)(vh + 1) > data_end) return -1;
        h_proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
        l3_hdr  = (void *)(vh + 1);
    }

    pkt->timestamp_ns = bpf_ktime_get_ns();
    pkt->packet_len   = skb->len;
    pkt->direction    = direction;
    pkt->ifindex      = skb->ifindex;

    if (h_proto == ETH_P_IP) {
        struct iphdr *iph = l3_hdr;
        if ((void *)(iph + 1) > data_end) return -1;
        pkt->ip_version    = 4;
        pkt->saddr         = iph->saddr;
        pkt->daddr         = iph->daddr;
        pkt->protocol      = iph->protocol;
        pkt->ip_ttl        = iph->ttl;
        pkt->ip_tos        = iph->tos;
        pkt->ip_id         = bpf_ntohs(iph->id);
        pkt->ip_header_len = iph->ihl * 4;
        void *l4_hdr = l3_hdr + pkt->ip_header_len;
        parse_l4(data_end, l4_hdr, iph->protocol, pkt);
    } else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = l3_hdr;
        if ((void *)(ip6h + 1) > data_end) return -1;
        pkt->ip_version    = 6;
        pkt->protocol      = ip6h->nexthdr;
        pkt->ip_ttl        = ip6h->hop_limit;
        pkt->ip_header_len = sizeof(struct ipv6hdr);
        __builtin_memcpy(pkt->saddr6, &ip6h->saddr, 16);
        __builtin_memcpy(pkt->daddr6, &ip6h->daddr, 16);
        void *l4_hdr = (void *)(ip6h + 1);
        parse_l4(data_end, l4_hdr, ip6h->nexthdr, pkt);
    } else {
        return -1;
    }
    return 0;
}

// ── 更新聚合统计（每包，不采样）──────────────────────────

static __always_inline void update_stats(
    __u8 protocol, __u8 direction, __u8 ip_version, __u32 bytes)
{
    struct tc_stats_key k = {
        .protocol   = protocol,
        .direction  = direction,
        .ip_version = ip_version,
    };
    struct tc_stats_val *v = bpf_map_lookup_elem(&tc_stats_map, &k);
    if (v) {
        __sync_fetch_and_add(&v->packets, 1);
        __sync_fetch_and_add(&v->bytes,   bytes);
    } else {
        struct tc_stats_val nv = { .packets = 1, .bytes = bytes };
        bpf_map_update_elem(&tc_stats_map, &k, &nv, BPF_ANY);
    }
}

// ── 采样判断：每 TC_SAMPLE_RATE 包送一个到 ringbuf ───────
// 使用 per-CPU 计数器，无锁，无 atomic 开销。

static __always_inline int should_sample(void)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&tc_sample_cnt, &key);
    if (!cnt) return 0;
    *cnt += 1;
    return (*cnt % TC_SAMPLE_RATE) == 0;
}

// ── tc_ingress ────────────────────────────────────────────

SEC("classifier/tc_ingress")
int tc_ingress(struct __sk_buff *skb)
{
    struct tc_packet pkt = {};
    if (parse_packet(skb, &pkt, FLOW_DIRECTION_INGRESS) < 0)
        return 0;

    // 聚合统计：每包都更新，无采样损失
    update_stats(pkt.protocol, FLOW_DIRECTION_INGRESS, pkt.ip_version, pkt.packet_len);

    // 采样上报：仅 1/TC_SAMPLE_RATE 的包进 ringbuf
    if (should_sample()) {
        struct tc_packet *ep = bpf_ringbuf_reserve(&tc_events, sizeof(*ep), 0);
        if (ep) {
            __builtin_memcpy(ep, &pkt, sizeof(pkt));
            bpf_ringbuf_submit(ep, 0);
        }
    }
    return 0;
}

// ── tc_egress ─────────────────────────────────────────────

SEC("classifier/tc_egress")
int tc_egress(struct __sk_buff *skb)
{
    struct tc_packet pkt = {};
    if (parse_packet(skb, &pkt, FLOW_DIRECTION_EGRESS) < 0)
        return 0;

    update_stats(pkt.protocol, FLOW_DIRECTION_EGRESS, pkt.ip_version, pkt.packet_len);

    if (should_sample()) {
        struct tc_packet *ep = bpf_ringbuf_reserve(&tc_events, sizeof(*ep), 0);
        if (ep) {
            __builtin_memcpy(ep, &pkt, sizeof(pkt));
            bpf_ringbuf_submit(ep, 0);
        }
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
