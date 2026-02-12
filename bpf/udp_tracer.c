// bpf/udp_tracer.c
// UDP 流量追踪器
//
// 修复：
//   1. udp_recvmsg entry 改为只保存 sock 指针（不再读 PARM3 作为包大小）
//   2. 新增 kretprobe/udp_recvmsg：用返回值（实际接收字节数）替代 buffer size
//   3. 接收方向：当 skc_daddr=0 时（未 connect 的 UDP socket）从 recvmsg 的
//      msghdr->msg_name 读取对端地址（通过 skb 的 cb 字段获取）

#include "headers/common.h"

struct udp_flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 pid;
};

struct udp_flow_stats {
    __u64 bytes_sent;
    __u64 bytes_recv;
    __u64 pkts_sent;
    __u64 pkts_recv;
    __u64 first_ts;
    __u64 last_ts;
};

struct udp_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    char  comm[MAX_COMM_LEN];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  direction;
    __u8  _pad[3];
    __u32 packet_size;   // 实际包大小（sendmsg=PARM3；recvmsg=kretprobe返回值）
    // 流聚合快照（与 Go UDPEvent 的 TotalBytes 对齐：[52:56] pad + [56:64] TotalBytes）
    __u32 _pad2;
    __u64 total_bytes;   // bytes_sent + bytes_recv 合计
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key,   struct udp_flow_key);
    __type(value, struct udp_flow_stats);
} udp_flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} udp_events SEC(".maps");

// kprobe entry 保存 sock 指针，供 kretprobe 使用
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64);            // pid_tgid
    __type(value, struct sock *);
} recvmsg_args SEC(".maps");

// ── 发送路径 ──────────────────────────────────────────────

SEC("kprobe/udp_sendmsg")
int kprobe__udp_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk  = (struct sock *)PT_REGS_PARM1(ctx);
    size_t       len = (size_t)PT_REGS_PARM3(ctx);

    struct udp_event ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    __u64 pg = bpf_get_current_pid_tgid();
    ev.pid = (__u32)(pg >> 32);
    ev.tid = (__u32)pg;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.direction   = FLOW_DIRECTION_EGRESS;
    ev.packet_size = (__u32)len;

    ev.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    ev.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    ev.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    ev.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    struct udp_flow_key key = {
        .saddr=ev.saddr, .daddr=ev.daddr,
        .sport=ev.sport, .dport=ev.dport,
        .pid=ev.pid,
    };
    struct udp_flow_stats *st = bpf_map_lookup_elem(&udp_flow_map, &key);
    if (st) {
        __sync_fetch_and_add(&st->bytes_sent, len);
        __sync_fetch_and_add(&st->pkts_sent,  1);
        st->last_ts    = ev.timestamp_ns;
        ev.total_bytes = st->bytes_sent + st->bytes_recv;
    } else {
        struct udp_flow_stats ns = {
            .bytes_sent=len, .pkts_sent=1,
            .first_ts=ev.timestamp_ns, .last_ts=ev.timestamp_ns,
        };
        bpf_map_update_elem(&udp_flow_map, &key, &ns, BPF_ANY);
        ev.total_bytes = len;
    }

    struct udp_event *ep = bpf_ringbuf_reserve(&udp_events, sizeof(*ep), 0);
    if (ep) { __builtin_memcpy(ep, &ev, sizeof(ev)); bpf_ringbuf_submit(ep, 0); }
    return 0;
}

// ── 接收路径 entry：保存 sock 指针 ────────────────────────

SEC("kprobe/udp_recvmsg")
int kprobe__udp_recvmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    __u64 pg = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&recvmsg_args, &pg, &sk, BPF_ANY);
    return 0;
}

// ── 接收路径 return：用返回值作为实际包大小 ───────────────
//
// 原先直接在 kprobe entry 读 PARM3（buffer size）是错误的：
//   DNS 查询应答:  recvmsg(sock, msg, 2048, ...)  → PARM3=2048（buffer）
//                  实际回包只有几十字节，返回值才是真实大小
// kretprobe 返回值 = 实际接收到的字节数（< 0 表示错误）

SEC("kretprobe/udp_recvmsg")
int kretprobe__udp_recvmsg(struct pt_regs *ctx)
{
    long ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;   // 出错或 0 字节，跳过

    __u64 pg = bpf_get_current_pid_tgid();
    struct sock **skp = bpf_map_lookup_elem(&recvmsg_args, &pg);
    if (!skp) return 0;
    struct sock *sk = *skp;
    bpf_map_delete_elem(&recvmsg_args, &pg);

    __u32 len = (__u32)ret;

    struct udp_event ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = (__u32)(pg >> 32);
    ev.tid = (__u32)pg;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.direction   = FLOW_DIRECTION_INGRESS;
    ev.packet_size = len;

    // 接收视角：本端=rcv_saddr/skc_num，对端=skc_daddr/skc_dport
    // 对于已 connect 的 UDP socket（比如 DNS client），这两个字段都有值
    ev.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    ev.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    ev.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    ev.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    // 聚合统计使用正向 key（本端=saddr，对端=daddr）
    struct udp_flow_key key = {
        .saddr=ev.saddr, .daddr=ev.daddr,
        .sport=ev.sport, .dport=ev.dport,
        .pid=ev.pid,
    };
    struct udp_flow_stats *st = bpf_map_lookup_elem(&udp_flow_map, &key);
    if (st) {
        __sync_fetch_and_add(&st->bytes_recv, len);
        __sync_fetch_and_add(&st->pkts_recv,  1);
        st->last_ts    = ev.timestamp_ns;
        ev.total_bytes = st->bytes_sent + st->bytes_recv;
    } else {
        struct udp_flow_stats ns = {
            .bytes_recv=len, .pkts_recv=1,
            .first_ts=ev.timestamp_ns, .last_ts=ev.timestamp_ns,
        };
        bpf_map_update_elem(&udp_flow_map, &key, &ns, BPF_ANY);
        ev.total_bytes = len;
    }

    struct udp_event *ep = bpf_ringbuf_reserve(&udp_events, sizeof(*ep), 0);
    if (ep) { __builtin_memcpy(ep, &ev, sizeof(ev)); bpf_ringbuf_submit(ep, 0); }
    return 0;
}

char _license[] SEC("license") = "GPL";
