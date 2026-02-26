// bpf/l7_tracer.c
// L7 载荷捕获 eBPF 程序 — v8 完全重写
//
// 核心改进（解决 l7_flow_log 写入为空的根本原因）：
//
//  旧方案 (v7) 的问题：
//    1. fd_to_sock 映射依赖 tcp_connect kprobe 预填充（只有客户端 connect 路径）
//    2. 服务端 accept() 路径（python3 http.server）完全没有填充 fd_to_sock
//    3. loopback 流量（127.0.0.1）在 write/read kprobe 里因找不到 fd→tuple 而跳过
//
//  新方案 (v8)：
//    1. 在 kprobe/tcp_sendmsg、kprobe/tcp_recvmsg 中，直接从 struct sock* 读取五元组
//       - 通过 bpf_probe_read_kernel 读 sock_common 前几个字段（偏移稳定）
//       - skc_daddr(0), skc_rcv_saddr(4), skc_dport(12), skc_num(14)
//    2. 不依赖任何预填充映射，完全 self-contained
//    3. 支持所有路径：connect/accept/loopback/Docker bridge
//
//  事件结构布局（与 Go parseL7Event 精确对齐）：
//  offset  0: timestamp_ns  u64   (8 bytes)
//  offset  8: pid           u32   (4 bytes)
//  offset 12: tid           u32   (4 bytes)
//  offset 16: comm          u8[16] (16 bytes)
//  offset 32: saddr         u32   (4 bytes)
//  offset 36: daddr         u32   (4 bytes)
//  offset 40: sport         u16   (2 bytes)
//  offset 42: dport         u16   (2 bytes)
//  offset 44: protocol      u8    (1 byte)
//  offset 45: direction     u8    (1 byte)
//  offset 46: payload_size  u32   (4 bytes)  [注：u32从46开始，跨越两字节空隙但pack后无gap]
//  offset 50: payload       u8[4096]
//  Total: 50 + 4096 = 4146 bytes

#include "headers/common.h"

#define MAX_PAYLOAD_SIZE 4096

// ── Ring Buffer ───────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} l7_events SEC(".maps");

// ── L7 事件（字段布局与 Go L7Event 精确对齐） ────────────

struct l7_event {
    __u64 timestamp_ns;               // offset  0
    __u32 pid;                        // offset  8
    __u32 tid;                        // offset 12
    __u8  comm[16];                   // offset 16
    __u32 saddr;                      // offset 32
    __u32 daddr;                      // offset 36
    __u16 sport;                      // offset 40
    __u16 dport;                      // offset 42
    __u8  protocol;                   // offset 44
    __u8  direction;                  // offset 45
    __u32 payload_size;               // offset 46 (packed, no gap)
    __u8  payload[MAX_PAYLOAD_SIZE];  // offset 50
} __attribute__((packed));

// ── sendmsg 进入时暂存 sk + iov 参数 ─────────────────────

struct sendmsg_args_t {
    __u64 sk_ptr;
    __u64 buf_ptr;
    __u32 buf_len;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u64); // pid_tgid
    __type(value, struct sendmsg_args_t);
    __uint(max_entries, 8192);
} active_sendmsg SEC(".maps");

// ── recvmsg 进入时暂存 sk + buf 指针 ─────────────────────

struct recvmsg_args_t {
    __u64 sk_ptr;
    __u64 buf_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u64); // pid_tgid
    __type(value, struct recvmsg_args_t);
    __uint(max_entries, 8192);
} active_recvmsg SEC(".maps");

// ── Helper：从 struct sock* 读取四元组 ───────────────────
//
// struct sock_common（所有 socket 开头）内存布局（kernel 4.14~6.8 稳定）：
//   +0x00: __be32 skc_daddr        (远端 IP，网络序)
//   +0x04: __be32 skc_rcv_saddr    (本地 IP，网络序)
//   ...
//   +0x0C: __be16 skc_dport        (远端端口，网络序)
//   +0x0E: __u16  skc_num          (本地端口，主机序)
//
// direction=EGRESS(发送):  本地=src, 远端=dst
// direction=INGRESS(接收): 本地=dst, 远端=src（翻转，使 src 始终是发起方 client）

struct l7_tuple {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

static __always_inline int read_tuple_from_sk(
    void *sk,
    struct l7_tuple *out,
    __u8 direction)
{
    __be32 skc_daddr    = 0;
    __be32 skc_rcv_saddr = 0;
    __be16 skc_dport    = 0;
    __u16  skc_num      = 0;

    if (bpf_probe_read_kernel(&skc_daddr,     4, sk + 0x00) < 0) return -1;
    if (bpf_probe_read_kernel(&skc_rcv_saddr, 4, sk + 0x04) < 0) return -1;
    if (bpf_probe_read_kernel(&skc_dport,     2, sk + 0x0C) < 0) return -1;
    if (bpf_probe_read_kernel(&skc_num,       2, sk + 0x0E) < 0) return -1;

    // 过滤掉全零（未连接的 sock）
    if (skc_daddr == 0 && skc_rcv_saddr == 0)
        return -1;

    // loopback(127.0.0.1) = 0x0100007F（小端），允许通过

    if (direction == FLOW_DIRECTION_EGRESS) {
        // 发送方：本地=src，远端=dst
        out->saddr = bpf_ntohl(skc_rcv_saddr);
        out->daddr = bpf_ntohl(skc_daddr);
        out->sport = skc_num;                      // 本地端口已是主机序
        out->dport = bpf_ntohs(skc_dport);         // 远端端口转主机序
    } else {
        // 接收方：远端=src（client），本地=dst（server）
        out->saddr = bpf_ntohl(skc_daddr);         // 远端 client = src
        out->daddr = bpf_ntohl(skc_rcv_saddr);     // 本地 server = dst
        out->sport = bpf_ntohs(skc_dport);         // 远端端口 = src port
        out->dport = skc_num;                      // 本地端口 = dst port
    }
    return 0;
}

// ── 辅助：从 struct msghdr 读取 iov 缓冲区指针和长度 ─────
//
// struct msghdr (kernel 4.1+) 布局（64-bit）：
//   +0x00: void        *msg_name
//   +0x08: int          msg_namelen
//   +0x0C: (pad 4 bytes on 64-bit)
//   +0x10: struct iov_iter msg_iter
//
// struct iov_iter (kernel 5.14+) 布局：
//   +0x00: u8           iter_type
//   +0x04: bool         copy_mc
//   +0x08: bool         nofault
//   ...（实际 iov 指针位置因版本而异）
//
// 最可靠方案：读 msghdr+0x10+0x08（iov_iter.iov 在 offset 8 of iov_iter）
//
// kernel 5.14 以前 iov_iter::iov 在 iov_iter+0x08
// kernel 5.14 以后 struct iov_iter 布局微调，但 iov ptr 通常还在 +0x08
//
// 为最大兼容性，我们直接读 msg + 0x18（即 msg_iter 起始 + 0x08 offset of iov）

static __always_inline int read_iov_from_msghdr(
    void *msg,
    __u64 *iov_base_out,
    __u32 *iov_len_out)
{
    // msg_iter 在 msghdr + 0x10，iov ptr 在 msg_iter + 0x08
    __u64 iov_ptr = 0;
    if (bpf_probe_read_kernel(&iov_ptr, 8, msg + 0x18) < 0)
        return -1;
    if (!iov_ptr)
        return -1;

    __u64 iov_base = 0;
    __u64 iov_len  = 0;
    if (bpf_probe_read_kernel(&iov_base, 8, (void *)iov_ptr + 0) < 0) return -1;
    if (bpf_probe_read_kernel(&iov_len,  8, (void *)iov_ptr + 8) < 0) return -1;

    if (!iov_base || iov_len == 0)
        return -1;

    *iov_base_out = iov_base;
    *iov_len_out  = (__u32)(iov_len < MAX_PAYLOAD_SIZE ? iov_len : MAX_PAYLOAD_SIZE);
    return 0;
}

// ── kprobe/tcp_sendmsg：记录参数 ──────────────────────────
//
// tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg_l7(struct pt_regs *ctx)
{
    void *sk  = (void *)PT_REGS_PARM1(ctx);
    void *msg = (void *)PT_REGS_PARM2(ctx);

    __u64 iov_base = 0;
    __u32 iov_len  = 0;
    if (read_iov_from_msghdr(msg, &iov_base, &iov_len) < 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_args_t args = {
        .sk_ptr  = (__u64)sk,
        .buf_ptr = iov_base,
        .buf_len = iov_len,
    };
    bpf_map_update_elem(&active_sendmsg, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe__tcp_sendmsg_l7(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_args_t *a = bpf_map_lookup_elem(&active_sendmsg, &pid_tgid);
    if (!a) return 0;

    ssize_t sent = PT_REGS_RC(ctx);
    struct sendmsg_args_t args = *a;
    bpf_map_delete_elem(&active_sendmsg, &pid_tgid);

    if (sent <= 0) return 0;

    struct l7_tuple t = {};
    if (read_tuple_from_sk((void *)args.sk_ptr, &t, FLOW_DIRECTION_EGRESS) < 0)
        return 0;

    struct l7_event *ev = bpf_ringbuf_reserve(&l7_events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    __u64 pg = bpf_get_current_pid_tgid();
    ev->pid  = (__u32)(pg >> 32);
    ev->tid  = (__u32)pg;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    ev->saddr    = t.saddr;
    ev->daddr    = t.daddr;
    ev->sport    = t.sport;
    ev->dport    = t.dport;
    ev->protocol = IPPROTO_TCP;
    ev->direction = FLOW_DIRECTION_EGRESS;

    __u32 copy_len = (__u32)sent;
    if (copy_len > args.buf_len) copy_len = args.buf_len;
    if (copy_len > MAX_PAYLOAD_SIZE) copy_len = MAX_PAYLOAD_SIZE;
    ev->payload_size = copy_len;

    // bpf_probe_read_user 需要 copy_len 为编译期已知或有界值
    bpf_probe_read_user(ev->payload, copy_len & (MAX_PAYLOAD_SIZE - 1),
                        (void *)args.buf_ptr);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── kprobe/tcp_recvmsg：记录参数 ──────────────────────────
//
// tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)

SEC("kprobe/tcp_recvmsg")
int kprobe__tcp_recvmsg_l7(struct pt_regs *ctx)
{
    void *sk  = (void *)PT_REGS_PARM1(ctx);
    void *msg = (void *)PT_REGS_PARM2(ctx);

    __u64 iov_base = 0;
    __u32 iov_len  = 0;
    // recvmsg 进入时 buf 尚未填充，只需记录 buf 地址
    // 先尝试读 iov；若 msg_iter 为空（内核懒初始化），kretprobe 也可再尝试
    read_iov_from_msghdr(msg, &iov_base, &iov_len);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct recvmsg_args_t args = {
        .sk_ptr  = (__u64)sk,
        .buf_ptr = iov_base,
    };
    bpf_map_update_elem(&active_recvmsg, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe__tcp_recvmsg_l7(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct recvmsg_args_t *a = bpf_map_lookup_elem(&active_recvmsg, &pid_tgid);
    if (!a) return 0;

    ssize_t received = PT_REGS_RC(ctx);
    struct recvmsg_args_t args = *a;
    bpf_map_delete_elem(&active_recvmsg, &pid_tgid);

    if (received <= 0) return 0;

    struct l7_tuple t = {};
    if (read_tuple_from_sk((void *)args.sk_ptr, &t, FLOW_DIRECTION_INGRESS) < 0)
        return 0;

    struct l7_event *ev = bpf_ringbuf_reserve(&l7_events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    __u64 pg = bpf_get_current_pid_tgid();
    ev->pid  = (__u32)(pg >> 32);
    ev->tid  = (__u32)pg;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    ev->saddr    = t.saddr;
    ev->daddr    = t.daddr;
    ev->sport    = t.sport;
    ev->dport    = t.dport;
    ev->protocol = IPPROTO_TCP;
    ev->direction = FLOW_DIRECTION_INGRESS;

    __u32 copy_len = (__u32)received;
    if (copy_len > MAX_PAYLOAD_SIZE) copy_len = MAX_PAYLOAD_SIZE;
    ev->payload_size = copy_len;

    if (args.buf_ptr) {
        bpf_probe_read_user(ev->payload, copy_len & (MAX_PAYLOAD_SIZE - 1),
                            (void *)args.buf_ptr);
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
