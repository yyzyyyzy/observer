// bpf/l7_tracer.c — L7 载荷捕获（kprobe on tcp_sendmsg/tcp_recvmsg）
//
// 改动要点：
//   - 使用 BPF_CORE_READ / BPF_CORE_READ_INTO 替换所有手写偏移，
//     依赖 BTF 在运行时做字段重定位，兼容内核版本差异。
//   - iov_iter 结构在 6.x 内核变化显著，使用 CO-RE 安全读取。

#include "headers/common.h"

#define MAX_PAYLOAD_SIZE 4096

// ── Ring Buffer ───────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} l7_events SEC(".maps");

// ── 端口黑名单（BPF 层过滤，对齐 DeepFlow skip_port_set）────
//
// 用 BPF_MAP_TYPE_HASH 实现 O(1) 端口过滤：
//   key   = __u32（端口号，主机字节序）
//   value = __u8（1=skip，占位不重要，仅检查 key 是否存在）
//
// Go 侧在 loadL7Programs() 之后通过 coll.Maps["l7_skip_ports"]
// 批量写入需要跳过的端口（自身服务端口、加密协议端口等）。
// 最多支持 256 条（覆盖绝大多数场景）。
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u32);
    __type(value, __u8);
    __uint(max_entries, 256);
} l7_skip_ports SEC(".maps");

// ── L7 事件结构（与 Go L7Event 对齐）────────────────────

struct l7_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u8  comm[16];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u8  direction;
    __u32 payload_size;
    __u8  payload[MAX_PAYLOAD_SIZE];
} __attribute__((packed));

// ── sendmsg/recvmsg 入参暂存 ──────────────────────────────

struct send_args_t {
    __u64 sk_ptr;
    __u64 buf_ptr;
    __u32 buf_len;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u64);
    __type(value, struct send_args_t);
    __uint(max_entries, 8192);
} l7_active_sendmsg SEC(".maps");

struct recv_args_t {
    __u64 sk_ptr;
    __u64 buf_ptr;
    __u32 buf_len;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u64);
    __type(value, struct recv_args_t);
    __uint(max_entries, 8192);
} l7_active_recvmsg SEC(".maps");

// ── 四元组结构 ────────────────────────────────────────────

struct l7_tuple {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

// ── Helper：CO-RE 读取 sock 四元组 ───────────────────────
//
// 使用 BPF_CORE_READ 通过 BTF 进行字段重定位，无需硬编码偏移。

static __always_inline int read_tuple_from_sk(
    struct sock *sk,
    struct l7_tuple *out,
    __u8 direction)
{
    __be32 skc_daddr     = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __be32 skc_rcv_saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __be16 skc_dport     = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __u16  skc_num       = BPF_CORE_READ(sk, __sk_common.skc_num);

    if (skc_daddr == 0 && skc_rcv_saddr == 0)
        return -1;

    if (direction == FLOW_DIRECTION_EGRESS) {
        out->saddr = bpf_ntohl(skc_rcv_saddr);
        out->daddr = bpf_ntohl(skc_daddr);
        out->sport = skc_num;
        out->dport = bpf_ntohs(skc_dport);
    } else {
        out->saddr = bpf_ntohl(skc_daddr);
        out->daddr = bpf_ntohl(skc_rcv_saddr);
        out->sport = bpf_ntohs(skc_dport);
        out->dport = skc_num;
    }
    return 0;
}

// ── Helper：CO-RE 从 msghdr 读取 iov buffer 指针和长度 ──
//
// kernel 6.x 引入了 ITER_UBUF（iter_type=0）作为单 buffer 快速路径。
// ITER_UBUF：直接使用 iov_iter.ubuf + count，无需解引用 iovec 指针。
// ITER_IOVEC（iter_type=1）：传统多段 iovec，需通过 __iov 指针访问。
// 通过读取 iter_type 字段来选择正确的读取路径。

#define ITER_UBUF  0
#define ITER_IOVEC 1

static __always_inline int read_iov_from_msghdr(
    struct msghdr *msg,
    __u64 *iov_base_out,
    __u32 *iov_len_out)
{
    __u8 iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);

    if (iter_type == ITER_UBUF) {
        // 快速路径：直接读 ubuf 和 count
        void *ubuf = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
        size_t count = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_len);
        if (!ubuf || count == 0)
            return -1;
        __u32 len = (__u32)count;
        if (len > MAX_PAYLOAD_SIZE)
            len = MAX_PAYLOAD_SIZE;
        *iov_base_out = (__u64)ubuf;
        *iov_len_out  = len;
        return 0;
    }

    // ITER_IOVEC 及其他：通过 __iov 指针读取第一个 iovec 元素
    const struct iovec *iov_ptr = BPF_CORE_READ(msg, msg_iter.__iov);
    if (!iov_ptr)
        return -1;

    __u64 iov_base = 0;
    __u64 iov_len  = 0;
    BPF_CORE_READ_INTO(&iov_base, iov_ptr, iov_base);
    BPF_CORE_READ_INTO(&iov_len,  iov_ptr, iov_len);

    if (!iov_base || iov_len == 0)
        return -1;

    __u32 len = (__u32)iov_len;
    if (len > MAX_PAYLOAD_SIZE)
        len = MAX_PAYLOAD_SIZE;

    *iov_base_out = iov_base;
    *iov_len_out  = len;
    return 0;
}

// ── Helper：端口黑名单查表 ────────────────────────────────
//
// 检查 sport 或 dport 是否在 l7_skip_ports 中。
// 返回 1 = 应跳过（不采集），0 = 正常采集。
//
// DeepFlow 同样在 BPF submit 前做端口过滤，避免无效数据进入 ring buffer。
static __always_inline int should_skip_port(__u16 sport, __u16 dport)
{
    __u32 sp = sport, dp = dport;
    if (bpf_map_lookup_elem(&l7_skip_ports, &sp))
        return 1;
    if (bpf_map_lookup_elem(&l7_skip_ports, &dp))
        return 1;
    return 0;
}

// ── Helper：填充事件头 ────────────────────────────────────

static __always_inline void fill_event_header(
    struct l7_event *ev,
    struct l7_tuple *t,
    __u8 direction)
{
    ev->timestamp_ns = bpf_ktime_get_ns();
    __u64 pg = bpf_get_current_pid_tgid();
    ev->pid  = (__u32)(pg >> 32);
    ev->tid  = (__u32)pg;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    ev->saddr     = t->saddr;
    ev->daddr     = t->daddr;
    ev->sport     = t->sport;
    ev->dport     = t->dport;
    ev->protocol  = IPPROTO_TCP;
    ev->direction = direction;
}

// ── kprobe/tcp_sendmsg ────────────────────────────────────

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg_l7(struct pt_regs *ctx)
{
    struct sock   *sk  = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    __u64 iov_base = 0;
    __u32 iov_len  = 0;
    if (read_iov_from_msghdr(msg, &iov_base, &iov_len) < 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct send_args_t args = {
        .sk_ptr  = (__u64)(long)sk,
        .buf_ptr = iov_base,
        .buf_len = iov_len,
    };
    bpf_map_update_elem(&l7_active_sendmsg, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe__tcp_sendmsg_l7(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct send_args_t *a = bpf_map_lookup_elem(&l7_active_sendmsg, &pid_tgid);
    if (!a) return 0;

    ssize_t sent = PT_REGS_RC(ctx);
    struct send_args_t args = *a;
    bpf_map_delete_elem(&l7_active_sendmsg, &pid_tgid);

    if (sent <= 0) return 0;

    struct l7_tuple t = {};
    if (read_tuple_from_sk((struct sock *)args.sk_ptr, &t, FLOW_DIRECTION_EGRESS) < 0)
        return 0;

    // BPF 层端口过滤：跳过黑名单端口，不写入 ring buffer
    if (should_skip_port(t.sport, t.dport))
        return 0;

    struct l7_event *ev = bpf_ringbuf_reserve(&l7_events, sizeof(*ev), 0);
    if (!ev) return 0;

    fill_event_header(ev, &t, FLOW_DIRECTION_EGRESS);

    __u32 valid = (__u32)sent;
    if (valid > args.buf_len) valid = args.buf_len;
    if (valid > MAX_PAYLOAD_SIZE) valid = MAX_PAYLOAD_SIZE;
    ev->payload_size = valid;

    bpf_probe_read_user(ev->payload, MAX_PAYLOAD_SIZE, (void *)args.buf_ptr);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── kprobe/tcp_recvmsg ────────────────────────────────────

SEC("kprobe/tcp_recvmsg")
int kprobe__tcp_recvmsg_l7(struct pt_regs *ctx)
{
    struct sock   *sk  = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    __u64 iov_base = 0;
    __u32 iov_len  = 0;
    read_iov_from_msghdr(msg, &iov_base, &iov_len);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct recv_args_t args = {
        .sk_ptr  = (__u64)(long)sk,
        .buf_ptr = iov_base,
        .buf_len = iov_len,
    };
    bpf_map_update_elem(&l7_active_recvmsg, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe__tcp_recvmsg_l7(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct recv_args_t *a = bpf_map_lookup_elem(&l7_active_recvmsg, &pid_tgid);
    if (!a) return 0;

    ssize_t received = PT_REGS_RC(ctx);
    struct recv_args_t args = *a;
    bpf_map_delete_elem(&l7_active_recvmsg, &pid_tgid);

    if (received <= 0) return 0;

    struct l7_tuple t = {};
    if (read_tuple_from_sk((struct sock *)args.sk_ptr, &t, FLOW_DIRECTION_INGRESS) < 0)
        return 0;

    // BPF 层端口过滤：跳过黑名单端口，不写入 ring buffer
    if (should_skip_port(t.sport, t.dport))
        return 0;

    struct l7_event *ev = bpf_ringbuf_reserve(&l7_events, sizeof(*ev), 0);
    if (!ev) return 0;

    fill_event_header(ev, &t, FLOW_DIRECTION_INGRESS);

    __u32 valid = (__u32)received;
    if (valid > args.buf_len) valid = args.buf_len;
    if (valid > MAX_PAYLOAD_SIZE) valid = MAX_PAYLOAD_SIZE;
    ev->payload_size = valid;

    bpf_probe_read_user(ev->payload, MAX_PAYLOAD_SIZE, (void *)args.buf_ptr);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
