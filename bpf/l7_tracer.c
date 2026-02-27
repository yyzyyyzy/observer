// bpf/l7_tracer.c — L7 载荷捕获 eBPF 程序
//
// 事件结构布局（与 Go parseL7Event 精确对齐，packed）：
//   [0:8]   timestamp_ns  u64
//   [8:12]  pid           u32
//   [12:16] tid           u32
//   [16:32] comm          u8[16]
//   [32:36] saddr         u32
//   [36:40] daddr         u32
//   [40:42] sport         u16
//   [42:44] dport         u16
//   [44]    protocol      u8
//   [45]    direction     u8
//   [46:50] payload_size  u32  (实际有效字节数)
//   [50:]   payload       u8[MAX_PAYLOAD_SIZE]

#include "headers/common.h"

// MAX_PAYLOAD_SIZE 必须是 2 的幂次。
// 关键：bpf_probe_read_user 使用编译期常量调用，确保 verifier 不需要
// 对运行时 size 做界限分析，从而在 kernel 6.x strict verifier 下通过。
#define MAX_PAYLOAD_SIZE 4096

// ── Ring Buffer ───────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} l7_events SEC(".maps");

// ── L7 事件结构（packed，与 Go L7Event 精确对齐）────────

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
    __u32 payload_size;  // 实际有效字节数（≤ MAX_PAYLOAD_SIZE）
    __u8  payload[MAX_PAYLOAD_SIZE];
} __attribute__((packed));

// ── sendmsg 入参暂存 ──────────────────────────────────────

struct sendmsg_args_t {
    __u64 sk_ptr;
    __u64 buf_ptr;
    __u32 buf_len;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u64);
    __type(value, struct sendmsg_args_t);
    __uint(max_entries, 8192);
} l7_active_sendmsg SEC(".maps");

// ── recvmsg 入参暂存 ──────────────────────────────────────

struct recvmsg_args_t {
    __u64 sk_ptr;
    __u64 buf_ptr;
    __u32 buf_len;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u64);
    __type(value, struct recvmsg_args_t);
    __uint(max_entries, 8192);
} l7_active_recvmsg SEC(".maps");

// ── Helper：从 sock* 读取四元组 ──────────────────────────
//
// struct sock_common 内存布局（kernel 4.14~6.12 稳定）：
//   +0x00: __be32 skc_daddr       (远端 IP，网络序)
//   +0x04: __be32 skc_rcv_saddr   (本地 IP，网络序)
//   +0x0C: __be16 skc_dport       (远端端口，网络序)
//   +0x0E: __u16  skc_num         (本地端口，主机序)

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
    __be32 skc_daddr     = 0;
    __be32 skc_rcv_saddr = 0;
    __be16 skc_dport     = 0;
    __u16  skc_num       = 0;

    if (bpf_probe_read_kernel(&skc_daddr,     4, sk + 0x00) < 0) return -1;
    if (bpf_probe_read_kernel(&skc_rcv_saddr, 4, sk + 0x04) < 0) return -1;
    if (bpf_probe_read_kernel(&skc_dport,     2, sk + 0x0C) < 0) return -1;
    if (bpf_probe_read_kernel(&skc_num,       2, sk + 0x0E) < 0) return -1;

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

// ── Helper：从 msghdr 读取 iov buffer 指针和长度 ─────────
//
// msghdr 布局（64-bit kernel）：
//   +0x10: struct iov_iter msg_iter
// iov_iter (kernel 5.14+): iov ptr 在 iov_iter + 0x08
// 故 iov_ptr 在 msghdr + 0x18

static __always_inline int read_iov_from_msghdr(
    void *msg,
    __u64 *iov_base_out,
    __u32 *iov_len_out)
{
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

    // 保存原始长度（供后续 payload_size 计算用，不超过 MAX_PAYLOAD_SIZE）
    __u32 len = (__u32)iov_len;
    if (len > MAX_PAYLOAD_SIZE) len = MAX_PAYLOAD_SIZE;

    *iov_base_out = iov_base;
    *iov_len_out  = len;
    return 0;
}

// ── Helper：填充 l7_event 公共头字段 ─────────────────────

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
    bpf_map_update_elem(&l7_active_sendmsg, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe__tcp_sendmsg_l7(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_args_t *a = bpf_map_lookup_elem(&l7_active_sendmsg, &pid_tgid);
    if (!a) return 0;

    ssize_t sent = PT_REGS_RC(ctx);
    struct sendmsg_args_t args = *a;
    bpf_map_delete_elem(&l7_active_sendmsg, &pid_tgid);

    if (sent <= 0) return 0;

    struct l7_tuple t = {};
    if (read_tuple_from_sk((void *)args.sk_ptr, &t, FLOW_DIRECTION_EGRESS) < 0)
        return 0;

    struct l7_event *ev = bpf_ringbuf_reserve(&l7_events, sizeof(*ev), 0);
    if (!ev) return 0;

    fill_event_header(ev, &t, FLOW_DIRECTION_EGRESS);

    // 计算实际有效字节数（不超过 buf_len 和 MAX_PAYLOAD_SIZE）
    __u32 valid = (__u32)sent;
    if (valid > args.buf_len) valid = args.buf_len;
    if (valid > MAX_PAYLOAD_SIZE) valid = MAX_PAYLOAD_SIZE;
    ev->payload_size = valid;

    // 关键：bpf_probe_read_user 使用编译期常量 MAX_PAYLOAD_SIZE，
    // 而非运行时 valid，彻底规避 kernel 6.x verifier 的 R2 unbounded 问题。
    // userspace 侧读取 payload[:payload_size] 获取有效数据，其余为零填充。
    bpf_probe_read_user(ev->payload, MAX_PAYLOAD_SIZE, (void *)args.buf_ptr);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── kprobe/tcp_recvmsg ────────────────────────────────────

SEC("kprobe/tcp_recvmsg")
int kprobe__tcp_recvmsg_l7(struct pt_regs *ctx)
{
    void *sk  = (void *)PT_REGS_PARM1(ctx);
    void *msg = (void *)PT_REGS_PARM2(ctx);

    __u64 iov_base = 0;
    __u32 iov_len  = 0;
    read_iov_from_msghdr(msg, &iov_base, &iov_len);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct recvmsg_args_t args = {
        .sk_ptr  = (__u64)sk,
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
    struct recvmsg_args_t *a = bpf_map_lookup_elem(&l7_active_recvmsg, &pid_tgid);
    if (!a) return 0;

    ssize_t received = PT_REGS_RC(ctx);
    struct recvmsg_args_t args = *a;
    bpf_map_delete_elem(&l7_active_recvmsg, &pid_tgid);

    if (received <= 0) return 0;

    struct l7_tuple t = {};
    if (read_tuple_from_sk((void *)args.sk_ptr, &t, FLOW_DIRECTION_INGRESS) < 0)
        return 0;

    struct l7_event *ev = bpf_ringbuf_reserve(&l7_events, sizeof(*ev), 0);
    if (!ev) return 0;

    fill_event_header(ev, &t, FLOW_DIRECTION_INGRESS);

    __u32 valid = (__u32)received;
    if (valid > args.buf_len) valid = args.buf_len;
    if (valid > MAX_PAYLOAD_SIZE) valid = MAX_PAYLOAD_SIZE;
    ev->payload_size = valid;

    // 同上：用编译期常量读取，userspace 只处理 payload[:payload_size]
    bpf_probe_read_user(ev->payload, MAX_PAYLOAD_SIZE, (void *)args.buf_ptr);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
