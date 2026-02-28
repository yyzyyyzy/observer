// bpf/tls_tracer.c — OpenSSL/BoringSSL 明文捕获
//
// 通过 uprobe 挂载用户态 SSL_write / SSL_read（返回时），
// 在 TLS 加解密完成后直接读取已解密的明文 buffer，
// 发送到 tls_events ringbuf 供 Go 侧解析 HTTP/gRPC 等明文协议。
//
// 支持的库（在用户态加载时由 Go 动态查找 so 路径）：
//   - libssl.so.3 / libssl.so.1.1 （OpenSSL）
//   - libboringssl.so             （BoringSSL / Chrome）
//
// 事件与 l7_event 布局完全相同，Go 侧可复用 parseL7Event。
// direction 语义：
//   SSL_write → EGRESS  （应用发出的明文）
//   SSL_read  → INGRESS （应用收到的明文）

#include "headers/common.h"

#define MAX_PAYLOAD_SIZE 4096

// ── TLS 明文事件（布局与 l7_event 完全一致）────────────

struct tls_event {
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

// ── Ring Buffer ───────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} tls_events SEC(".maps");

// ── SSL fd → 四元组 解析辅助 Map ──────────────────────────
// 通过 pid_tgid 暂存 SSL_read/SSL_write 的入参（SSL* 指针，用户态 buf 地址）。

struct ssl_args_t {
    __u64 ssl_ptr;    // SSL* （用户态指针，不可直接解引用）
    __u64 buf_ptr;    // 明文 buffer 地址（用户态）
    __u32 buf_len;    // buffer 长度
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u64);
    __type(value, struct ssl_args_t);
    __uint(max_entries, 8192);
} ssl_write_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u64);
    __type(value, struct ssl_args_t);
    __uint(max_entries, 8192);
} ssl_read_args SEC(".maps");

// ── pid → fd 映射（用于关联 sock 四元组） ────────────────
// SSL_get_fd 返回文件描述符，通过 /proc/PID/fd/N -> socket -> 四元组。
// eBPF 内无法直接做 fd→sock 查找，我们改用更轻量的方案：
// 在 l7_events 事件里，Go 侧通过 PID+FD 查 /proc/net/tcp 获得四元组。
// 因此 tls_event 的四元组字段默认为零（Go 侧补全），PID/TID 为有效值。
//
// 若需要在 BPF 侧填充四元组，可通过 BPF_MAP_TYPE_SOCKMAP 或
// 在 tcp_tracer 建立的 flow_tracker_map 中二次查找（可选增强）。

// ── Helper：填充事件公共头（四元组由 Go 补全）──────────

static __always_inline void fill_tls_header(
    struct tls_event *ev,
    __u8 direction)
{
    ev->timestamp_ns = bpf_ktime_get_ns();
    __u64 pg = bpf_get_current_pid_tgid();
    ev->pid  = (__u32)(pg >> 32);
    ev->tid  = (__u32)pg;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    // saddr/daddr/sport/dport 由 Go 侧通过 /proc/net/tcp[6] + PID 补全
    ev->protocol  = IPPROTO_TCP;
    ev->direction = direction;
}

// ── uprobe：SSL_write(ssl, buf, num) → 捕获发送明文 ──────
//
// 参数（System V AMD64 ABI）：
//   rdi = SSL *ssl
//   rsi = const void *buf   (明文)
//   rdx = int num           (写入字节数)

SEC("uprobe/SSL_write")
int uprobe__ssl_write(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    void *buf    = (void *)PT_REGS_PARM2(ctx);
    __u32 num    = (__u32)PT_REGS_PARM3(ctx);
    if (!buf || num == 0) return 0;

    struct ssl_args_t args = {
        .ssl_ptr = (__u64)PT_REGS_PARM1(ctx),
        .buf_ptr = (__u64)buf,
        .buf_len = num < MAX_PAYLOAD_SIZE ? num : MAX_PAYLOAD_SIZE,
    };
    bpf_map_update_elem(&ssl_write_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write")
int uretprobe__ssl_write(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args_t *a = bpf_map_lookup_elem(&ssl_write_args, &pid_tgid);
    if (!a) return 0;

    int ret = (int)PT_REGS_RC(ctx);
    struct ssl_args_t args = *a;
    bpf_map_delete_elem(&ssl_write_args, &pid_tgid);

    if (ret <= 0) return 0;

    struct tls_event *ev = bpf_ringbuf_reserve(&tls_events, sizeof(*ev), 0);
    if (!ev) return 0;

    fill_tls_header(ev, FLOW_DIRECTION_EGRESS);

    __u32 valid = (__u32)ret;
    if (valid > args.buf_len) valid = args.buf_len;
    if (valid > MAX_PAYLOAD_SIZE) valid = MAX_PAYLOAD_SIZE;
    ev->payload_size = valid;

    bpf_probe_read_user(ev->payload, MAX_PAYLOAD_SIZE, (void *)args.buf_ptr);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── uprobe：SSL_read(ssl, buf, num) → 捕获接收明文 ───────
//
// kprobe 阶段保存 buf 指针（此时 buf 尚未填充）；
// kretprobe 阶段返回值即实际读取字节数，buf 中已有解密数据。

SEC("uprobe/SSL_read")
int uprobe__ssl_read(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    void *buf = (void *)PT_REGS_PARM2(ctx);
    __u32 num = (__u32)PT_REGS_PARM3(ctx);
    if (!buf || num == 0) return 0;

    struct ssl_args_t args = {
        .ssl_ptr = (__u64)PT_REGS_PARM1(ctx),
        .buf_ptr = (__u64)buf,
        .buf_len = num < MAX_PAYLOAD_SIZE ? num : MAX_PAYLOAD_SIZE,
    };
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int uretprobe__ssl_read(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args_t *a = bpf_map_lookup_elem(&ssl_read_args, &pid_tgid);
    if (!a) return 0;

    int ret = (int)PT_REGS_RC(ctx);
    struct ssl_args_t args = *a;
    bpf_map_delete_elem(&ssl_read_args, &pid_tgid);

    if (ret <= 0) return 0;

    struct tls_event *ev = bpf_ringbuf_reserve(&tls_events, sizeof(*ev), 0);
    if (!ev) return 0;

    fill_tls_header(ev, FLOW_DIRECTION_INGRESS);

    __u32 valid = (__u32)ret;
    if (valid > args.buf_len) valid = args.buf_len;
    if (valid > MAX_PAYLOAD_SIZE) valid = MAX_PAYLOAD_SIZE;
    ev->payload_size = valid;

    // 返回时 buf 中已有解密后的明文
    bpf_probe_read_user(ev->payload, MAX_PAYLOAD_SIZE, (void *)args.buf_ptr);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── uprobe：SSL_write_ex(ssl, buf, num, *written) ────────

SEC("uprobe/SSL_write_ex")
int uprobe__ssl_write_ex(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    void *buf = (void *)PT_REGS_PARM2(ctx);
    __u32 num = (__u32)PT_REGS_PARM3(ctx);
    if (!buf || num == 0) return 0;

    struct ssl_args_t args = {
        .ssl_ptr = (__u64)PT_REGS_PARM1(ctx),
        .buf_ptr = (__u64)buf,
        .buf_len = num < MAX_PAYLOAD_SIZE ? num : MAX_PAYLOAD_SIZE,
    };
    bpf_map_update_elem(&ssl_write_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write_ex")
int uretprobe__ssl_write_ex(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args_t *a = bpf_map_lookup_elem(&ssl_write_args, &pid_tgid);
    if (!a) return 0;

    int ret = (int)PT_REGS_RC(ctx);
    struct ssl_args_t args = *a;
    bpf_map_delete_elem(&ssl_write_args, &pid_tgid);

    if (ret != 1) return 0; // SSL_write_ex 成功返回 1

    struct tls_event *ev = bpf_ringbuf_reserve(&tls_events, sizeof(*ev), 0);
    if (!ev) return 0;

    fill_tls_header(ev, FLOW_DIRECTION_EGRESS);
    ev->payload_size = args.buf_len;
    bpf_probe_read_user(ev->payload, MAX_PAYLOAD_SIZE, (void *)args.buf_ptr);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── uprobe：SSL_read_ex(ssl, buf, num, *readbytes) ───────

SEC("uprobe/SSL_read_ex")
int uprobe__ssl_read_ex(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    void *buf = (void *)PT_REGS_PARM2(ctx);
    __u32 num = (__u32)PT_REGS_PARM3(ctx);
    if (!buf || num == 0) return 0;

    struct ssl_args_t args = {
        .ssl_ptr = (__u64)PT_REGS_PARM1(ctx),
        .buf_ptr = (__u64)buf,
        .buf_len = num < MAX_PAYLOAD_SIZE ? num : MAX_PAYLOAD_SIZE,
    };
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read_ex")
int uretprobe__ssl_read_ex(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args_t *a = bpf_map_lookup_elem(&ssl_read_args, &pid_tgid);
    if (!a) return 0;

    int ret = (int)PT_REGS_RC(ctx);
    struct ssl_args_t args = *a;
    bpf_map_delete_elem(&ssl_read_args, &pid_tgid);

    if (ret != 1) return 0;

    struct tls_event *ev = bpf_ringbuf_reserve(&tls_events, sizeof(*ev), 0);
    if (!ev) return 0;

    fill_tls_header(ev, FLOW_DIRECTION_INGRESS);
    ev->payload_size = args.buf_len;
    bpf_probe_read_user(ev->payload, MAX_PAYLOAD_SIZE, (void *)args.buf_ptr);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
