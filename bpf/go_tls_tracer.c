// bpf/go_tls_tracer.c — Go 运行时 TLS 明文捕获
//
// Go 程序使用内置的 crypto/tls 包，不链接 libssl.so，
// 因此 tls_tracer.c 的 OpenSSL uprobe 无法覆盖 Go 服务。
//
// 本文件 hook Go 标准库中以下函数：
//   crypto/tls.(*Conn).Write  → 捕获发送明文
//   crypto/tls.(*Conn).Read   → 捕获接收明文
//
// Go ABI（Register-based，Go 1.17+，amd64）：
//   receiver (*tls.Conn) → AX（rax）
//   buf      ([]byte)    → BX（rbx）= data ptr, CX（rcx）= len
//   返回值  (int, error) → AX（rax）= n, BX（rbx）= error.type
//
// 注意：Go ABI 与 System V ABI 不同，不能用 PT_REGS_PARM* 宏。
// 需要直接读取 rax/rbx/rcx 寄存器。

#include "headers/common.h"

#define MAX_GO_PAYLOAD 4096

// ── Go TLS 事件（与 tls_event 布局相同，复用 Go parseL7Event）

struct go_tls_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u8  comm[16];
    __u32 saddr;        // 由 Go 侧通过 pid+sport 查 pid_fd_sock_map 补全
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u8  direction;
    __u32 payload_size;
    __u8  payload[MAX_GO_PAYLOAD];
} __attribute__((packed));

// ── Maps ──────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} go_tls_events SEC(".maps");

// Go crypto/tls Write/Read 入参暂存
struct go_tls_args_t {
    __u64 buf_ptr;  // []byte data pointer
    __u64 buf_len;  // []byte len
};

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __type(key,         __u64);  // pid_tgid
    __type(value,       struct go_tls_args_t);
    __uint(max_entries, 8192);
} go_write_args SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __type(key,         __u64);
    __type(value,       struct go_tls_args_t);
    __uint(max_entries, 8192);
} go_read_args SEC(".maps");

// ── uprobe：crypto/tls.(*Conn).Write ─────────────────────
//
// Go register ABI (amd64):
//   rax = *tls.Conn (receiver)
//   rbx = buf data ptr
//   rcx = buf len
//   rdx = buf cap

SEC("uprobe/crypto/tls.(*Conn).Write")
int uprobe__go_tls_write(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Go ABI: 第二个参数（slice data ptr）在 rbx
    __u64 buf_ptr = ctx->bx;  // rbx
    __u64 buf_len = ctx->cx;  // rcx (len)

    if (!buf_ptr || buf_len == 0) return 0;

    struct go_tls_args_t args = {
        .buf_ptr = buf_ptr,
        .buf_len = buf_len < MAX_GO_PAYLOAD ? buf_len : MAX_GO_PAYLOAD,
    };
    bpf_map_update_elem(&go_write_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/crypto/tls.(*Conn).Write")
int uretprobe__go_tls_write(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct go_tls_args_t *a = bpf_map_lookup_elem(&go_write_args, &pid_tgid);
    if (!a) return 0;

    struct go_tls_args_t args = *a;
    bpf_map_delete_elem(&go_write_args, &pid_tgid);

    // Go ABI: 返回值 n int → rax
    __s64 n = (__s64)ctx->ax;
    if (n <= 0) return 0;

    struct go_tls_event *ev = bpf_ringbuf_reserve(&go_tls_events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    __u64 pg = bpf_get_current_pid_tgid();
    ev->pid  = (__u32)(pg >> 32);
    ev->tid  = (__u32)pg;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    // 四元组由 Go 侧通过 pid_fd_sock_map 补全（sport 作为索引）
    ev->saddr = 0;
    ev->daddr = 0;
    ev->sport = 0;
    ev->dport = 0;
    ev->protocol  = IPPROTO_TCP;
    ev->direction = FLOW_DIRECTION_EGRESS;

    __u32 valid = (__u32)n;
    if (valid > args.buf_len) valid = (__u32)args.buf_len;
    if (valid > MAX_GO_PAYLOAD) valid = MAX_GO_PAYLOAD;
    ev->payload_size = valid;
    bpf_probe_read_user(ev->payload, MAX_GO_PAYLOAD, (void *)args.buf_ptr);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── uprobe：crypto/tls.(*Conn).Read ──────────────────────
//
// 入参阶段保存 buf 地址（buf 此时为空）；
// 返回时 buf 已填充解密数据，n = 实际读取字节数。

SEC("uprobe/crypto/tls.(*Conn).Read")
int uprobe__go_tls_read(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u64 buf_ptr = ctx->bx;  // rbx
    __u64 buf_len = ctx->cx;  // rcx

    if (!buf_ptr || buf_len == 0) return 0;

    struct go_tls_args_t args = {
        .buf_ptr = buf_ptr,
        .buf_len = buf_len < MAX_GO_PAYLOAD ? buf_len : MAX_GO_PAYLOAD,
    };
    bpf_map_update_elem(&go_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/crypto/tls.(*Conn).Read")
int uretprobe__go_tls_read(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct go_tls_args_t *a = bpf_map_lookup_elem(&go_read_args, &pid_tgid);
    if (!a) return 0;

    struct go_tls_args_t args = *a;
    bpf_map_delete_elem(&go_read_args, &pid_tgid);

    __s64 n = (__s64)ctx->ax;
    if (n <= 0) return 0;

    struct go_tls_event *ev = bpf_ringbuf_reserve(&go_tls_events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    __u64 pg = bpf_get_current_pid_tgid();
    ev->pid  = (__u32)(pg >> 32);
    ev->tid  = (__u32)pg;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    ev->saddr = 0; ev->daddr = 0;
    ev->sport = 0; ev->dport = 0;
    ev->protocol  = IPPROTO_TCP;
    ev->direction = FLOW_DIRECTION_INGRESS;

    __u32 valid = (__u32)n;
    if (valid > args.buf_len) valid = (__u32)args.buf_len;
    if (valid > MAX_GO_PAYLOAD) valid = MAX_GO_PAYLOAD;
    ev->payload_size = valid;
    bpf_probe_read_user(ev->payload, MAX_GO_PAYLOAD, (void *)args.buf_ptr);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── uprobe：net/http.(*Transport).roundTrip ──────────────
//
// hook Go net/http 客户端出口，可补全 Host/Path 等信息，
// 与 crypto/tls.Write 事件关联（同 goroutine = 同 tid）。
// 此处仅捕获请求地址 URL，不读取 body（避免大量拷贝）。
//
// Go struct http.Request 偏移（Go 1.20+，amd64）：
//   方法字段：Method string（offset 0）→ data ptr at offset 0, len at 8
//   URL 字段：URL *url.URL（offset 16）→ Path string 在 url.URL 内 offset 96
// 偏移依赖 Go 版本，可通过 dlv/pahole 确认；此处用保守偏移。
// 如果偏移不对，bpf_probe_read_user 返回错误，函数静默跳过。

// 在 Go 二进制中符号为 net/http.(*Transport).roundTrip
// 实际挂载时由 Go 侧管理器通过 ex.Uprobe("net/http.(*Transport).roundTrip", ...)
// 完成，BPF 侧只需声明 SEC 名即可。

// 此 hook 为可选增强，不影响主流程。

SEC("uprobe/net/http.(*Transport).roundTrip")
int uprobe__go_http_roundtrip(struct pt_regs *ctx)
{
    // rax = *http.Transport, rbx = *http.Request
    __u64 req_ptr = ctx->bx;
    if (!req_ptr) return 0;

    // 读取 Request.Method（string：data ptr at +0, len at +8）
    __u64 method_ptr = 0;
    __u64 method_len = 0;
    bpf_probe_read_user(&method_ptr, 8, (void *)(req_ptr + 0));
    bpf_probe_read_user(&method_len, 8, (void *)(req_ptr + 8));

    if (!method_ptr || method_len == 0 || method_len > 16) return 0;

    // 此处不发出单独事件，仅记录 goroutine 级别的 method，
    // 由 Go 侧与 go_tls_write 事件按 tid 关联后补充到 ParseResult 中。
    // （实际方案：写入 percpu/hash map，由 go_tls_write uretprobe 读取合并）
    return 0;
}

char _license[] SEC("license") = "GPL";
