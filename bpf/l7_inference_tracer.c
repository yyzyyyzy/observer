// bpf/l7_inference_tracer.c — 内核态 L7 协议推断
//
// 架构：四层 tail call 链，每个 BPF 程序指令数严格控制。
//
//   第 0 层 kprobe  (tcp_sendmsg / tcp_recvmsg)
//     → 保存 sk_ptr + buf_ptr + direction 到 infer_args map
//     指令预算：< 100
//
//   第 1 层 kretprobe (tcp_sendmsg / tcp_recvmsg)
//     → 仅将 pid_tgid + ret_val 写入 infer_ret map
//     → tail_call TAIL_SETUP（不做任何内联辅助函数）
//     指令预算：< 80
//
//   第 2 层 tail_setup (TAIL_SETUP = 0)
//     → 从 infer_args / infer_ret 读取参数
//     → 读取 sock 四元组
//     → bpf_probe_read_user 前 16 字节
//     → 协议推断（纯字节比较）
//     → 写 infer_ctx_map
//     → tail_call 对应协议子程序
//     指令预算：< 3000
//
//   第 3 层 tail_http / tail_mysql / ... (TAIL_HTTP=1 ...)
//     → 从 infer_ctx_map 读上下文
//     → 提取协议元数据
//     → 写 l7_meta_events ringbuf
//     指令预算：各自 < 2000
//
// 这样设计确保：被 verifier 统计的最大程序（tail_setup）
// 只包含四元组读取 + 16 字节 peek + 协议推断，不含任何协议解析逻辑。

#include "headers/common.h"

// ── 协议枚举 ──────────────────────────────────────────────

#define L7_PROTO_UNKNOWN  0
#define L7_PROTO_HTTP     1
#define L7_PROTO_HTTP2    2
#define L7_PROTO_MYSQL    3
#define L7_PROTO_REDIS    4
#define L7_PROTO_DNS      5
#define L7_PROTO_KAFKA    6
#define L7_PROTO_MQTT     7

// tail call 跳转表索引
#define TAIL_SETUP  0
#define TAIL_HTTP   1
#define TAIL_HTTP2  2
#define TAIL_MYSQL  3
#define TAIL_REDIS  4
#define TAIL_DNS    5
#define TAIL_KAFKA  6

#define PEEK_SIZE  16   // 协议推断只需要前 16 字节
#define META_SIZE  48   // HTTP URL hash 额外读取

// ── 事件结构体（80 bytes）────────────────────────────────

struct l7_meta_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u8  comm[16];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  direction;
    __u8  l7_proto;
    __u8  req_type;     // 1=request 2=response 3=session
    __u8  http_method;
    __u8  mysql_cmd;
    __u16 http_status;
    __u32 http_url_hash;
    __u8  redis_cmd[8];
    __u16 dns_txid;
    __u16 dns_flags;
    __u16 kafka_api_key;
    __u16 _pad;
    __u32 kafka_correl;
    __u32 payload_len;
};

// ── Maps ──────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} l7_meta_events SEC(".maps");

// tail call 跳转表（TAIL_SETUP=0 ... TAIL_KAFKA=6）
struct {
    __uint(type,        BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);
    __type(key,         __u32);
    __type(value,       __u32);
} l7_tail_progs SEC(".maps");

// kprobe entry 保存的参数（key = pid_tgid）
struct infer_args_t {
    __u64 sk_ptr;
    __u64 buf_ptr;
    __u32 buf_len;
    __u8  direction;
    __u8  _pad[3];
};

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,         __u64);
    __type(value,       struct infer_args_t);
} infer_send_args SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,         __u64);
    __type(value,       struct infer_args_t);
} infer_recv_args SEC(".maps");

// kretprobe 写入、tail_setup 读取（key = pid_tgid）
struct infer_ret_t {
    __u64 pid_tgid;
    __s64 ret_val;      // 实际收发字节数
    __u8  is_recv;      // 0=sendmsg 1=recvmsg
    __u8  _pad[7];
};

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,         __u64);
    __type(value,       struct infer_ret_t);
} infer_ret_map SEC(".maps");

// percpu 上下文，在 tail_setup → 协议子程序之间传递
struct infer_ctx_t {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u8  comm[16];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  direction;
    __u8  l7_proto;
    __u8  _pad;
    __u32 buf_len;
    __u64 buf_ptr;
    __u8  peek[PEEK_SIZE];
};

struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       struct infer_ctx_t);
} infer_ctx_map SEC(".maps");

// ═══════════════════════════════════════════════════════════
// 第 0 层：kprobe entry（极简，只保存参数）
// ═══════════════════════════════════════════════════════════

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg_infer(struct pt_regs *ctx)
{
    struct sock   *sk  = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    // 直接读 iov，iter_type=0 表示 ITER_UBUF（内核 6.0+）
    __u64 buf_ptr = 0;
    __u32 buf_len = 0;

    __u8 iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);
    if (iter_type == 0) {
        void *ubuf = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
        if (!ubuf) return 0;
        size_t cnt = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_len);
        buf_ptr = (__u64)ubuf;
        buf_len = (__u32)(cnt < 65536 ? cnt : 65536);
    } else {
        const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
        if (!iov) return 0;
        __u64 base = 0; __u64 len = 0;
        BPF_CORE_READ_INTO(&base, iov, iov_base);
        BPF_CORE_READ_INTO(&len,  iov, iov_len);
        if (!base) return 0;
        buf_ptr = base;
        buf_len = (__u32)(len < 65536 ? len : 65536);
    }

    __u64 pg = bpf_get_current_pid_tgid();
    struct infer_args_t a = {};
    a.sk_ptr    = (__u64)(long)sk;
    a.buf_ptr   = buf_ptr;
    a.buf_len   = buf_len;
    a.direction = FLOW_DIRECTION_EGRESS;
    bpf_map_update_elem(&infer_send_args, &pg, &a, BPF_ANY);
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe__tcp_recvmsg_infer(struct pt_regs *ctx)
{
    struct sock   *sk  = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    __u64 buf_ptr = 0;
    __u32 buf_len = 0;

    __u8 iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);
    if (iter_type == 0) {
        void *ubuf = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
        if (!ubuf) return 0;
        size_t cnt = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_len);
        buf_ptr = (__u64)ubuf;
        buf_len = (__u32)(cnt < 65536 ? cnt : 65536);
    } else {
        const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
        if (!iov) return 0;
        __u64 base = 0; __u64 len = 0;
        BPF_CORE_READ_INTO(&base, iov, iov_base);
        BPF_CORE_READ_INTO(&len,  iov, iov_len);
        if (!base) return 0;
        buf_ptr = base;
        buf_len = (__u32)(len < 65536 ? len : 65536);
    }

    __u64 pg = bpf_get_current_pid_tgid();
    struct infer_args_t a = {};
    a.sk_ptr    = (__u64)(long)sk;
    a.buf_ptr   = buf_ptr;
    a.buf_len   = buf_len;
    a.direction = FLOW_DIRECTION_INGRESS;
    bpf_map_update_elem(&infer_recv_args, &pg, &a, BPF_ANY);
    return 0;
}

// ═══════════════════════════════════════════════════════════
// 第 1 层：kretprobe（只写 ret_val + tail_call TAIL_SETUP）
// 不内联任何辅助函数，保持程序极小
// ═══════════════════════════════════════════════════════════

SEC("kretprobe/tcp_sendmsg")
int kretprobe__tcp_sendmsg_infer(struct pt_regs *ctx)
{
    __s64 ret = (ssize_t)PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    __u64 pg = bpf_get_current_pid_tgid();
    struct infer_ret_t r = {};
    r.pid_tgid = pg;
    r.ret_val  = ret;
    r.is_recv  = 0;
    bpf_map_update_elem(&infer_ret_map, &pg, &r, BPF_ANY);
    bpf_tail_call(ctx, &l7_tail_progs, TAIL_SETUP);
    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe__tcp_recvmsg_infer(struct pt_regs *ctx)
{
    __s64 ret = (ssize_t)PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    __u64 pg = bpf_get_current_pid_tgid();
    struct infer_ret_t r = {};
    r.pid_tgid = pg;
    r.ret_val  = ret;
    r.is_recv  = 1;
    bpf_map_update_elem(&infer_ret_map, &pg, &r, BPF_ANY);
    bpf_tail_call(ctx, &l7_tail_progs, TAIL_SETUP);
    return 0;
}

// ═══════════════════════════════════════════════════════════
// 第 2 层：tail_setup — 读参数 + 四元组 + peek + 推断 + 分发
// 所有逻辑集中在此一个 SEC，不内联大型辅助函数
// ═══════════════════════════════════════════════════════════

SEC("kprobe/tail_setup")
int tail_setup(struct pt_regs *ctx)
{
    __u64 pg = bpf_get_current_pid_tgid();

    // 读取 ret_val
    struct infer_ret_t *rp = bpf_map_lookup_elem(&infer_ret_map, &pg);
    if (!rp) return 0;
    __s64 nbytes = rp->ret_val;
    __u8  is_recv = rp->is_recv;
    bpf_map_delete_elem(&infer_ret_map, &pg);

    if (nbytes <= 0) return 0;

    // 读取 entry 参数
    struct infer_args_t *ap = is_recv
        ? bpf_map_lookup_elem(&infer_recv_args, &pg)
        : bpf_map_lookup_elem(&infer_send_args, &pg);
    if (!ap) return 0;

    __u64 sk_ptr   = ap->sk_ptr;
    __u64 buf_ptr  = ap->buf_ptr;
    __u8  direction = ap->direction;

    if (is_recv)
        bpf_map_delete_elem(&infer_recv_args, &pg);
    else
        bpf_map_delete_elem(&infer_send_args, &pg);

    // 读取 percpu 上下文槽
    __u32 zero = 0;
    struct infer_ctx_t *ictx = bpf_map_lookup_elem(&infer_ctx_map, &zero);
    if (!ictx) return 0;

    // 填充公共头
    ictx->timestamp_ns = bpf_ktime_get_ns();
    ictx->pid       = (__u32)(pg >> 32);
    ictx->tid       = (__u32)pg;
    bpf_get_current_comm(&ictx->comm, 16);
    ictx->direction = direction;
    ictx->buf_len   = (__u32)nbytes;
    ictx->buf_ptr   = buf_ptr;
    ictx->proto     = IPPROTO_TCP;

    // 读取 sock 四元组（直接展开，不调用辅助函数）
    struct sock *sk = (struct sock *)sk_ptr;
    ictx->saddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
    ictx->daddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));
    ictx->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    ictx->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    // 读取前 PEEK_SIZE 字节
    __builtin_memset(ictx->peek, 0, PEEK_SIZE);
    if (bpf_probe_read_user(ictx->peek, PEEK_SIZE, (void *)buf_ptr) < 0)
        return 0;

    // ── 协议推断（纯字节比较，零循环，零内联调用）──────────
    const __u8 *p = ictx->peek;
    __u16 sp = ictx->sport, dp = ictx->dport;
    __u8 proto = L7_PROTO_UNKNOWN;

    if (sp == 53 || dp == 53) {
        proto = L7_PROTO_DNS;
        goto dispatch;
    }
    if ((sp == 1883 || dp == 1883 || sp == 8883 || dp == 8883) && p[0] == 0x10) {
        proto = L7_PROTO_MQTT;
        goto dispatch;
    }
    if (sp == 9092 || dp == 9092 || sp == 9093 || dp == 9093) {
        __u16 api = ((__u16)p[4] << 8) | p[5];
        if (api <= 67) { proto = L7_PROTO_KAFKA; goto dispatch; }
    }
    if (sp == 3306 || dp == 3306) {
        if (p[4] <= 0x1f) { proto = L7_PROTO_MYSQL; goto dispatch; }
    }
    if (sp == 6379 || dp == 6379) {
        if (p[0]=='*' || p[0]=='+' || p[0]=='-' || p[0]==':' || p[0]=='$') {
            proto = L7_PROTO_REDIS; goto dispatch;
        }
    }
    // HTTP/2 preface
    if (p[0]=='P' && p[1]=='R' && p[2]=='I' && p[3]==' ' && p[4]=='*' && p[5]==' ') {
        proto = L7_PROTO_HTTP2; goto dispatch;
    }
    // HTTP/1.x 请求方法
    if (p[0]=='G' && p[1]=='E' && p[2]=='T' && p[3]==' ') { proto=L7_PROTO_HTTP; goto dispatch; }
    if (p[0]=='P' && p[1]=='O' && p[2]=='S' && p[3]=='T') { proto=L7_PROTO_HTTP; goto dispatch; }
    if (p[0]=='P' && p[1]=='U' && p[2]=='T' && p[3]==' ') { proto=L7_PROTO_HTTP; goto dispatch; }
    if (p[0]=='D' && p[1]=='E' && p[2]=='L' && p[3]=='E') { proto=L7_PROTO_HTTP; goto dispatch; }
    if (p[0]=='H' && p[1]=='E' && p[2]=='A' && p[3]=='D') { proto=L7_PROTO_HTTP; goto dispatch; }
    if (p[0]=='P' && p[1]=='A' && p[2]=='T' && p[3]=='C') { proto=L7_PROTO_HTTP; goto dispatch; }
    if (p[0]=='O' && p[1]=='P' && p[2]=='T' && p[3]=='I') { proto=L7_PROTO_HTTP; goto dispatch; }
    if (p[0]=='C' && p[1]=='O' && p[2]=='N' && p[3]=='N') { proto=L7_PROTO_HTTP; goto dispatch; }
    if (p[0]=='T' && p[1]=='R' && p[2]=='A' && p[3]=='C') { proto=L7_PROTO_HTTP; goto dispatch; }
    // HTTP/1.x 响应
    if (p[0]=='H' && p[1]=='T' && p[2]=='T' && p[3]=='P') { proto=L7_PROTO_HTTP; goto dispatch; }

dispatch:
    if (proto == L7_PROTO_UNKNOWN || proto == L7_PROTO_MQTT) return 0;
    ictx->l7_proto = proto;

    __u32 tail_idx;
    if      (proto == L7_PROTO_HTTP)   tail_idx = TAIL_HTTP;
    else if (proto == L7_PROTO_HTTP2)  tail_idx = TAIL_HTTP2;
    else if (proto == L7_PROTO_MYSQL)  tail_idx = TAIL_MYSQL;
    else if (proto == L7_PROTO_REDIS)  tail_idx = TAIL_REDIS;
    else if (proto == L7_PROTO_DNS)    tail_idx = TAIL_DNS;
    else if (proto == L7_PROTO_KAFKA)  tail_idx = TAIL_KAFKA;
    else return 0;

    bpf_tail_call(ctx, &l7_tail_progs, tail_idx);
    return 0;
}

// ═══════════════════════════════════════════════════════════
// 第 3 层：协议子程序（各自独立 SEC，verifier 单独计数）
// ═══════════════════════════════════════════════════════════

// 公共辅助：填充事件头（内联可接受，单次使用）
static __always_inline void fill_meta_hdr(
    struct l7_meta_event *ev,
    const struct infer_ctx_t *ictx)
{
    ev->timestamp_ns = ictx->timestamp_ns;
    ev->pid          = ictx->pid;
    ev->tid          = ictx->tid;
    __builtin_memcpy(ev->comm, ictx->comm, 16);
    ev->saddr        = ictx->saddr;
    ev->daddr        = ictx->daddr;
    ev->sport        = ictx->sport;
    ev->dport        = ictx->dport;
    ev->proto        = ictx->proto;
    ev->direction    = ictx->direction;
    ev->l7_proto     = ictx->l7_proto;
    ev->payload_len  = ictx->buf_len;
}

// ── HTTP ──────────────────────────────────────────────────

SEC("kprobe/tail_http")
int tail_http(struct pt_regs *ctx)
{
    __u32 zero = 0;
    struct infer_ctx_t *ictx = bpf_map_lookup_elem(&infer_ctx_map, &zero);
    if (!ictx) return 0;

    struct l7_meta_event *ev = bpf_ringbuf_reserve(&l7_meta_events, sizeof(*ev), 0);
    if (!ev) return 0;
    __builtin_memset(ev, 0, sizeof(*ev));
    fill_meta_hdr(ev, ictx);

    const __u8 *p = ictx->peek;

    if (p[0]=='H' && p[1]=='T' && p[2]=='T' && p[3]=='P') {
        // 响应：HTTP/1.x NNN
        ev->req_type = 2;
        // "HTTP/1.1 200 ..." → status 在 offset 9
        __u16 s = 0;
        if (p[9]  >='0' && p[9]  <='9') s  = ((__u16)(p[9]  -'0')) * 100;
        if (p[10] >='0' && p[10] <='9') s += ((__u16)(p[10] -'0')) * 10;
        if (p[11] >='0' && p[11] <='9') s += ((__u16)(p[11] -'0'));
        ev->http_status = s;
    } else {
        // 请求
        ev->req_type = 1;
        if      (p[0]=='G')              ev->http_method = 1; // GET
        else if (p[0]=='P'&&p[1]=='O')   ev->http_method = 2; // POST
        else if (p[0]=='P'&&p[1]=='U')   ev->http_method = 3; // PUT
        else if (p[0]=='D')              ev->http_method = 4; // DELETE
        else if (p[0]=='H'&&p[1]=='E')   ev->http_method = 5; // HEAD
        else if (p[0]=='P'&&p[1]=='A')   ev->http_method = 6; // PATCH
        else if (p[0]=='O')              ev->http_method = 7; // OPTIONS
        else if (p[0]=='C'&&p[1]=='O')   ev->http_method = 8; // CONNECT
        else if (p[0]=='T')              ev->http_method = 9; // TRACE

        // URL hash：额外读取 META_SIZE 字节
        __u8 meta[META_SIZE];
        __builtin_memset(meta, 0, META_SIZE);
        bpf_probe_read_user(meta, META_SIZE, (void *)ictx->buf_ptr);

        // 找 method 后的空格（固定偏移匹配）
        int us = 0;
        if      (meta[3]==' ') us = 4;
        else if (meta[4]==' ') us = 5;
        else if (meta[6]==' ') us = 7;
        else if (meta[7]==' ') us = 8;

        // djb2 hash，固定展开 16 步（无循环）
        __u32 h = 5381;
        if (us > 0 && us <= (int)(META_SIZE - 16)) {
            const __u8 *u = meta + us;
            #define DJB2(i) if(u[i] && u[i]!=' ' && u[i]!='?') h=((h<<5)+h)+u[i]
            DJB2(0);  DJB2(1);  DJB2(2);  DJB2(3);
            DJB2(4);  DJB2(5);  DJB2(6);  DJB2(7);
            DJB2(8);  DJB2(9);  DJB2(10); DJB2(11);
            DJB2(12); DJB2(13); DJB2(14); DJB2(15);
            #undef DJB2
        }
        ev->http_url_hash = h;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── HTTP/2 ────────────────────────────────────────────────

SEC("kprobe/tail_http2")
int tail_http2(struct pt_regs *ctx)
{
    __u32 zero = 0;
    struct infer_ctx_t *ictx = bpf_map_lookup_elem(&infer_ctx_map, &zero);
    if (!ictx) return 0;

    struct l7_meta_event *ev = bpf_ringbuf_reserve(&l7_meta_events, sizeof(*ev), 0);
    if (!ev) return 0;
    __builtin_memset(ev, 0, sizeof(*ev));
    fill_meta_hdr(ev, ictx);
    ev->req_type = 1;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── MySQL ─────────────────────────────────────────────────

SEC("kprobe/tail_mysql")
int tail_mysql(struct pt_regs *ctx)
{
    __u32 zero = 0;
    struct infer_ctx_t *ictx = bpf_map_lookup_elem(&infer_ctx_map, &zero);
    if (!ictx) return 0;

    struct l7_meta_event *ev = bpf_ringbuf_reserve(&l7_meta_events, sizeof(*ev), 0);
    if (!ev) return 0;
    __builtin_memset(ev, 0, sizeof(*ev));
    fill_meta_hdr(ev, ictx);

    const __u8 *p = ictx->peek;
    ev->mysql_cmd = (ictx->buf_len >= 5) ? p[4] : 0;
    ev->req_type  = (ictx->dport == 3306) ? 1 : 2;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── Redis ─────────────────────────────────────────────────

SEC("kprobe/tail_redis")
int tail_redis(struct pt_regs *ctx)
{
    __u32 zero = 0;
    struct infer_ctx_t *ictx = bpf_map_lookup_elem(&infer_ctx_map, &zero);
    if (!ictx) return 0;

    struct l7_meta_event *ev = bpf_ringbuf_reserve(&l7_meta_events, sizeof(*ev), 0);
    if (!ev) return 0;
    __builtin_memset(ev, 0, sizeof(*ev));
    fill_meta_hdr(ev, ictx);

    const __u8 *p = ictx->peek;
    if (p[0] == '*' && ictx->buf_len >= 9) {
        ev->req_type    = 1;
        // RESP *N\r\n$M\r\nCMD → CMD 起始于固定偏移 8（覆盖单字节 M 情形）
        ev->redis_cmd[0] = p[8];
        ev->redis_cmd[1] = p[9];
        ev->redis_cmd[2] = p[10];
        ev->redis_cmd[3] = p[11];
        ev->redis_cmd[4] = p[12];
        ev->redis_cmd[5] = p[13];
        ev->redis_cmd[6] = p[14];
        ev->redis_cmd[7] = 0;
    } else {
        ev->req_type = (p[0]=='+' || p[0]==':' || p[0]=='$' || p[0]=='-') ? 2 : 1;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── DNS ───────────────────────────────────────────────────

SEC("kprobe/tail_dns")
int tail_dns(struct pt_regs *ctx)
{
    __u32 zero = 0;
    struct infer_ctx_t *ictx = bpf_map_lookup_elem(&infer_ctx_map, &zero);
    if (!ictx) return 0;

    struct l7_meta_event *ev = bpf_ringbuf_reserve(&l7_meta_events, sizeof(*ev), 0);
    if (!ev) return 0;
    __builtin_memset(ev, 0, sizeof(*ev));
    fill_meta_hdr(ev, ictx);

    const __u8 *p = ictx->peek;
    if (ictx->buf_len >= 4) {
        ev->dns_txid  = ((__u16)p[0] << 8) | p[1];
        ev->dns_flags = ((__u16)p[2] << 8) | p[3];
        // QR bit（最高位）：0=query 1=response
        ev->req_type  = (ev->dns_flags & 0x8000) ? 2 : 1;
    } else {
        ev->req_type = 3;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── Kafka ─────────────────────────────────────────────────

SEC("kprobe/tail_kafka")
int tail_kafka(struct pt_regs *ctx)
{
    __u32 zero = 0;
    struct infer_ctx_t *ictx = bpf_map_lookup_elem(&infer_ctx_map, &zero);
    if (!ictx) return 0;

    struct l7_meta_event *ev = bpf_ringbuf_reserve(&l7_meta_events, sizeof(*ev), 0);
    if (!ev) return 0;
    __builtin_memset(ev, 0, sizeof(*ev));
    fill_meta_hdr(ev, ictx);
    ev->req_type = 1;

    const __u8 *p = ictx->peek;
    if (ictx->buf_len >= 12) {
        ev->kafka_api_key = ((__u16)p[4] << 8) | p[5];
        ev->kafka_correl  = ((__u32)p[8]<<24) | ((__u32)p[9]<<16) |
                            ((__u32)p[10]<<8) |  (__u32)p[11];
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
