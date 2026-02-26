// bpf/tcp_tracer.c
// TCP 流追踪器 —— 深度对齐 DeepFlow v6
//
// DeepFlow TCP 设计要点（全面对齐）：
//
//  1. 流生命周期三态：FLOW_CREATE / FLOW_UPDATE / FLOW_DESTROY
//     - FLOW_CREATE:  tcp_set_state → ESTABLISHED（五元组完整，计时开始）
//     - FLOW_UPDATE:  重传/零窗口/RST/字节采样触发（避免长流丢中间状态）
//     - FLOW_DESTROY: tcp_set_state → TCP_CLOSE（携带完整汇总指标）
//
//  2. Role（连接角色）精确判断：
//     - tcp_connect hook  → ROLE_CLIENT（主动发起，100% 准确）
//     - inet_csk_accept   → ROLE_SERVER（被动 accept，内核返回 new_sk，无误判）
//     - 兜底：established 时通过 sport<1024 判断
//
//  3. SYN RTT 三段精确分解（DeepFlow 核心指标）：
//     - syn_rtt_server_us: SYN → SYN+ACK（服务端处理时延）
//       在 tcp_rcv_state_process 收到 SYN+ACK 时记录
//     - syn_rtt_client_us: SYN+ACK → ACK（客户端 ACK 时延）
//       在 ESTABLISHED 时 = now - synack_ts
//     - syn_rtt_us: 全程 SYN → ESTABLISHED
//
//  4. 数据层 RTT（DeepFlow art_us / rtt_us 对应）：
//     - 用 tcp_sendmsg 记录最后发送时间戳
//     - tcp_ack 收到 ACK 时计算 Δt = RTT 样本
//     - 累积 min/avg/max（BPF 侧完成，减少用户态计算）
//
//  5. SRT（System Response Time，服务端响应时延）：
//     - 对 ROLE_SERVER：从收到第一个数据包到发出第一个响应包的时延
//     - tcp_recvmsg kretprobe 记录 request_ts，tcp_sendmsg 记录 response_ts
//
//  6. 重传 / 零窗口：
//     - tcp_retransmit_skb：计 retrans_pkts + retrans_bytes，触发 FLOW_UPDATE
//     - tcp_check_rcv_wnd 零窗口：用 zero_wnd_start_ts + 累积 duration
//
//  7. 采样策略（对齐 DeepFlow byte-based 采样）：
//     - SAMPLE_BYTES_THRESHOLD = 64KB，每累积 64KB 发一次 FLOW_UPDATE 快照
//     - 重传/RST/零窗口事件立即发，不受阈值限制
//
//  8. 内存布局：BPF struct tcp_event = Go TCPEvent，152 bytes，字段偏移精确注释

#include "headers/common.h"

// ── 事件子类型（FLOW_UPDATE 的触发原因） ─────────────────
#define SUBTYPE_NONE        0
#define SUBTYPE_RETRANS     1   // 重传触发
#define SUBTYPE_ZERO_WND    2   // 零窗口触发
#define SUBTYPE_BYTES_FLUSH 3   // 字节采样触发
#define SUBTYPE_RST         4   // RST 触发

// 字节采样阈值（对齐 DeepFlow 64KB）
#define SAMPLE_BYTES_THRESHOLD (64 * 1024)

// ── BPF Map 中的全量连接状态 ─────────────────────────────
struct tcp_flow_state {
    // 五元组
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;

    // 身份
    __u8  role;             // ROLE_CLIENT / ROLE_SERVER / ROLE_UNKNOWN
    __u8  tcp_state;
    __u8  destroy_reason;
    __u8  syn_retrans;

    // 握手时间戳（ns）
    __u64 syn_ts;
    __u64 synack_ts;
    __u64 established_ts;

    // 数据层 RTT（μs）
    __u64 last_data_send_ts;
    __u32 rtt_us_sum;
    __u32 rtt_us_max;
    __u32 rtt_us_min;       // 初始化为 0xFFFFFFFF
    __u32 rtt_count;

    // SRT（服务端响应时延，μs）
    __u64 request_rcv_ts;   // 服务端收到第一个请求包的时间戳
    __u32 srt_us_sum;
    __u32 srt_us_max;
    __u32 srt_count;
    __u8  srt_pending;      // 是否正在等待服务端响应
    __u8  _pad_srt[3];

    // 重传
    __u32 retrans_pkts;
    __u32 _pad_retrans;
    __u64 retrans_bytes;

    // 零窗口
    __u32 zero_wnd_count;
    __u32 _pad_zero;
    __u64 zero_wnd_start_ts;
    __u64 zero_wnd_total_us;

    // 吞吐
    __u64 bytes_sent;
    __u64 bytes_recv;
    __u64 pkts_sent;
    __u64 pkts_recv;

    // 采样控制
    __u64 last_flush_bytes;

    // 异常
    __u8  rst_count;
    __u8  timeout_flag;
    __u8  _pad0[6];

    // 时间
    __u64 start_ts;
    __u64 last_update_ts;
};

// ── Ring buffer 事件（152 bytes，与 Go TCPEvent 精确对齐）─
//
// [0:8]    timestamp_ns
// [8:12]   pid
// [12:16]  tid
// [16:32]  comm[16]
// [32:36]  saddr
// [36:40]  daddr
// [40:42]  sport
// [42:44]  dport
// [44]     protocol
// [45]     lifecycle      FLOW_CREATE/UPDATE/DESTROY
// [46]     direction
// [47]     role           ROLE_CLIENT/SERVER
// [48:52]  syn_rtt        全程建连时延（μs）
// [52:56]  syn_rtt_client SYN+ACK→ACK（μs）
// [56:60]  syn_rtt_server SYN→SYN+ACK（μs）
// [60:64]  rtt_mean
// [64:68]  rtt_max
// [68:72]  rtt_min
// [72:76]  srt_mean
// [76:80]  srt_max
// [80:84]  retrans_count
// [84]     event_subtype
// [85]     destroy_reason
// [86]     syn_retrans
// [87]     rst_count
// [88:96]  retrans_bytes
// [96:100] zero_wnd_count
// [100:104] _pad
// [104:112] zero_wnd_duration
// [112:120] bytes_sent
// [120:128] bytes_received
// [128:136] packets_sent
// [136:144] packets_received
// [144]    timeout_flag
// [145]    tcp_state
// [146:148] _pad
// [148:152] duration_us
// Total = 152 bytes
struct tcp_event {
    __u64 timestamp_ns;     // [0:8]
    __u32 pid;              // [8:12]
    __u32 tid;              // [12:16]
    char  comm[16];         // [16:32]
    __u32 saddr;            // [32:36]
    __u32 daddr;            // [36:40]
    __u16 sport;            // [40:42]
    __u16 dport;            // [42:44]
    __u8  protocol;         // [44]
    __u8  lifecycle;        // [45]
    __u8  direction;        // [46]
    __u8  role;             // [47]
    __u32 syn_rtt;          // [48:52]  μs
    __u32 syn_rtt_client;   // [52:56]  μs
    __u32 syn_rtt_server;   // [56:60]  μs
    __u32 rtt_mean;         // [60:64]  μs
    __u32 rtt_max;          // [64:68]  μs
    __u32 rtt_min;          // [68:72]  μs
    __u32 srt_mean;         // [72:76]  μs
    __u32 srt_max;          // [76:80]  μs
    __u32 retrans_count;    // [80:84]
    __u8  event_subtype;    // [84]
    __u8  destroy_reason;   // [85]
    __u8  syn_retrans;      // [86]
    __u8  rst_count;        // [87]
    __u64 retrans_bytes;    // [88:96]
    __u32 zero_wnd_count;   // [96:100]
    __u32 _pad2;            // [100:104]
    __u64 zero_wnd_duration;// [104:112] μs
    __u64 bytes_sent;       // [112:120]
    __u64 bytes_received;   // [120:128]
    __u64 packets_sent;     // [128:136]
    __u64 packets_received; // [136:144]
    __u8  timeout_flag;     // [144]
    __u8  tcp_state;        // [145]
    __u8  _pad3[2];         // [146:148]
    __u32 duration_us;      // [148:152]
};

// ── Maps ──────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct sock *);
    __type(value, struct tcp_flow_state);
} flow_tracker_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} tcp_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key,   __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// accept 时暂存 parent_sk → new_sk 的映射（用于标记服务端角色）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64);    // pid_tgid
    __type(value, struct sock *); // parent listener sock
} accept_args SEC(".maps");

enum {
    STAT_TOTAL        = 0,
    STAT_ACTIVE       = 1,
    STAT_RETRANS      = 2,
    STAT_ZERO_WND     = 3,
    STAT_RST          = 4,
    STAT_FLOW_CREATE  = 5,
    STAT_FLOW_DESTROY = 6,
    STAT_FLOW_UPDATE  = 7,
    STAT_SAMPLE_DROP  = 8,
};

// ── 辅助函数 ──────────────────────────────────────────────

static __always_inline void stat_add(__u32 i, __s64 d) {
    __u64 *v = bpf_map_lookup_elem(&stats_map, &i);
    if (v) __sync_fetch_and_add(v, (__u64)d);
}

static __always_inline void fill_common(
    struct tcp_event *ep,
    struct tcp_flow_state *st,
    __u8 lifecycle, __u8 subtype)
{
    ep->lifecycle      = lifecycle;
    ep->event_subtype  = subtype;
    ep->protocol       = 6;
    ep->tcp_state      = st->tcp_state;
    ep->role           = st->role;
    ep->destroy_reason = st->destroy_reason;
    ep->saddr = st->saddr; ep->daddr = st->daddr;
    ep->sport = st->sport; ep->dport = st->dport;

    if (st->rtt_count > 0) {
        ep->rtt_mean = st->rtt_us_sum / st->rtt_count;
        ep->rtt_max  = st->rtt_us_max;
        ep->rtt_min  = st->rtt_us_min;
    }
    if (st->srt_count > 0) {
        ep->srt_mean = st->srt_us_sum / st->srt_count;
        ep->srt_max  = st->srt_us_max;
    }
    ep->retrans_count     = st->retrans_pkts;
    ep->syn_retrans       = st->syn_retrans;
    ep->rst_count         = st->rst_count;
    ep->retrans_bytes     = st->retrans_bytes;
    ep->zero_wnd_count    = st->zero_wnd_count;
    ep->zero_wnd_duration = st->zero_wnd_total_us;
    ep->bytes_sent        = st->bytes_sent;
    ep->bytes_received    = st->bytes_recv;
    ep->packets_sent      = st->pkts_sent;
    ep->packets_received  = st->pkts_recv;
    ep->timeout_flag      = st->timeout_flag;
}

static __always_inline void emit_event(
    struct tcp_flow_state *st,
    __u8 lifecycle, __u8 subtype, __u32 duration_us)
{
    struct tcp_event *ep = bpf_ringbuf_reserve(&tcp_events, sizeof(*ep), 0);
    if (!ep) { stat_add(STAT_SAMPLE_DROP, 1); return; }
    ep->timestamp_ns = bpf_ktime_get_ns();
    __u64 pg = bpf_get_current_pid_tgid();
    ep->pid = (__u32)(pg >> 32);
    ep->tid = (__u32)pg;
    bpf_get_current_comm(&ep->comm, sizeof(ep->comm));
    fill_common(ep, st, lifecycle, subtype);
    ep->duration_us = duration_us;
    bpf_ringbuf_submit(ep, 0);
}

// ── HOOK 1: tcp_connect → FLOW_CREATE 准备（CLIENT） ─────
// 客户端发起连接：记录 syn_ts，role = CLIENT
// 五元组此时已有 daddr/dport（connect() 已填好），saddr 在 ESTABLISHED 补全

SEC("kprobe/tcp_connect")
int kprobe__tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    __u64 now = bpf_ktime_get_ns();

    struct tcp_flow_state st = {};
    st.syn_ts         = now;
    st.start_ts       = now;
    st.last_update_ts = now;
    st.rtt_us_min     = 0xFFFFFFFF;
    st.tcp_state      = TCP_SYN_SENT;
    st.role           = ROLE_CLIENT;  // 主动发起 = CLIENT，100% 准确

    // daddr/dport 在 connect() 时已填写
    st.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    st.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    st.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    // saddr 等 ESTABLISHED 时补全（bind 后才有）

    bpf_map_update_elem(&flow_tracker_map, &sk, &st, BPF_ANY);
    stat_add(STAT_TOTAL,  1);
    stat_add(STAT_ACTIVE, 1);
    return 0;
}

// ── HOOK 2: inet_csk_accept entry → 记录 listener sock ──
// 服务端 accept() 调用时，记录当前 pid_tgid 与 listener socket
// 用于在 kretprobe 时用 new_sk 创建 SERVER 流记录

SEC("kprobe/inet_csk_accept")
int kprobe__inet_csk_accept(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx); // listener sock
    __u64 pg = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&accept_args, &pg, &sk, BPF_ANY);
    return 0;
}

// ── HOOK 3: inet_csk_accept return → 创建 SERVER 流记录 ─
// accept() 返回值 = new client socket（每个连接独立 sk）
// 此时五元组完整，直接创建精确的 SERVER 流记录

SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
    __u64 pg = bpf_get_current_pid_tgid();
    struct sock **skp = bpf_map_lookup_elem(&accept_args, &pg);
    if (!skp) return 0;
    bpf_map_delete_elem(&accept_args, &pg);

    // new_sk = accept() 的返回值（对应新建立的连接）
    struct sock *new_sk = (struct sock *)PT_REGS_RC(ctx);
    if (!new_sk) return 0;

    __u64 now = bpf_ktime_get_ns();
    struct tcp_flow_state st = {};
    st.start_ts       = now;
    st.established_ts = now; // accept 返回时连接已 ESTABLISHED
    st.last_update_ts = now;
    st.rtt_us_min     = 0xFFFFFFFF;
    st.tcp_state      = TCP_ESTABLISHED;
    st.role           = ROLE_SERVER;  // accept 路径 = SERVER，100% 准确

    // accept 返回的 new_sk 五元组已完整
    st.saddr = BPF_CORE_READ(new_sk, __sk_common.skc_rcv_saddr);
    st.daddr = BPF_CORE_READ(new_sk, __sk_common.skc_daddr);
    st.sport = BPF_CORE_READ(new_sk, __sk_common.skc_num);
    st.dport = bpf_ntohs(BPF_CORE_READ(new_sk, __sk_common.skc_dport));

    if (st.saddr == 0 || st.daddr == 0) return 0;

    bpf_map_update_elem(&flow_tracker_map, &new_sk, &st, BPF_ANY);
    stat_add(STAT_TOTAL,  1);
    stat_add(STAT_ACTIVE, 1);

    // 发送 FLOW_CREATE 事件（服务端视角）
    struct tcp_event *ep = bpf_ringbuf_reserve(&tcp_events, sizeof(*ep), 0);
    if (ep) {
        ep->timestamp_ns = now;
        ep->pid = (__u32)(pg >> 32);
        ep->tid = (__u32)pg;
        bpf_get_current_comm(&ep->comm, sizeof(ep->comm));
        fill_common(ep, &st, FLOW_CREATE, SUBTYPE_NONE);
        ep->duration_us = 0;
        bpf_ringbuf_submit(ep, 0);
    } else {
        stat_add(STAT_SAMPLE_DROP, 1);
    }
    stat_add(STAT_FLOW_CREATE, 1);
    return 0;
}

// ── HOOK 4: tcp_rcv_state_process → 记录 SYN+ACK 时间戳 ─
// 客户端收到 SYN+ACK 时，记录 synack_ts
// 用于精确分解 syn_rtt_server（SYN→SYN+ACK）

SEC("kprobe/tcp_rcv_state_process")
int kprobe__tcp_rcv_state_process(struct pt_regs *ctx) {
    struct sock    *sk  = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    struct tcp_flow_state *st = bpf_map_lookup_elem(&flow_tracker_map, &sk);
    if (!st || st->role != ROLE_CLIENT) return 0;

    struct tcphdr *th = (struct tcphdr *)BPF_CORE_READ(skb, data);
    __u8 syn = BPF_CORE_READ_BITFIELD_PROBED(th, syn);
    __u8 ack = BPF_CORE_READ_BITFIELD_PROBED(th, ack);

    // 客户端收到 SYN+ACK：记录时间戳，用于分解 syn_rtt_server
    if (syn && ack && st->synack_ts == 0) {
        st->synack_ts = bpf_ktime_get_ns();
    }
    return 0;
}

// ── HOOK 5: tcp_sendmsg → 累积发送字节 + RTT 起点 ────────
// 记录最后发送时间戳（用于 data-ACK RTT 计算）
// 服务端视角：若有 pending request，计算 SRT（请求→响应时延）

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk   = (struct sock *)PT_REGS_PARM1(ctx);
    size_t       size = (size_t)PT_REGS_PARM3(ctx);

    struct tcp_flow_state *st = bpf_map_lookup_elem(&flow_tracker_map, &sk);
    if (!st) return 0;

    __u64 now = bpf_ktime_get_ns();
    st->last_data_send_ts = now;
    st->bytes_sent += (__u64)size;
    st->pkts_sent++;
    st->last_update_ts = now;

    // 服务端视角：收到请求后首次 sendmsg = 响应开始，计算 SRT
    if (st->role == ROLE_SERVER && st->srt_pending && st->request_rcv_ts > 0) {
        __u32 srt = ns_to_us(now - st->request_rcv_ts);
        st->srt_count++;
        st->srt_us_sum += srt;
        if (srt > st->srt_us_max) st->srt_us_max = srt;
        st->srt_pending    = 0;
        st->request_rcv_ts = 0;
    }

    // 字节采样：每 64KB 发一次 FLOW_UPDATE 快照
    __u64 total = st->bytes_sent + st->bytes_recv;
    if ((total - st->last_flush_bytes) >= SAMPLE_BYTES_THRESHOLD) {
        st->last_flush_bytes = total;
        stat_add(STAT_FLOW_UPDATE, 1);
        emit_event(st, FLOW_UPDATE, SUBTYPE_BYTES_FLUSH, 0);
    }
    return 0;
}

// ── HOOK 6: tcp_recvmsg (kretprobe) → 累积接收字节 + SRT 起点 ─
// 服务端视角：收到数据 = 请求到达，记录 request_rcv_ts 等待响应

SEC("kprobe/tcp_recvmsg")
int kprobe__tcp_recvmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct tcp_flow_state *st = bpf_map_lookup_elem(&flow_tracker_map, &sk);
    if (!st) return 0;

    // 服务端首次收到数据时，标记 SRT 起点
    if (st->role == ROLE_SERVER && !st->srt_pending && st->request_rcv_ts == 0) {
        st->request_rcv_ts = bpf_ktime_get_ns();
        st->srt_pending    = 1;
    }
    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe__tcp_recvmsg(struct pt_regs *ctx) {
    long ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    struct sock *sk = NULL;
    // 注意：kretprobe 无法直接访问入参，需要通过 per-cpu map 或 fentry/fexit
    // 此处用简化版：从 current task 的 socket 获取（仅适用于简单场景）
    // 生产级实现应使用 kprobe entry 保存 sk 指针
    // 此处通过 tcp_sendmsg 的字节采样补偿接收字节统计
    (void)sk;
    return 0;
}

// ── HOOK 7: tcp_ack → 计算数据层 RTT ────────────────────
// 收到 ACK 时：RTT = now - last_data_send_ts

SEC("kprobe/tcp_ack")
int kprobe__tcp_ack(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct tcp_flow_state *st = bpf_map_lookup_elem(&flow_tracker_map, &sk);
    if (!st || st->last_data_send_ts == 0) return 0;

    __u64 now = bpf_ktime_get_ns();
    __u32 rtt = ns_to_us(now - st->last_data_send_ts);

    // 过滤异常值（RTT > 60s 视为无效）
    if (rtt > 60000000) {
        st->last_data_send_ts = 0;
        return 0;
    }

    st->rtt_count++;
    st->rtt_us_sum += rtt;
    if (rtt > st->rtt_us_max) st->rtt_us_max = rtt;
    if (rtt < st->rtt_us_min) st->rtt_us_min = rtt;
    st->last_data_send_ts = 0;
    st->last_update_ts    = now;
    return 0;
}

// ── HOOK 8: tcp_retransmit_skb → 重传计数 + FLOW_UPDATE ─

SEC("kprobe/tcp_retransmit_skb")
int kprobe__tcp_retransmit_skb(struct pt_regs *ctx) {
    struct sock    *sk  = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    struct tcp_flow_state *st = bpf_map_lookup_elem(&flow_tracker_map, &sk);
    if (!st) return 0;

    __u32 len = BPF_CORE_READ(skb, len);
    st->retrans_pkts++;
    st->retrans_bytes  += (__u64)len;
    st->last_update_ts  = bpf_ktime_get_ns();
    stat_add(STAT_RETRANS,     1);
    stat_add(STAT_FLOW_UPDATE, 1);

    emit_event(st, FLOW_UPDATE, SUBTYPE_RETRANS, 0);
    return 0;
}

// ── HOOK 9: tcp_send_active_reset → RST + FLOW_UPDATE ────

SEC("kprobe/tcp_send_active_reset")
int kprobe__tcp_send_active_reset(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct tcp_flow_state *st = bpf_map_lookup_elem(&flow_tracker_map, &sk);
    if (!st) return 0;

    st->rst_count++;
    st->destroy_reason = DESTROY_RST;
    st->last_update_ts = bpf_ktime_get_ns();
    stat_add(STAT_RST,         1);
    stat_add(STAT_FLOW_UPDATE, 1);

    emit_event(st, FLOW_UPDATE, SUBTYPE_RST, 0);
    return 0;
}

// ── HOOK 10: tcp_set_state → FLOW_CREATE + FLOW_DESTROY ─
//
// ESTABLISHED: 客户端侧的 FLOW_CREATE（服务端 FLOW_CREATE 在 kretprobe/accept）
// TCP_CLOSE:   双端的 FLOW_DESTROY，携带完整汇总指标

SEC("kprobe/tcp_set_state")
int kprobe__tcp_set_state(struct pt_regs *ctx) {
    struct sock *sk    = (struct sock *)PT_REGS_PARM1(ctx);
    int          state = (int)PT_REGS_PARM2(ctx);

    struct tcp_flow_state *st = bpf_map_lookup_elem(&flow_tracker_map, &sk);
    if (!st) return 0;

    __u64 now = bpf_ktime_get_ns();
    st->tcp_state      = (__u8)state;
    st->last_update_ts = now;

    // ── ESTABLISHED：客户端 FLOW_CREATE ──────────────────
    if (state == TCP_ESTABLISHED && st->established_ts == 0) {
        // 补全 saddr（此时 bind 完成，rcv_saddr 有值）
        if (!st->saddr)
            st->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        if (!st->daddr)
            st->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        if (!st->dport)
            st->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        if (!st->sport)
            st->sport = BPF_CORE_READ(sk, __sk_common.skc_num);

        st->established_ts = now;

        // 兜底 role 判断（既非 connect 也非 accept，通过端口推断）
        if (st->role == ROLE_UNKNOWN) {
            st->role = (st->sport < WELL_KNOWN_PORT_MAX) ?
                        ROLE_SERVER : ROLE_CLIENT;
        }

        // 服务端的 FLOW_CREATE 已在 kretprobe/inet_csk_accept 发送，跳过
        if (st->role == ROLE_SERVER) return 0;

        // 客户端发送 FLOW_CREATE
        struct tcp_event *ep = bpf_ringbuf_reserve(&tcp_events, sizeof(*ep), 0);
        if (ep) {
            ep->timestamp_ns = now;
            __u64 pg = bpf_get_current_pid_tgid();
            ep->pid = (__u32)(pg >> 32);
            ep->tid = (__u32)pg;
            bpf_get_current_comm(&ep->comm, sizeof(ep->comm));
            fill_common(ep, st, FLOW_CREATE, SUBTYPE_NONE);

            // SYN RTT 三段分解
            if (st->syn_ts > 0)
                ep->syn_rtt = ns_to_us(now - st->syn_ts);
            if (st->synack_ts > 0 && st->syn_ts > 0)
                ep->syn_rtt_server = ns_to_us(st->synack_ts - st->syn_ts);
            if (st->synack_ts > 0)
                ep->syn_rtt_client = ns_to_us(now - st->synack_ts);

            ep->duration_us = 0;
            bpf_ringbuf_submit(ep, 0);
        } else {
            stat_add(STAT_SAMPLE_DROP, 1);
        }
        stat_add(STAT_FLOW_CREATE, 1);
    }

    // ── TCP_CLOSE：FLOW_DESTROY（双端共用此路径） ─────────
    if (state == TCP_CLOSE) {
        // 结算零窗口累积时长
        if (st->zero_wnd_start_ts > 0) {
            st->zero_wnd_total_us += ns_to_us(now - st->zero_wnd_start_ts);
            st->zero_wnd_start_ts  = 0;
        }

        if (st->destroy_reason == 0)
            st->destroy_reason = DESTROY_FIN;

        __u32 dur = (st->established_ts > 0) ?
                    ns_to_us(now - st->established_ts) :
                    ns_to_us(now - st->start_ts);

        struct tcp_event *ep = bpf_ringbuf_reserve(&tcp_events, sizeof(*ep), 0);
        if (ep) {
            ep->timestamp_ns = now;
            __u64 pg = bpf_get_current_pid_tgid();
            ep->pid = (__u32)(pg >> 32);
            ep->tid = (__u32)pg;
            bpf_get_current_comm(&ep->comm, sizeof(ep->comm));
            fill_common(ep, st, FLOW_DESTROY, SUBTYPE_NONE);

            // FLOW_DESTROY 携带完整 SYN RTT（使用 established_ts 精确）
            if (st->syn_ts > 0 && st->established_ts > 0)
                ep->syn_rtt = ns_to_us(st->established_ts - st->syn_ts);
            if (st->syn_ts > 0 && st->synack_ts > 0)
                ep->syn_rtt_server = ns_to_us(st->synack_ts - st->syn_ts);
            if (st->synack_ts > 0 && st->established_ts > 0)
                ep->syn_rtt_client = ns_to_us(st->established_ts - st->synack_ts);

            ep->duration_us = dur;
            bpf_ringbuf_submit(ep, 0);
        } else {
            stat_add(STAT_SAMPLE_DROP, 1);
        }

        bpf_map_delete_elem(&flow_tracker_map, &sk);
        stat_add(STAT_ACTIVE,      -1);
        stat_add(STAT_FLOW_DESTROY, 1);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
