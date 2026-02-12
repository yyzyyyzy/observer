// bpf/tcp_tracer.c
// DeepFlow 风格 TCP 追踪器
//
// 设计原则（对齐 DeepFlow）：
//   - flow_tracker_map 持续累积全量连接状态
//   - ring buffer 只在关键节点发事件：FLOW_START / FLOW_END / RETRANS / ZERO_WND / RST
//   - tcp_connect 只建 map 条目（还没五元组，saddr 此时为 0）
//   - FLOW_START 在 tcp_set_state → ESTABLISHED 时发出（五元组已完整）
//   - FLOW_END   在 tcp_set_state → TCP_CLOSE   时发出

#include "headers/common.h"

// ── 事件类型 ──────────────────────────────────────────────
#define EVENT_FLOW_START  1   // 连接进入 ESTABLISHED
#define EVENT_FLOW_END    2   // 连接进入 TCP_CLOSE
#define EVENT_RETRANS     3   // 发生重传
#define EVENT_ZERO_WND    4   // 零窗口开始
#define EVENT_RST         5   // 发送 RST

// ── BPF Map 中存储的全量连接状态 ─────────────────────────
struct tcp_flow_state {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;

    __u64 syn_ts;           // SYN 发出（tcp_connect）
    __u64 synack_ts;        // 收到 SYN+ACK
    __u64 established_ts;   // 进入 ESTABLISHED
    __u8  syn_retrans;      // SYN 重传次数

    __u64 last_data_send_ts;
    __u32 rtt_us_sum;
    __u32 rtt_us_max;
    __u32 rtt_us_min;       // 初始化为 0xFFFFFFFF
    __u32 rtt_count;

    __u32 srt_us_sum;
    __u32 srt_us_max;
    __u32 srt_count;

    __u32 retrans_pkts;
    __u64 retrans_bytes;

    __u32 zero_wnd_count;
    __u64 zero_wnd_start_ts;
    __u64 zero_wnd_total_us;

    __u64 bytes_sent;
    __u64 bytes_recv;
    __u64 pkts_sent;
    __u64 pkts_recv;

    __u8  rst_count;
    __u8  timeout_flag;
    __u8  tcp_state;
    __u8  _pad;

    __u64 start_ts;
    __u64 last_update_ts;
};

// ── ring buffer 中的精简事件 ──────────────────────────────
// 字段顺序严格对齐 Go parseTCPEvent 的偏移（见 manager.go）
struct tcp_event {
    // [0:8]   timestamp
    __u64 timestamp_ns;
    // [8:12]  pid
    __u32 pid;
    // [12:16] tid
    __u32 tid;
    // [16:32] comm
    char  comm[16];
    // [32:36] saddr
    __u32 saddr;
    // [36:40] daddr
    __u32 daddr;
    // [40:42] sport
    __u16 sport;
    // [42:44] dport
    __u16 dport;
    // [44]    protocol
    __u8  protocol;
    // [45]    event_type
    __u8  event_type;
    // [46]    direction
    __u8  direction;
    // [47]    pad
    __u8  _pad0;
    // [48:52] syn_rtt
    __u32 syn_rtt;
    // [52:56] syn_rtt_client
    __u32 syn_rtt_client;
    // [56:60] syn_rtt_server
    __u32 syn_rtt_server;
    // [60:64] rtt_mean
    __u32 rtt_mean;
    // [64:68] rtt_max
    __u32 rtt_max;
    // [68:72] rtt_min
    __u32 rtt_min;
    // [72:76] srt_mean
    __u32 srt_mean;
    // [76:80] srt_max
    __u32 srt_max;
    // [80:84] retrans_count
    __u32 retrans_count;
    // [84:88] pad
    __u32 _pad1;
    // [88:96] retrans_bytes
    __u64 retrans_bytes;
    // [96:100] zero_wnd_count
    __u32 zero_wnd_count;
    // [100:104] pad
    __u32 _pad2;
    // [104:112] zero_wnd_duration
    __u64 zero_wnd_duration;
    // [112:120] bytes_sent
    __u64 bytes_sent;
    // [120:128] bytes_received
    __u64 bytes_received;
    // [128:136] packets_sent
    __u64 packets_sent;
    // [136:144] packets_received
    __u64 packets_received;
    // [144] syn_retrans
    __u8  syn_retrans;
    // [145] rst_count
    __u8  rst_count;
    // [146] timeout_flag
    __u8  timeout_flag;
    // [147] tcp_state
    __u8  tcp_state;
    // [148:152] duration_ns (实际存的是 μs)
    __u32 duration_ns;
};
// 总大小 = 152 字节，与 Go minSize=152 完全对齐

// ── Maps ─────────────────────────────────────────────────

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

enum { STAT_TOTAL=0, STAT_ACTIVE=1, STAT_RETRANS=2, STAT_ZERO_WND=3, STAT_RST=4 };

// ── 辅助 ──────────────────────────────────────────────────

static __always_inline void stat_add(__u32 i, __s64 d) {
    __u64 *v = bpf_map_lookup_elem(&stats_map, &i);
    if (v) __sync_fetch_and_add(v, d);
}

static __always_inline void fill_event(
    struct tcp_event *ep,
    struct tcp_flow_state *st,
    __u8 etype)
{
    ep->event_type = etype;
    ep->protocol   = 6;
    ep->tcp_state  = st->tcp_state;
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
    ep->retrans_count    = st->retrans_pkts;
    ep->retrans_bytes    = st->retrans_bytes;
    ep->zero_wnd_count   = st->zero_wnd_count;
    ep->zero_wnd_duration = st->zero_wnd_total_us;
    ep->syn_retrans      = st->syn_retrans;
    ep->rst_count        = st->rst_count;
    ep->bytes_sent       = st->bytes_sent;
    ep->bytes_received   = st->bytes_recv;
    ep->packets_sent     = st->pkts_sent;
    ep->packets_received = st->pkts_recv;
}

// emit_event：用于 RETRANS / ZERO_WND / RST 这种通用事件
static __always_inline void emit_event(
    struct tcp_flow_state *st,
    __u8 etype)
{
    struct tcp_event *ep = bpf_ringbuf_reserve(&tcp_events, sizeof(*ep), 0);
    if (!ep) return;

    ep->timestamp_ns = bpf_ktime_get_ns();
    __u64 pg = bpf_get_current_pid_tgid();
    ep->pid = (__u32)(pg >> 32);
    ep->tid = (__u32)pg;
    bpf_get_current_comm(&ep->comm, sizeof(ep->comm));
    fill_event(ep, st, etype);
    bpf_ringbuf_submit(ep, 0);
}

// ── HOOK: tcp_connect ─────────────────────────────────────
// 客户端发起连接：此时五元组尚未完整（saddr=0），只建 map 条目。
// 五元组将在 tcp_set_state → ESTABLISHED 时填充。

SEC("kprobe/tcp_connect")
int kprobe__tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    struct tcp_flow_state st = {};
    st.syn_ts         = bpf_ktime_get_ns();
    st.start_ts       = st.syn_ts;
    st.last_update_ts = st.syn_ts;
    st.rtt_us_min     = 0xFFFFFFFF;
    st.tcp_state      = TCP_SYN_SENT;

    // tcp_connect 时 skc_rcv_saddr 可能还是 0（路由选择后才确定）
    // 先存 daddr/dport，完整五元组等 ESTABLISHED 后再补
    st.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    st.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    st.sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    bpf_map_update_elem(&flow_tracker_map, &sk, &st, BPF_ANY);
    stat_add(STAT_TOTAL, 1);
    stat_add(STAT_ACTIVE, 1);
    return 0;
}

// ── HOOK: tcp_rcv_state_process ───────────────────────────
// 跟踪握手：记录 SYN+ACK 时间

SEC("kprobe/tcp_rcv_state_process")
int kprobe__tcp_rcv_state_process(struct pt_regs *ctx) {
    struct sock    *sk  = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    struct tcp_flow_state *st = bpf_map_lookup_elem(&flow_tracker_map, &sk);
    if (!st) return 0;

    struct tcphdr *th = (struct tcphdr *)BPF_CORE_READ(skb, data);
    __u8 syn = BPF_CORE_READ_BITFIELD_PROBED(th, syn);
    __u8 ack = BPF_CORE_READ_BITFIELD_PROBED(th, ack);

    if (syn && ack && st->synack_ts == 0)
        st->synack_ts = bpf_ktime_get_ns();

    return 0;
}

// ── HOOK: tcp_sendmsg ─────────────────────────────────────

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk   = (struct sock *)PT_REGS_PARM1(ctx);
    size_t       size = (size_t)PT_REGS_PARM3(ctx);

    struct tcp_flow_state *st = bpf_map_lookup_elem(&flow_tracker_map, &sk);
    if (!st) return 0;

    __u64 now = bpf_ktime_get_ns();
    st->last_data_send_ts = now;
    st->bytes_sent += size;
    st->pkts_sent++;
    st->last_update_ts = now;
    return 0;
}

// ── HOOK: tcp_ack ─────────────────────────────────────────

SEC("kprobe/tcp_ack")
int kprobe__tcp_ack(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    struct tcp_flow_state *st = bpf_map_lookup_elem(&flow_tracker_map, &sk);
    if (!st || st->last_data_send_ts == 0) return 0;

    __u64 now = bpf_ktime_get_ns();
    __u32 rtt = ns_to_us(now - st->last_data_send_ts);
    st->rtt_count++;
    st->rtt_us_sum += rtt;
    if (rtt > st->rtt_us_max) st->rtt_us_max = rtt;
    if (rtt < st->rtt_us_min) st->rtt_us_min = rtt;
    st->last_data_send_ts = 0;
    st->last_update_ts    = now;
    return 0;
}

// ── HOOK: tcp_retransmit_skb → 发 RETRANS 事件 ────────────

SEC("kprobe/tcp_retransmit_skb")
int kprobe__tcp_retransmit_skb(struct pt_regs *ctx) {
    struct sock    *sk  = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    struct tcp_flow_state *st = bpf_map_lookup_elem(&flow_tracker_map, &sk);
    if (!st) return 0;

    __u32 len = BPF_CORE_READ(skb, len);
    st->retrans_pkts++;
    st->retrans_bytes  += len;
    st->last_update_ts  = bpf_ktime_get_ns();
    stat_add(STAT_RETRANS, 1);

    emit_event(st, EVENT_RETRANS);
    return 0;
}

// ── HOOK: tcp_send_active_reset → 发 RST 事件 ────────────

SEC("kprobe/tcp_send_active_reset")
int kprobe__tcp_send_active_reset(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    struct tcp_flow_state *st = bpf_map_lookup_elem(&flow_tracker_map, &sk);
    if (!st) return 0;

    st->rst_count++;
    st->last_update_ts = bpf_ktime_get_ns();
    stat_add(STAT_RST, 1);

    emit_event(st, EVENT_RST);
    return 0;
}

// ── HOOK: tcp_set_state → FLOW_START + FLOW_END ───────────
// 这是最关键的 hook：
//   → ESTABLISHED: 补全五元组，发 FLOW_START
//   → TCP_CLOSE:   汇总指标，发 FLOW_END，清理 map

SEC("kprobe/tcp_set_state")
int kprobe__tcp_set_state(struct pt_regs *ctx) {
    struct sock *sk    = (struct sock *)PT_REGS_PARM1(ctx);
    int          state = (int)PT_REGS_PARM2(ctx);

    struct tcp_flow_state *st = bpf_map_lookup_elem(&flow_tracker_map, &sk);
    if (!st) return 0;

    __u64 now = bpf_ktime_get_ns();
    st->tcp_state      = (__u8)state;
    st->last_update_ts = now;

    if (state == TCP_ESTABLISHED && st->established_ts == 0) {
        // 补全五元组（此时 skc_rcv_saddr 已有值）
        st->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        if (st->daddr == 0)
            st->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        if (st->dport == 0)
            st->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        if (st->sport == 0)
            st->sport = BPF_CORE_READ(sk, __sk_common.skc_num);

        st->established_ts = now;

        // 发 FLOW_START 事件
        struct tcp_event *ep = bpf_ringbuf_reserve(&tcp_events, sizeof(*ep), 0);
        if (ep) {
            ep->timestamp_ns = now;
            __u64 pg = bpf_get_current_pid_tgid();
            ep->pid = (__u32)(pg >> 32);
            ep->tid = (__u32)pg;
            bpf_get_current_comm(&ep->comm, sizeof(ep->comm));

            fill_event(ep, st, EVENT_FLOW_START);

            // 建连时延
            if (st->syn_ts > 0)
                ep->syn_rtt = ns_to_us(now - st->syn_ts);
            if (st->synack_ts > 0 && st->syn_ts > 0)
                ep->syn_rtt_server = ns_to_us(st->synack_ts - st->syn_ts);
            if (st->synack_ts > 0)
                ep->syn_rtt_client = ns_to_us(now - st->synack_ts);

            bpf_ringbuf_submit(ep, 0);
        }
    }

    if (state == TCP_CLOSE) {
        // 结算零窗口
        if (st->zero_wnd_start_ts > 0) {
            st->zero_wnd_total_us += ns_to_us(now - st->zero_wnd_start_ts);
            st->zero_wnd_start_ts  = 0;
        }

        // 发 FLOW_END 事件
        struct tcp_event *ep = bpf_ringbuf_reserve(&tcp_events, sizeof(*ep), 0);
        if (ep) {
            ep->timestamp_ns = now;
            __u64 pg = bpf_get_current_pid_tgid();
            ep->pid = (__u32)(pg >> 32);
            ep->tid = (__u32)pg;
            bpf_get_current_comm(&ep->comm, sizeof(ep->comm));

            fill_event(ep, st, EVENT_FLOW_END);

            if (st->syn_ts > 0 && st->established_ts > 0)
                ep->syn_rtt = ns_to_us(st->established_ts - st->syn_ts);
            if (st->syn_ts > 0 && st->synack_ts > 0)
                ep->syn_rtt_server = ns_to_us(st->synack_ts - st->syn_ts);
            if (st->synack_ts > 0 && st->established_ts > 0)
                ep->syn_rtt_client = ns_to_us(st->established_ts - st->synack_ts);

            ep->duration_ns = ns_to_us(now - st->start_ts);
            bpf_ringbuf_submit(ep, 0);
        }

        bpf_map_delete_elem(&flow_tracker_map, &sk);
        stat_add(STAT_ACTIVE, -1);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
