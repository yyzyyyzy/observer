// bpf/udp_tracer.c
// UDP 流追踪器 —— 深度对齐 DeepFlow v6
//
// DeepFlow UDP 设计要点（全面对齐）：
//
//  1. 流定义：与 TCP 一致用 <五元组+PID> 聚合，超时判断生命周期
//     - 无 ESTABLISHED，通过 idle timeout（用户态 GC）判断流结束
//     - 对应 DeepFlow udp_flow_log 写入 l4_flow_log（protocol=17）
//
//  2. 角色判断（DeepFlow UDP role 对齐）：
//     - sendmsg 路径：dst_port < 1024 或已知服务端口 → ROLE_CLIENT
//     - 服务端口（53/123/161/514 等）在本端 → ROLE_SERVER
//     - 规则：目的端口 < 1024 = 本端是 CLIENT（对方是服务）
//
//  3. FlowKey 规范化（DeepFlow 方向规范化）：
//     - 始终以 CLIENT 为 src（normalize_key）
//     - 同一流的 sendmsg/recvmsg 可以通过相同 key 聚合
//
//  4. 真实接收包大小（DeepFlow 准确性要求）：
//     - kprobe/udp_recvmsg: 保存 sock 指针
//     - kretprobe/udp_recvmsg: 用返回值（实际接收字节数），非 buffer size
//
//  5. 未 connect 的 UDP socket 处理：
//     - DNS server、syslog 等：recvfrom 时 skc_daddr=0
//     - 通过 msghdr->msg_name 读取对端地址（需 BPF_CORE_READ 安全访问）
//     - 简化版：daddr=0 的流仍记录，服务端 port 有值即可
//
//  6. 字节采样（对齐 DeepFlow 64KB 阈值）：
//     - NEW 事件始终发送
//     - UPDATE 仅在累积字节超过 SAMPLE_BYTES_THRESHOLD 时发
//     - 防止 DNS 查询等小包高频刷爆 ring buffer
//
//  7. 事件类型：
//     - UDP_FLOW_NEW:    首次看到该五元组
//     - UDP_FLOW_UPDATE: 字节采样触发的快照（中间状态）
//     - 流结束（DESTROY）完全由用户态 GC 完成（类 DeepFlow udp timeout）
//
//  8. 内存布局：BPF struct udp_flow_event = Go UDPFlowEvent，88 bytes

#include "headers/common.h"

// ── 事件类型 ──────────────────────────────────────────────
#define UDP_FLOW_NEW    1
#define UDP_FLOW_UPDATE 2

// 字节采样阈值（对齐 DeepFlow 64KB）
#define UDP_SAMPLE_BYTES (64 * 1024)

// ── 已知服务端口（DeepFlow UDP 角色判断规则） ────────────
// 目的端口命中 → 本端为 CLIENT，对端为 SERVER
static __always_inline __u8 is_server_port(__u16 port) {
    switch (port) {
    case 53:   // DNS
    case 67:   // DHCP server
    case 68:   // DHCP client（对端视角是 server）
    case 69:   // TFTP
    case 123:  // NTP
    case 137:  // NetBIOS
    case 161:  // SNMP
    case 162:  // SNMP trap
    case 514:  // syslog
    case 4789: // VXLAN
    case 8472: // Flannel VXLAN
    case 51820:// WireGuard
        return 1;
    default:
        return (port < 1024) ? 1 : 0;
    }
}

// ── BPF Maps ──────────────────────────────────────────────

// UDP 流聚合 Map（LRU，BPF 侧自动驱逐最久未访问的流）
struct udp_flow_key {
    __u32 saddr;    // 规范化：CLIENT IP
    __u32 daddr;    // 规范化：SERVER IP（0 = 未 connect）
    __u16 sport;    // 规范化：CLIENT port
    __u16 dport;    // 规范化：SERVER port
    __u32 pid;
    __u8  _pad[4];
};

struct udp_flow_state {
    __u64 bytes_sent;
    __u64 bytes_recv;
    __u64 pkts_sent;
    __u64 pkts_recv;
    __u64 first_ts;
    __u64 last_ts;
    __u64 last_flush_bytes;
    __u8  role;
    __u8  event_sent;       // 是否已发过 UDP_FLOW_NEW
    __u8  _pad[6];
};

struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct udp_flow_key);
    __type(value, struct udp_flow_state);
} udp_flow_map SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} udp_events SEC(".maps");

// kprobe entry 保存 sock 指针（供 kretprobe/udp_recvmsg 使用）
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,         __u64);       // pid_tgid
    __type(value,       struct sock *);
} recvmsg_args SEC(".maps");

// ── UDP 流事件（88 bytes，与 Go UDPFlowEvent 精确对齐）────
//
// [0:8]    TimestampNs
// [8:12]   PID
// [12:16]  TID
// [16:32]  Comm[16]
// [32:36]  SAddr       规范化 CLIENT IP
// [36:40]  DAddr       规范化 SERVER IP
// [40:42]  SPort       规范化 CLIENT port
// [42:44]  DPort       规范化 SERVER port
// [44]     Direction   0=ingress 1=egress（本端视角）
// [45]     Role        1=CLIENT 2=SERVER
// [46]     EventType   1=NEW 2=UPDATE
// [47]     _pad
// [48:52]  PacketSize  本次真实包大小
// [52:56]  _pad2
// [56:64]  TotalBytes  bytes_sent + bytes_recv
// [64:72]  BytesSent   累积发送
// [72:80]  BytesRecv   累积接收
// [80:88]  DurationNs  自 first_ts 起的持续时间
struct udp_flow_event {
    __u64 timestamp_ns; // [0:8]
    __u32 pid;          // [8:12]
    __u32 tid;          // [12:16]
    __u8  comm[16];     // [16:32]
    __u32 saddr;        // [32:36]
    __u32 daddr;        // [36:40]
    __u16 sport;        // [40:42]
    __u16 dport;        // [42:44]
    __u8  direction;    // [44]
    __u8  role;         // [45]
    __u8  event_type;   // [46]
    __u8  _pad;         // [47]
    __u32 packet_size;  // [48:52]
    __u32 _pad2;        // [52:56]
    __u64 total_bytes;  // [56:64]
    __u64 bytes_sent;   // [64:72]
    __u64 bytes_recv;   // [72:80]
    __u64 duration_ns;  // [80:88]
};

// ── Helper：角色 + FlowKey 规范化 ────────────────────────
//
// DeepFlow 规范：CLIENT 的 sport > dport（通常临时端口），SERVER 的 dport 为服务端口
// normalize 后：saddr/sport = CLIENT，daddr/dport = SERVER

static __always_inline void normalize_key(
    struct udp_flow_key *key,
    __u32 saddr, __u32 daddr,
    __u16 sport, __u16 dport,
    __u32 pid, __u8 *out_role,
    __u8 is_send) // 1=sendmsg 0=recvmsg
{
    __u8 role;

    if (is_send) {
        // sendmsg：本端是发送方
        // 若目的端口是服务端口 → 本端是 CLIENT
        if (is_server_port(dport)) {
            role = ROLE_CLIENT;
            key->saddr = saddr; key->daddr = daddr;
            key->sport = sport; key->dport = dport;
        } else if (is_server_port(sport)) {
            // 本端是服务端口 → 本端是 SERVER（主动发响应）
            role = ROLE_SERVER;
            key->saddr = daddr; key->daddr = saddr;
            key->sport = dport; key->dport = sport;
        } else {
            // 无法确定：源端口更高 = 临时端口 = CLIENT
            role = (sport > dport) ? ROLE_CLIENT : ROLE_SERVER;
            if (role == ROLE_CLIENT) {
                key->saddr = saddr; key->daddr = daddr;
                key->sport = sport; key->dport = dport;
            } else {
                key->saddr = daddr; key->daddr = saddr;
                key->sport = dport; key->dport = sport;
            }
        }
    } else {
        // recvmsg：本端是接收方，角色与 sendmsg 对称
        if (is_server_port(sport)) {
            // 本端 sport 是服务端口 → 本端是 SERVER（收到客户端请求）
            role = ROLE_SERVER;
            key->saddr = daddr; key->daddr = saddr;
            key->sport = dport; key->dport = sport;
        } else if (is_server_port(dport)) {
            // 对端 dport 是服务端口 → 本端是 CLIENT（收到服务端响应）
            role = ROLE_CLIENT;
            key->saddr = saddr; key->daddr = daddr;
            key->sport = sport; key->dport = dport;
        } else {
            role = (dport > sport) ? ROLE_CLIENT : ROLE_SERVER;
            if (role == ROLE_CLIENT) {
                key->saddr = saddr; key->daddr = daddr;
                key->sport = sport; key->dport = dport;
            } else {
                key->saddr = daddr; key->daddr = saddr;
                key->sport = dport; key->dport = sport;
            }
        }
    }

    key->pid = pid;
    *out_role = role;
}

// ── Helper：发送 ring buffer 事件 ────────────────────────

static __always_inline void emit_udp_event(
    struct udp_flow_state *st,
    __u32 saddr, __u32 daddr,
    __u16 sport, __u16 dport,
    __u32 pid, __u32 packet_size,
    __u8 direction, __u8 role, __u8 event_type,
    __u64 now)
{
    struct udp_flow_event *ev = bpf_ringbuf_reserve(&udp_events, sizeof(*ev), 0);
    if (!ev) return;

    __u64 pg = bpf_get_current_pid_tgid();
    ev->timestamp_ns = now;
    ev->pid          = pid;
    ev->tid          = (__u32)pg;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    ev->saddr        = saddr;
    ev->daddr        = daddr;
    ev->sport        = sport;
    ev->dport        = dport;
    ev->direction    = direction;
    ev->role         = role;
    ev->event_type   = event_type;
    ev->packet_size  = packet_size;
    ev->total_bytes  = st->bytes_sent + st->bytes_recv;
    ev->bytes_sent   = st->bytes_sent;
    ev->bytes_recv   = st->bytes_recv;
    ev->duration_ns  = (st->first_ts > 0) ? (now - st->first_ts) : 0;
    bpf_ringbuf_submit(ev, 0);
}

// ── 发送路径：udp_sendmsg ─────────────────────────────────

SEC("kprobe/udp_sendmsg")
int kprobe__udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    size_t len      = (size_t)PT_REGS_PARM3(ctx);
    __u64  now      = bpf_ktime_get_ns();
    __u64  pg       = bpf_get_current_pid_tgid();
    __u32  pid      = (__u32)(pg >> 32);

    __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (saddr == 0) return 0; // 未 bind 的发送，跳过

    __u8 role = ROLE_UNKNOWN;
    struct udp_flow_key key = {};
    normalize_key(&key, saddr, daddr, sport, dport, pid, &role, 1);

    struct udp_flow_state *st = bpf_map_lookup_elem(&udp_flow_map, &key);
    __u8 event_type = UDP_FLOW_UPDATE;

    if (!st) {
        struct udp_flow_state ns = {
            .bytes_sent = (__u64)len,
            .pkts_sent  = 1,
            .first_ts   = now,
            .last_ts    = now,
            .role       = role,
        };
        bpf_map_update_elem(&udp_flow_map, &key, &ns, BPF_NOEXIST);
        st = bpf_map_lookup_elem(&udp_flow_map, &key);
        if (!st) return 0;
        event_type = UDP_FLOW_NEW;
    } else {
        __sync_fetch_and_add(&st->bytes_sent, (__u64)len);
        __sync_fetch_and_add(&st->pkts_sent, 1);
        st->last_ts = now;
    }

    __u64 total = st->bytes_sent + st->bytes_recv;
    if (event_type == UDP_FLOW_NEW ||
        (total - st->last_flush_bytes) >= UDP_SAMPLE_BYTES) {
        st->last_flush_bytes = total;
        emit_udp_event(st, key.saddr, key.daddr, key.sport, key.dport,
                       pid, (__u32)len, FLOW_DIRECTION_EGRESS,
                       role, event_type, now);
    }
    return 0;
}

// ── 接收路径 entry：保存 sock 指针 ────────────────────────

SEC("kprobe/udp_recvmsg")
int kprobe__udp_recvmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    __u64 pg = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&recvmsg_args, &pg, &sk, BPF_ANY);
    return 0;
}

// ── 接收路径 return：用 kretprobe 返回值获取真实接收大小 ─
//
// 为什么必须用 kretprobe：
//   kprobe entry 的 PARM3 是用户提供的 buffer size（上限），
//   实际接收到的字节数只有内核完成 copy 后才知道 = kretprobe 返回值
//   例如 DNS 查询：buffer=4096，实际响应可能只有 60 bytes
//   用 buffer size 会严重高估流量统计，与 DeepFlow 指标不符

SEC("kretprobe/udp_recvmsg")
int kretprobe__udp_recvmsg(struct pt_regs *ctx) {
    long ret = PT_REGS_RC(ctx);
    __u64 pg  = bpf_get_current_pid_tgid();

    // 无论成功与否，清理 recvmsg_args
    struct sock **skp = bpf_map_lookup_elem(&recvmsg_args, &pg);
    if (!skp) return 0;
    struct sock *sk = *skp;
    bpf_map_delete_elem(&recvmsg_args, &pg);

    if (ret <= 0) return 0; // 错误或 0 字节，跳过

    __u32 pid = (__u32)(pg >> 32);
    __u64 now = bpf_ktime_get_ns();
    __u32 len = (__u32)ret; // 真实接收字节数

    __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (saddr == 0) return 0;

    __u8 role = ROLE_UNKNOWN;
    struct udp_flow_key key = {};
    normalize_key(&key, saddr, daddr, sport, dport, pid, &role, 0);

    struct udp_flow_state *st = bpf_map_lookup_elem(&udp_flow_map, &key);
    __u8 event_type = UDP_FLOW_UPDATE;

    if (!st) {
        struct udp_flow_state ns = {
            .bytes_recv = (__u64)len,
            .pkts_recv  = 1,
            .first_ts   = now,
            .last_ts    = now,
            .role       = role,
        };
        bpf_map_update_elem(&udp_flow_map, &key, &ns, BPF_NOEXIST);
        st = bpf_map_lookup_elem(&udp_flow_map, &key);
        if (!st) return 0;
        event_type = UDP_FLOW_NEW;
    } else {
        __sync_fetch_and_add(&st->bytes_recv, (__u64)len);
        __sync_fetch_and_add(&st->pkts_recv, 1);
        st->last_ts = now;
    }

    __u64 total = st->bytes_sent + st->bytes_recv;
    if (event_type == UDP_FLOW_NEW ||
        (total - st->last_flush_bytes) >= UDP_SAMPLE_BYTES) {
        st->last_flush_bytes = total;
        emit_udp_event(st, key.saddr, key.daddr, key.sport, key.dport,
                       pid, len, FLOW_DIRECTION_INGRESS,
                       role, event_type, now);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
