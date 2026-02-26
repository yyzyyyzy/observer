// bpf/headers/common.h
// 公共头文件 — DeepFlow 对齐版
//
// 变更：
//   - 增加 Flow 生命周期三态 (FLOW_CREATE / FLOW_UPDATE / FLOW_DESTROY)
//   - 增加 role 定义 (ROLE_CLIENT / ROLE_SERVER / ROLE_UNKNOWN)
//   - 增加销毁原因 (DESTROY_FIN / DESTROY_RST / DESTROY_TIMEOUT)
//   - 增加采样辅助宏

#ifndef __COMMON_H__
#define __COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// ── Flow 生命周期三态（与 Go FlowLifecycle 对应）──────────
#define FLOW_CREATE   1   // 连接进入 ESTABLISHED：五元组确定，计时开始
#define FLOW_UPDATE   2   // 中间状态变化上报（重传 / 零窗口 / RST 累积）
#define FLOW_DESTROY  3   // 连接终止：FIN 完成 / RST / 超时淘汰

// ── 销毁原因 ───────────────────────────────────────────────
#define DESTROY_FIN     1   // 正常四次挥手
#define DESTROY_RST     2   // RST 强制断开
#define DESTROY_TIMEOUT 3   // 用户态 GC 超时淘汰

// ── role：判断当前主机在连接中的角色 ─────────────────────
#define ROLE_UNKNOWN  0
#define ROLE_CLIENT   1   // 主动发起 tcp_connect
#define ROLE_SERVER   2   // 被动 accept（通过监听端口判断）

// ── 方向（数据流方向） ────────────────────────────────────
#define FLOW_DIRECTION_INGRESS  0
#define FLOW_DIRECTION_EGRESS   1

// ── 协议 ─────────────────────────────────────────────────
#define PROTO_TCP  6
#define PROTO_UDP  17

// POSIX 标准协议/地址族常量（vmlinux.h 通常已包含，此处作为后备）
#ifndef IPPROTO_TCP
#define IPPROTO_TCP  6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP  17
#endif
#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

// ── TCP 状态（与内核一致） ────────────────────────────────
#define TCP_ESTABLISHED  1
#define TCP_SYN_SENT     2
#define TCP_SYN_RECV     3
#define TCP_FIN_WAIT1    4
#define TCP_FIN_WAIT2    5
#define TCP_TIME_WAIT    6
#define TCP_CLOSE        7
#define TCP_CLOSE_WAIT   8
#define TCP_LAST_ACK     9
#define TCP_LISTEN       10
#define TCP_CLOSING      11

// ── 以太网 ───────────────────────────────────────────────
#define ETH_P_IP 0x0800

// ── 进程名最大长度 ────────────────────────────────────────
#define MAX_COMM_LEN 16

// ── Well-known port 阈值（port < 1024 认为是 server 端）──
#define WELL_KNOWN_PORT_MAX 1024

// ── 时间转换辅助函数 ──────────────────────────────────────
static __always_inline __u32 ns_to_us(__u64 ns) {
    return (__u32)(ns / 1000);
}

static __always_inline __u32 ns_to_ms(__u64 ns) {
    return (__u32)(ns / 1000000);
}

// ── 网络字节序 ────────────────────────────────────────────
#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif
#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif
#ifndef bpf_ntohl
#define bpf_ntohl(x) __builtin_bswap32(x)
#endif
#ifndef bpf_htonl
#define bpf_htonl(x) __builtin_bswap32(x)
#endif

// ── 原子统计 Map 更新宏 ───────────────────────────────────
#define UPDATE_STAT(map, index, delta)              \
    do {                                            \
        __u64 *_v = bpf_map_lookup_elem(map, &(index)); \
        if (_v) __sync_fetch_and_add(_v, delta);   \
    } while (0)

// ── role 推断：通过端口判断 client/server ─────────────────
// 规则：发起 tcp_connect 的一侧为 CLIENT；
//       dport < WELL_KNOWN_PORT_MAX 也认为对端是 SERVER。
// 注意：此宏在 tcp_connect hook 中使用（sk 已有 dport）。
static __always_inline __u8 infer_role_from_connect(__u16 dport) {
    // 主动发起连接 → 本端是 CLIENT
    (void)dport;
    return ROLE_CLIENT;
}

static __always_inline __u8 infer_role_from_listen(__u16 sport) {
    // 被动 accept（sport < 1024 或 sport 是已知服务端口）→ SERVER
    if (sport < WELL_KNOWN_PORT_MAX)
        return ROLE_SERVER;
    return ROLE_SERVER; // accept 路径统一是 SERVER
}

#endif /* __COMMON_H__ */
