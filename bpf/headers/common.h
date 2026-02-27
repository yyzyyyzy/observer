// bpf/headers/common.h — 公共头文件

#ifndef __COMMON_H__
#define __COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// ── Flow 生命周期三态 ─────────────────────────────────────
#define FLOW_CREATE   1
#define FLOW_UPDATE   2
#define FLOW_DESTROY  3

// ── 销毁原因 ──────────────────────────────────────────────
#define DESTROY_FIN     1
#define DESTROY_RST     2
#define DESTROY_TIMEOUT 3

// ── 连接角色 ──────────────────────────────────────────────
#define ROLE_UNKNOWN  0
#define ROLE_CLIENT   1
#define ROLE_SERVER   2

// ── 流量方向 ──────────────────────────────────────────────
#define FLOW_DIRECTION_INGRESS  0
#define FLOW_DIRECTION_EGRESS   1

// ── 协议 ─────────────────────────────────────────────────
#define PROTO_TCP  6
#define PROTO_UDP  17

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

// ── TCP 状态 ──────────────────────────────────────────────
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

// ── 以太网/IP ─────────────────────────────────────────────
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_8021Q 0x8100

// ── 其他常量 ──────────────────────────────────────────────
#define MAX_COMM_LEN        16
#define WELL_KNOWN_PORT_MAX 1024

// ── IPv6 地址（128 bit = 2 × u64）────────────────────────
struct ipv6_addr {
    __u64 hi;
    __u64 lo;
};

// ── 辅助：时间单位转换 ────────────────────────────────────
static __always_inline __u32 ns_to_us(__u64 ns) {
    return (__u32)(ns / 1000);
}

static __always_inline __u32 ns_to_ms(__u64 ns) {
    return (__u32)(ns / 1000000);
}

// ── 网络字节序宏 ──────────────────────────────────────────
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

#endif /* __COMMON_H__ */
