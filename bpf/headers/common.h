// bpf/headers/common.h
// 公共头文件和宏定义

#ifndef __COMMON_H__
#define __COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// 事件类型
#define EVENT_TYPE_CONNECT  1
#define EVENT_TYPE_ACCEPT   2
#define EVENT_TYPE_CLOSE    3
#define EVENT_TYPE_DATA     4

// 方向
#define FLOW_DIRECTION_INGRESS  0
#define FLOW_DIRECTION_EGRESS   1

// 协议
#define PROTO_TCP  6
#define PROTO_UDP  17

// TCP 状态
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

#define ETH_P_IP	0x0800

// 辅助宏
#define MAX_COMM_LEN 16

// 时间转换
static __always_inline __u32 ns_to_us(__u64 ns) {
    return (__u32)(ns / 1000);
}

static __always_inline __u32 ns_to_ms(__u64 ns) {
    return (__u32)(ns / 1000000);
}

// 网络字节序转换
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

// 统计更新宏
#define UPDATE_STAT(map, index, delta)             \
    do {                                           \
        __u64 *val = bpf_map_lookup_elem(map, &index); \
        if (val) {                                 \
            __sync_fetch_and_add(val, delta);      \
        }                                          \
    } while(0)

#endif /* __COMMON_H__ */
