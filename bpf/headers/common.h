// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Network Observer Project

#ifndef __NETWORK_OBSERVER_COMMON_H__
#define __NETWORK_OBSERVER_COMMON_H__

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

/*===========================================================================
 * Constants
 *===========================================================================*/

#define MAX_PACKET_SIZE       1500
#define TASK_COMM_LEN         16
#define MAX_CONNECTIONS       10240
#define MAX_FLOWS             10240

/*===========================================================================
 * Enumerations
 *===========================================================================*/

// Flow direction
enum flow_direction {
    FLOW_DIRECTION_INGRESS = 0,
    FLOW_DIRECTION_EGRESS  = 1,
};

// Protocol types
enum protocol_type {
    PROTOCOL_TCP = 6,
    PROTOCOL_UDP = 17,
};

// Connection event types
enum event_type {
    EVENT_TYPE_CONNECT = 1,
    EVENT_TYPE_ACCEPT  = 2,
    EVENT_TYPE_CLOSE   = 3,
    EVENT_TYPE_DATA    = 4,
};

/*===========================================================================
 * Data Structures
 *===========================================================================*/

/**
 * struct tcp_event - TCP connection event
 * @timestamp_ns: Event timestamp in nanoseconds
 * @pid: Process ID
 * @tid: Thread ID
 * @comm: Process command name
 * @saddr: Source IP address (IPv4)
 * @daddr: Destination IP address (IPv4)
 * @sport: Source port
 * @dport: Destination port
 * @event_type: Type of event (connect/accept/close)
 * @direction: Flow direction (ingress/egress)
 * @bytes_sent: Total bytes sent
 * @bytes_received: Total bytes received
 * @duration_ns: Connection duration in nanoseconds
 */
struct tcp_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    char  comm[TASK_COMM_LEN];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  event_type;
    __u8  direction;
    __u8  _padding[2];
    __u64 bytes_sent;
    __u64 bytes_received;
    __u32 duration_ns;
    __u32 _reserved;
} __attribute__((packed));

/**
 * struct udp_event - UDP flow event
 * @timestamp_ns: Event timestamp in nanoseconds
 * @pid: Process ID
 * @tid: Thread ID
 * @comm: Process command name
 * @saddr: Source IP address (IPv4)
 * @daddr: Destination IP address (IPv4)
 * @sport: Source port
 * @dport: Destination port
 * @direction: Flow direction (ingress/egress)
 * @packet_size: Size of the packet
 * @total_bytes: Total bytes transferred
 */
struct udp_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    char  comm[TASK_COMM_LEN];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  direction;
    __u8  _padding[3];
    __u32 packet_size;
    __u64 total_bytes;
} __attribute__((packed));

/**
 * struct tc_packet - Traffic Control packet event
 * @timestamp_ns: Event timestamp in nanoseconds
 * @ifindex: Network interface index
 * @saddr: Source IP address (IPv4)
 * @daddr: Destination IP address (IPv4)
 * @sport: Source port
 * @dport: Destination port
 * @protocol: IP protocol (TCP/UDP)
 * @direction: Flow direction (ingress/egress)
 * @packet_len: Total packet length
 * @tcp_flags: TCP flags (if protocol is TCP)
 */
struct tc_packet {
    __u64 timestamp_ns;
    __u32 ifindex;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u8  direction;
    __u8  tcp_flags;
    __u8  _padding;
    __u32 packet_len;
} __attribute__((packed));

/**
 * struct conn_tuple - Connection 5-tuple for tracking
 * @saddr: Source IP address
 * @daddr: Destination IP address
 * @sport: Source port
 * @dport: Destination port
 * @netns: Network namespace ID
 */
struct conn_tuple {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 netns;
};

/**
 * struct conn_stats - Connection statistics
 * @bytes_sent: Total bytes sent
 * @bytes_received: Total bytes received
 * @packets_sent: Total packets sent
 * @packets_received: Total packets received
 * @start_ts: Connection start timestamp
 * @last_ts: Last activity timestamp
 */
struct conn_stats {
    __u64 bytes_sent;
    __u64 bytes_received;
    __u64 packets_sent;
    __u64 packets_received;
    __u64 start_ts;
    __u64 last_ts;
};

/*===========================================================================
 * Helper Macros
 *===========================================================================*/

//#define barrier() __asm__ __volatile__("" ::: "memory")

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memset
#define memset(dest, val, n) __builtin_memset((dest), (val), (n))
#endif

#endif /* __NETWORK_OBSERVER_COMMON_H__ */
