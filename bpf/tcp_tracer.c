// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Network Observer Project

//go:build ignore

#include "headers/common.h"

char LICENSE[] SEC("license") = "GPL";

/*===========================================================================
 * Maps
 *===========================================================================*/

// Ring buffer for TCP events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} tcp_events SEC(".maps");

// Connection tracking map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, struct conn_tuple);
    __type(value, struct conn_stats);
} tcp_conn_stats SEC(".maps");

/*===========================================================================
 * Tracepoint Structures
 *===========================================================================*/

/**
 * struct inet_sock_set_state_args - inet_sock_set_state tracepoint args
 * 
 * Kernel tracepoint: /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format
 */
struct inet_sock_set_state_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    
    const void    *skaddr;
    int            oldstate;
    int            newstate;
    __u16          sport;
    __u16          dport;
    __u16          family;
    __u16          protocol;
    __u8           saddr[4];
    __u8           daddr[4];
    __u8           saddr_v6[16];
    __u8           daddr_v6[16];
};

/*===========================================================================
 * Helper Functions
 *===========================================================================*/

/**
 * submit_tcp_event - Submit TCP event to ring buffer
 * @ctx: Tracepoint context
 * @event: Event to submit
 * 
 * Returns: 0 on success, negative on error
 */
static __always_inline int submit_tcp_event(void *ctx, struct tcp_event *event)
{
    struct tcp_event *rb_event;
    
    rb_event = bpf_ringbuf_reserve(&tcp_events, sizeof(*rb_event), 0);
    if (!rb_event) {
        return -1;
    }
    
    memcpy(rb_event, event, sizeof(*rb_event));
    bpf_ringbuf_submit(rb_event, 0);
    
    return 0;
}

/*===========================================================================
 * Tracepoint Handlers
 *===========================================================================*/

/**
 * handle_inet_sock_set_state - Handle TCP state change events
 * @ctx: Tracepoint context
 * 
 * Monitors TCP connection state transitions:
 * - TCP_ESTABLISHED (1): Connection established
 * - TCP_CLOSE (7): Connection closed
 * 
 * Returns: 0
 */
SEC("tp/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct inet_sock_set_state_args *ctx)
{
    // Only process TCP protocol
    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    int oldstate = ctx->oldstate;
    int newstate = ctx->newstate;
    
    struct tcp_event event = {};
    event.timestamp_ns = bpf_ktime_get_ns();
    
    // Get process information
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = (__u32)pid_tgid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Copy connection 4-tuple
    memcpy(&event.saddr, ctx->saddr, 4);
    memcpy(&event.daddr, ctx->daddr, 4);
    event.sport = ctx->sport;
    event.dport = ctx->dport;
    
    // Handle connection establishment (-> TCP_ESTABLISHED)
    if (newstate == 1 && oldstate != 1) {
        event.event_type = EVENT_TYPE_CONNECT;
        event.direction = FLOW_DIRECTION_EGRESS;
        
        submit_tcp_event(ctx, &event);
        
        // Initialize connection stats
        struct conn_tuple tuple = {};
        memcpy(&tuple.saddr, ctx->saddr, 4);
        memcpy(&tuple.daddr, ctx->daddr, 4);
        tuple.sport = ctx->sport;
        tuple.dport = ctx->dport;
        tuple.netns = 0; // TODO: Get actual netns
        
        struct conn_stats stats = {};
        stats.start_ts = event.timestamp_ns;
        stats.last_ts = event.timestamp_ns;
        
        bpf_map_update_elem(&tcp_conn_stats, &tuple, &stats, BPF_NOEXIST);
    }
    
    // Handle connection close (-> TCP_CLOSE)
    if (newstate == 7) {
        event.event_type = EVENT_TYPE_CLOSE;
        
        // Retrieve connection stats
        struct conn_tuple tuple = {};
        memcpy(&tuple.saddr, ctx->saddr, 4);
        memcpy(&tuple.daddr, ctx->daddr, 4);
        tuple.sport = ctx->sport;
        tuple.dport = ctx->dport;
        tuple.netns = 0;
        
        struct conn_stats *stats = bpf_map_lookup_elem(&tcp_conn_stats, &tuple);
        if (stats) {
            event.bytes_sent = stats->bytes_sent;
            event.bytes_received = stats->bytes_received;
            
            __u64 duration = event.timestamp_ns - stats->start_ts;
            if (duration < 0xFFFFFFFF) {
                event.duration_ns = (__u32)duration;
            }
            
            bpf_map_delete_elem(&tcp_conn_stats, &tuple);
        }
        
        submit_tcp_event(ctx, &event);
    }
    
    return 0;
}
