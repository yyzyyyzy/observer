// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Network Observer Project

//go:build ignore

#include "headers/common.h"

char LICENSE[] SEC("license") = "GPL";

/*===========================================================================
 * Maps
 *===========================================================================*/

// Ring buffer for UDP events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024); // 128KB ring buffer
} udp_events SEC(".maps");

// Flow tracking map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct conn_tuple);
    __type(value, struct conn_stats);
} udp_flow_stats SEC(".maps");

/*===========================================================================
 * Syscall Tracepoint Structures
 *===========================================================================*/

struct sys_enter_sendto_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    
    int            __syscall_nr;
    int            fd;
    void          *buff;
    unsigned long  len;
    unsigned long  flags;
    void          *addr;
    int            addr_len;
};

struct sys_enter_recvfrom_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    
    int            __syscall_nr;
    int            fd;
    void          *ubuf;
    unsigned long  size;
    unsigned long  flags;
    void          *addr;
    void          *addr_len;
};

/*===========================================================================
 * Helper Functions
 *===========================================================================*/

static __always_inline int submit_udp_event(void *ctx, struct udp_event *event)
{
    struct udp_event *rb_event;
    
    rb_event = bpf_ringbuf_reserve(&udp_events, sizeof(*rb_event), 0);
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
 * handle_sendto_enter - Handle UDP sendto syscall
 * @ctx: Syscall tracepoint context
 * 
 * Tracks outbound UDP packets
 * 
 * Returns: 0
 */
SEC("tp/syscalls/sys_enter_sendto")
int handle_sendto_enter(struct sys_enter_sendto_args *ctx)
{
    struct udp_event event = {};
    
    event.timestamp_ns = bpf_ktime_get_ns();
    event.direction = FLOW_DIRECTION_EGRESS;
    event.packet_size = (__u32)ctx->len;
    
    // Get process information
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = (__u32)pid_tgid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Submit event
    submit_udp_event(ctx, &event);
    
    return 0;
}

/**
 * handle_recvfrom_enter - Handle UDP recvfrom syscall
 * @ctx: Syscall tracepoint context
 * 
 * Tracks inbound UDP packets
 * 
 * Returns: 0
 */
SEC("tp/syscalls/sys_enter_recvfrom")
int handle_recvfrom_enter(struct sys_enter_recvfrom_args *ctx)
{
    struct udp_event event = {};
    
    event.timestamp_ns = bpf_ktime_get_ns();
    event.direction = FLOW_DIRECTION_INGRESS;
    event.packet_size = (__u32)ctx->size;
    
    // Get process information
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = (__u32)pid_tgid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Submit event
    submit_udp_event(ctx, &event);
    
    return 0;
}
