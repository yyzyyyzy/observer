// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Network Observer Project

//go:build ignore

#include "headers/common.h"
#include <linux/pkt_cls.h>

char LICENSE[] SEC("license") = "GPL";

/*===========================================================================
 * Maps
 *===========================================================================*/

// Ring buffer for TC packet events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} tc_events SEC(".maps");

// Packet counter per interface
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   // ifindex
    __type(value, __u64); // packet count
} tc_packet_count SEC(".maps");

/*===========================================================================
 * Configuration
 *===========================================================================*/

// Sampling rate: emit 1 out of every SAMPLE_RATE packets
#define SAMPLE_RATE 100

/*===========================================================================
 * Helper Functions
 *===========================================================================*/

static __always_inline int submit_tc_packet(void *ctx, struct tc_packet *packet)
{
    struct tc_packet *rb_packet;
    
    rb_packet = bpf_ringbuf_reserve(&tc_events, sizeof(*rb_packet), 0);
    if (!rb_packet) {
        return -1;
    }
    
    memcpy(rb_packet, packet, sizeof(*rb_packet));
    bpf_ringbuf_submit(rb_packet, 0);
    
    return 0;
}

/**
 * process_packet - Process and optionally emit TC packet event
 * @skb: Socket buffer
 * @direction: Flow direction (ingress/egress)
 * 
 * Parses packet headers and emits events based on sampling rate
 * 
 * Returns: TC_ACT_OK to continue processing
 */
static __always_inline int process_packet(struct __sk_buff *skb, __u8 direction)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    // Parse IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;
    
    // Prepare packet event
    struct tc_packet packet = {};
    packet.timestamp_ns = bpf_ktime_get_ns();
    packet.ifindex = skb->ifindex;
    packet.saddr = iph->saddr;
    packet.daddr = iph->daddr;
    packet.protocol = iph->protocol;
    packet.direction = direction;
    packet.packet_len = skb->len;
    
    __u32 ip_hdr_len = iph->ihl * 4;
    
    // Parse transport layer headers
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + ip_hdr_len;
        if ((void *)(tcph + 1) > data_end)
            return TC_ACT_OK;
        
        packet.sport = bpf_ntohs(tcph->source);
        packet.dport = bpf_ntohs(tcph->dest);
        
        // Extract TCP flags (offset 13 from tcph)
        __u8 *flags_byte = (__u8 *)tcph + 13;
        if ((void *)(flags_byte + 1) > data_end)
            return TC_ACT_OK;
        packet.tcp_flags = *flags_byte;
        
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + ip_hdr_len;
        if ((void *)(udph + 1) > data_end)
            return TC_ACT_OK;
        
        packet.sport = bpf_ntohs(udph->source);
        packet.dport = bpf_ntohs(udph->dest);
    }
    
    // Update packet counter
    __u32 ifindex = skb->ifindex;
    __u64 *count = bpf_map_lookup_elem(&tc_packet_count, &ifindex);
    
    if (count) {
        __sync_fetch_and_add(count, 1);
        
        // Sample: emit 1 out of every SAMPLE_RATE packets
        if (*count % SAMPLE_RATE == 0) {
            submit_tc_packet(skb, &packet);
        }
    } else {
        __u64 new_count = 1;
        bpf_map_update_elem(&tc_packet_count, &ifindex, &new_count, BPF_ANY);
    }
    
    return TC_ACT_OK;
}

/*===========================================================================
 * TC Classifiers
 *===========================================================================*/

/**
 * tc_egress - TC egress (outbound) hook
 * @skb: Socket buffer
 * 
 * Captures outbound packets at the TC layer
 * 
 * Returns: TC_ACT_OK
 */
SEC("classifier/egress")
int tc_egress(struct __sk_buff *skb)
{
    return process_packet(skb, FLOW_DIRECTION_EGRESS);
}

/**
 * tc_ingress - TC ingress (inbound) hook
 * @skb: Socket buffer
 * 
 * Captures inbound packets at the TC layer
 * 
 * Returns: TC_ACT_OK
 */
SEC("classifier/ingress")
int tc_ingress(struct __sk_buff *skb)
{
    return process_packet(skb, FLOW_DIRECTION_INGRESS);
}
