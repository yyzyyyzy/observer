// pkg/flow/udp_cache.go
// UDP Flow Cache — 五元组流聚合，超时后写入 l4_flow_log。

package flow

import (
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	log "github.com/sirupsen/logrus"

	"observer/pkg/cloudmeta"
	"observer/pkg/ebpf"
	"observer/pkg/storage"
)

type udpEntry struct {
	flow     *ebpf.UDPFlow
	lastSeen time.Time
}

// UDPCache UDP 流聚合缓存，按五元组+PID 聚合，idle 超时后写入 l4_flow_log。
type UDPCache struct {
	cfg          CacheConfig
	lrc          *lru.Cache[ebpf.FlowKey, *udpEntry]
	store        *storage.ClickHouseClient
	metaProvider cloudmeta.MetaProvider
}

func NewUDPCache(cfg CacheConfig, store *storage.ClickHouseClient, meta cloudmeta.MetaProvider) *UDPCache {
	if meta == nil {
		meta = &cloudmeta.NoopMetaProvider{}
	}
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = 65536
	}
	if cfg.FlowTTL <= 0 {
		cfg.FlowTTL = 2 * time.Minute
	}

	c := &UDPCache{cfg: cfg, store: store, metaProvider: meta}
	c.lrc, _ = lru.NewWithEvict[ebpf.FlowKey, *udpEntry](cfg.MaxFlows, func(_ ebpf.FlowKey, e *udpEntry) {
		c.persistL4(e.flow, time.Now())
	})
	return c
}

func (c *UDPCache) HandleUDPEvent(ev *ebpf.UDPFlowEvent) {
	role := ebpf.FlowRole(ev.Role)
	key := ebpf.NewFlowKey(ev.SAddr, ev.DAddr, ev.SPort, ev.DPort, 17, role)
	now := time.Now()

	if e, ok := c.lrc.Get(key); ok {
		e.flow.BytesSent = ev.BytesSent
		e.flow.BytesRecv = ev.BytesRecv
		// PktsSent/PktsRecv 由上层维护（BPF 侧当前未单独统计包数）
		e.lastSeen = now
		return
	}

	srcIP := ebpf.Uint32ToIP(ev.SAddr)
	dstIP := ebpf.Uint32ToIP(ev.DAddr)
	f := &ebpf.UDPFlow{
		Key:         key,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     ev.SPort,
		DstPort:     ev.DPort,
		Role:        role,
		ProcessName: ebpf.ParseCommField(ev.Comm),
		PID:         ev.PID,
		StartTime:   now,
		LastSeen:    now,
		BytesSent:   ev.BytesSent,
		BytesRecv:   ev.BytesRecv,
	}
	if tag := c.metaProvider.GetTag(srcIP); tag != nil {
		f.CloudTag = tag
	} else if tag := c.metaProvider.GetTag(dstIP); tag != nil {
		f.CloudTag = tag
	}
	c.lrc.Add(key, &udpEntry{flow: f, lastSeen: now})
}

// RunGC 清理 idle 超时 UDP 流，写入 l4_flow_log（close_type=TIMEOUT）。
func (c *UDPCache) RunGC() int {
	now := time.Now()
	var expired []ebpf.FlowKey
	for _, key := range c.lrc.Keys() {
		if e, ok := c.lrc.Peek(key); ok && now.Sub(e.lastSeen) > c.cfg.FlowTTL {
			expired = append(expired, key)
		}
	}
	for _, key := range expired {
		if e, ok := c.lrc.Peek(key); ok {
			c.persistL4(e.flow, now)
		}
		c.lrc.Remove(key)
	}
	if len(expired) > 0 {
		log.WithField("count", len(expired)).Debug("UDP flow GC")
	}
	return len(expired)
}

func (c *UDPCache) persistL4(f *ebpf.UDPFlow, now time.Time) {
	if c.store == nil {
		return
	}
	row := storage.L4FlowLog{
		StartTime:  f.StartTime,
		EndTime:    now,
		DurationUs: uint64(now.Sub(f.StartTime).Microseconds()),

		SrcIP:    storage.SafeIPv4(f.SrcIP),
		DstIP:    storage.SafeIPv4(f.DstIP),
		SrcPort:  f.SrcPort,
		DstPort:  f.DstPort,
		Protocol: 17, // UDP

		PID:         f.PID,
		ProcessName: f.ProcessName,

		Role:      uint8(f.Role),
		CloseType: 3, // TIMEOUT（UDP 无 FIN/RST）

		BytesSent:       f.BytesSent,
		BytesReceived:   f.BytesRecv,
		PacketsSent:     f.PktsSent,
		PacketsReceived: f.PktsRecv,

		// 无 K8s 环境时默认 0.0.0.0
		PodIP: storage.SafeIPv4(""),
	}

	if tag, ok := f.CloudTag.(*cloudmeta.CloudTag); ok && tag != nil {
		row.PodName = tag.PodName
		row.PodNamespace = tag.PodNamespace
		row.ServiceName = tag.ServiceName
		row.NodeName = tag.NodeName
		row.PodIP = storage.SafeIPv4(tag.PodIP)
		row.Region = tag.Region
		row.AZ = tag.AZ
		row.AppLabels = tag.AppLabelsJSON()
	}

	c.store.WriteL4FlowLog(row)
}

func (c *UDPCache) Size() int { return c.lrc.Len() }
