// pkg/collector/udp_collector.go
package collector

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"observer/pkg/ebpf"
)

// UDPCollector UDP 数据采集器
type UDPCollector struct {
	mu      sync.RWMutex
	metrics *Metrics

	lastStatsTime    time.Time
	lastBytesSent    uint64
	lastBytesRecv    uint64
	lastPacketsSent  uint64
	lastPacketsRecv  uint64
	totalBytesSent   uint64
	totalBytesRecv   uint64
	totalPacketsSent uint64
	totalPacketsRecv uint64
}

// NewUDPCollector 创建 UDP 采集器
func NewUDPCollector() *UDPCollector {
	return &UDPCollector{
		metrics:       NewMetrics("udp"),
		lastStatsTime: time.Now(),
	}
}

// HandleUDPEvent 实现 ebpf.UDPEventHandler 接口
func (c *UDPCollector) HandleUDPEvent(event *ebpf.UDPEvent) {
	srcIP := ebpf.Uint32ToIP(event.SAddr)
	dstIP := ebpf.Uint32ToIP(event.DAddr)

	c.mu.Lock()
	defer c.mu.Unlock()

	if event.Direction == ebpf.FlowDirectionEgress {
		delta := uint64(event.PacketSize)
		c.totalBytesSent += delta
		c.totalPacketsSent++
		c.metrics.BytesSent.Add(float64(delta))
		c.metrics.PacketsSent.Inc()
	} else {
		delta := uint64(event.PacketSize)
		c.totalBytesRecv += delta
		c.totalPacketsRecv++
		c.metrics.BytesReceived.Add(float64(delta))
		c.metrics.PacketsReceived.Inc()
	}

	log.WithFields(log.Fields{
		"src":         srcIP,
		"dst":         dstIP,
		"sport":       event.SPort,
		"dport":       event.DPort,
		"packet_size": event.PacketSize,
		"direction":   ebpf.GetDirectionName(event.Direction),
		"pid":         event.PID,
	}).Debug("UDP packet")
}

// CalculateRates 计算并更新 BPS/PPS 速率
func (c *UDPCollector) CalculateRates() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(c.lastStatsTime).Seconds()
	if elapsed <= 0 {
		return
	}

	bytesDelta := (c.totalBytesSent + c.totalBytesRecv) - (c.lastBytesSent + c.lastBytesRecv)
	pktsDelta := (c.totalPacketsSent + c.totalPacketsRecv) - (c.lastPacketsSent + c.lastPacketsRecv)

	c.metrics.BytesPerSecond.Set(float64(bytesDelta) / elapsed)
	c.metrics.PacketsPerSecond.Set(float64(pktsDelta) / elapsed)

	c.lastBytesSent = c.totalBytesSent
	c.lastBytesRecv = c.totalBytesRecv
	c.lastPacketsSent = c.totalPacketsSent
	c.lastPacketsRecv = c.totalPacketsRecv
	c.lastStatsTime = now
}

// GetMetrics 返回指标对象
func (c *UDPCollector) GetMetrics() *Metrics {
	return c.metrics
}

// Close 释放资源
func (c *UDPCollector) Close() error {
	log.Info("UDP collector closed")
	return nil
}
