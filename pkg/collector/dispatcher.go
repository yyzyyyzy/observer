// pkg/collector/dispatcher.go
package collector

import (
	"observer/pkg/ebpf"
	log "github.com/sirupsen/logrus"
)

// Dispatcher 统一事件分发器，实现 ebpf.Manager 的所有 Handler 接口
// 将 eBPF 事件路由到对应的 Collector
type Dispatcher struct {
	tcp *TCPCollector
	udp *UDPCollector
	tc  *TCCollector
}

// NewDispatcher 创建分发器，注入所有 Collector
func NewDispatcher(tcp *TCPCollector, udp *UDPCollector, tc *TCCollector) *Dispatcher {
	return &Dispatcher{tcp: tcp, udp: udp, tc: tc}
}

// HandleTCPEvent 实现 ebpf.TCPEventHandler 接口
func (d *Dispatcher) HandleTCPEvent(event *ebpf.TCPEvent) {
	if d.tcp == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.WithField("panic", r).Error("Panic in TCP event handler")
		}
	}()
	d.tcp.HandleTCPEvent(event)
}

// HandleUDPEvent 实现 ebpf.UDPEventHandler 接口
func (d *Dispatcher) HandleUDPEvent(event *ebpf.UDPEvent) {
	if d.udp == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.WithField("panic", r).Error("Panic in UDP event handler")
		}
	}()
	d.udp.HandleUDPEvent(event)
}

// HandleTCPacket 实现 ebpf.TCPacketHandler 接口
func (d *Dispatcher) HandleTCPacket(pkt *ebpf.TCPacket) {
	if d.tc == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.WithField("panic", r).Error("Panic in TC packet handler")
		}
	}()
	d.tc.HandleTCPacket(pkt)
}
