// pkg/collector/dispatcher.go — 统一事件分发器

package collector

import (
	"observer/pkg/ebpf"
	log "github.com/sirupsen/logrus"
)

// Dispatcher 实现所有 ebpf Handler 接口，将事件路由到各 Collector
type Dispatcher struct {
	tcp *TCPCollector
	udp *UDPCollector
	tc  *TCCollector
}

func NewDispatcher(tcp *TCPCollector, udp *UDPCollector, tc *TCCollector) *Dispatcher {
	return &Dispatcher{tcp: tcp, udp: udp, tc: tc}
}

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

func (d *Dispatcher) HandleUDPEvent(event *ebpf.UDPFlowEvent) {
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
