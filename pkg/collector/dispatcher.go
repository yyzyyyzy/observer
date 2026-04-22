// pkg/collector/dispatcher.go — 统一事件分发器

package collector

import (
	"observer/pkg/ebpf"
	log "github.com/sirupsen/logrus"
)

// Dispatcher 实现所有 ebpf Handler 接口，将事件路由到各 Collector
type Dispatcher struct {
	tcp        *TCPCollector
	udp        *UDPCollector
	tc         *TCCollector
	udpL7      *UDPDispatcher      // UDP L7 协议分发（DNS/NTP 等）
	l7MetaDisp *L7MetaDispatcher   // 内核态 L7 推断结果分发
}

func NewDispatcher(tcp *TCPCollector, udp *UDPCollector, tc *TCCollector) *Dispatcher {
	return &Dispatcher{tcp: tcp, udp: udp, tc: tc}
}

// WithUDPL7Dispatcher 注入 UDP L7 分发器
func (d *Dispatcher) WithUDPL7Dispatcher(udpL7 *UDPDispatcher) *Dispatcher {
	d.udpL7 = udpL7
	return d
}

// WithL7MetaDispatcher 注入内核 L7 推断分发器
func (d *Dispatcher) WithL7MetaDispatcher(meta *L7MetaDispatcher) *Dispatcher {
	d.l7MetaDisp = meta
	return d
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

// HandleL7Event 处理 L7 载荷事件（TCP 和 UDP 协议均可能经此路径）
func (d *Dispatcher) HandleL7Event(event *ebpf.L7Event) {
	if event.Protocol == ebpf.ProtocolUDP && d.udpL7 != nil {
		defer func() {
			if r := recover(); r != nil {
				log.WithField("panic", r).Error("Panic in UDP L7 handler")
			}
		}()
		d.udpL7.HandleUDPL7Event(event)
	}
}

// HandleL7MetaEvent 处理内核态 L7 协议推断结果
func (d *Dispatcher) HandleL7MetaEvent(event *ebpf.L7MetaEvent) {
	if d.l7MetaDisp == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.WithField("panic", r).Error("Panic in L7 meta handler")
		}
	}()
	d.l7MetaDisp.HandleL7MetaEvent(event)
}
