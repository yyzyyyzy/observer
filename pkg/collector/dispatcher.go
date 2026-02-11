package collector

import (
	"observer/pkg/ebpf"
)

type EventDispatcher struct {
	tcpCollector *TCPCollector
	udpCollector *UDPCollector
	tcCollector  *TCCollector
}

func NewEventDispatcher() *EventDispatcher {
	return &EventDispatcher{
		tcpCollector: NewTCPCollector(),
		udpCollector: NewUDPCollector(),
		tcCollector:  NewTCCollector(),
	}
}

func (d *EventDispatcher) HandleTCPEvent(event *ebpf.TCPEvent) {
	d.tcpCollector.HandleTCPEvent(event)
}

func (d *EventDispatcher) HandleUDPEvent(event *ebpf.UDPEvent) {
	d.udpCollector.HandleUDPEvent(event)
}

func (d *EventDispatcher) HandleTCPacket(packet *ebpf.TCPacket) {
	d.tcCollector.HandleTCPacket(packet)
}

func (d *EventDispatcher) GetTCPCollector() *TCPCollector {
	return d.tcpCollector
}

func (d *EventDispatcher) GetUDPCollector() *UDPCollector {
	return d.udpCollector
}

func (d *EventDispatcher) GetTCCollector() *TCCollector {
	return d.tcCollector
}
