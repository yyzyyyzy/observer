// Package ebpf provides eBPF program management and event handling
package ebpf

import "time"

/*===========================================================================
 * Constants
 *===========================================================================*/

// Event types
const (
	EventTypeConnect = 1
	EventTypeAccept  = 2
	EventTypeClose   = 3
	EventTypeData    = 4
)

// Flow directions
const (
	FlowDirectionIngress = 0
	FlowDirectionEgress  = 1
)

// Protocol types
const (
	ProtocolTCP = 6
	ProtocolUDP = 17
)

/*===========================================================================
 * Event Structures
 *===========================================================================*/

// TCPEvent represents a TCP connection event from eBPF
type TCPEvent struct {
	TimestampNs   uint64
	PID           uint32
	TID           uint32
	Comm          [16]byte
	SAddr         uint32
	DAddr         uint32
	SPort         uint16
	DPort         uint16
	EventType     uint8
	Direction     uint8
	_             [2]byte // padding
	BytesSent     uint64
	BytesReceived uint64
	DurationNs    uint32
	_             uint32 // reserved
}

// UDPEvent represents a UDP flow event from eBPF
type UDPEvent struct {
	TimestampNs uint64
	PID         uint32
	TID         uint32
	Comm        [16]byte
	SAddr       uint32
	DAddr       uint32
	SPort       uint16
	DPort       uint16
	Direction   uint8
	_           [3]byte // padding
	PacketSize  uint32
	TotalBytes  uint64
}

// TCPacket represents a packet captured at TC hook
type TCPacket struct {
	TimestampNs uint64
	IfIndex     uint32
	SAddr       uint32
	DAddr       uint32
	SPort       uint16
	DPort       uint16
	Protocol    uint8
	Direction   uint8
	TCPFlags    uint8
	_           uint8 // padding
	PacketLen   uint32
}

/*===========================================================================
 * Application Structures
 *===========================================================================*/

// FlowInfo represents aggregated flow information
type FlowInfo struct {
	SrcIP           string
	DstIP           string
	SrcPort         uint16
	DstPort         uint16
	Protocol        string
	Direction       string
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64
	StartTime       time.Time
	Duration        time.Duration
	ProcessName     string
	PID             uint32
}

/*===========================================================================
 * Event Handler Interface
 *===========================================================================*/

// EventHandler defines the interface for handling network events
type EventHandler interface {
	// HandleTCPEvent processes a TCP connection event
	HandleTCPEvent(event *TCPEvent)
	
	// HandleUDPEvent processes a UDP flow event
	HandleUDPEvent(event *UDPEvent)
	
	// HandleTCPacket processes a TC packet event
	HandleTCPacket(packet *TCPacket)
}
