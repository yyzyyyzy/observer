package ebpf

import (
	"bytes"
	"encoding/binary"
	"net"
)

/*===========================================================================
 * Conversion Functions
 *===========================================================================*/

// Uint32ToIP converts a uint32 IP address to string representation
func Uint32ToIP(ip uint32) string {
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, ip)
	return net.IP(ipBytes).String()
}

// BytesToString converts a null-terminated byte array to string
func BytesToString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}

// DirectionToString converts flow direction to string
func DirectionToString(direction uint8) string {
	switch direction {
	case FlowDirectionIngress:
		return "INGRESS"
	case FlowDirectionEgress:
		return "EGRESS"
	default:
		return "UNKNOWN"
	}
}

// ProtocolToString converts protocol number to string
func ProtocolToString(protocol uint8) string {
	switch protocol {
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	default:
		return "UNKNOWN"
	}
}

// EventTypeToString converts event type to string
func EventTypeToString(eventType uint8) string {
	switch eventType {
	case EventTypeConnect:
		return "CONNECT"
	case EventTypeAccept:
		return "ACCEPT"
	case EventTypeClose:
		return "CLOSE"
	case EventTypeData:
		return "DATA"
	default:
		return "UNKNOWN"
	}
}

/*===========================================================================
 * TCP Flags Parsing
 *===========================================================================*/

// TCPFlags represents TCP flag bits
type TCPFlags struct {
	FIN bool
	SYN bool
	RST bool
	PSH bool
	ACK bool
	URG bool
	ECE bool
	CWR bool
}

// ParseTCPFlags parses TCP flags byte into TCPFlags struct
func ParseTCPFlags(flags uint8) TCPFlags {
	return TCPFlags{
		FIN: flags&0x01 != 0,
		SYN: flags&0x02 != 0,
		RST: flags&0x04 != 0,
		PSH: flags&0x08 != 0,
		ACK: flags&0x10 != 0,
		URG: flags&0x20 != 0,
		ECE: flags&0x40 != 0,
		CWR: flags&0x80 != 0,
	}
}

// String returns string representation of TCP flags
func (f TCPFlags) String() string {
	var flags []string
	if f.FIN {
		flags = append(flags, "FIN")
	}
	if f.SYN {
		flags = append(flags, "SYN")
	}
	if f.RST {
		flags = append(flags, "RST")
	}
	if f.PSH {
		flags = append(flags, "PSH")
	}
	if f.ACK {
		flags = append(flags, "ACK")
	}
	if f.URG {
		flags = append(flags, "URG")
	}
	if f.ECE {
		flags = append(flags, "ECE")
	}
	if f.CWR {
		flags = append(flags, "CWR")
	}
	
	if len(flags) == 0 {
		return "NONE"
	}
	
	result := ""
	for i, flag := range flags {
		if i > 0 {
			result += "|"
		}
		result += flag
	}
	return result
}
