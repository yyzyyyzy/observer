// pkg/ebpf/utils.go
package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// Uint32ToIP 将 uint32 转换为 IP 字符串
func Uint32ToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24))
}

// IPToUint32 将 IP 字符串转换为 uint32
func IPToUint32(ip string) (uint32, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ip)
	}
	
	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ip)
	}
	
	return binary.LittleEndian.Uint32(ipv4), nil
}

// BytesToString 将字节数组转换为字符串（去除 null 字符）
func BytesToString(b []byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

// StringToBytes 将字符串转换为固定长度字节数组
func StringToBytes(s string, length int) []byte {
	b := make([]byte, length)
	copy(b, s)
	return b
}

// FormatBytes 格式化字节数
func FormatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	
	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/float64(TB))
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// FormatDuration 格式化时长（微秒）
func FormatDuration(us uint32) string {
	switch {
	case us >= 1000000:
		return fmt.Sprintf("%.2f s", float64(us)/1000000)
	case us >= 1000:
		return fmt.Sprintf("%.2f ms", float64(us)/1000)
	default:
		return fmt.Sprintf("%d µs", us)
	}
}

// ParseCommField 解析进程名字段
func ParseCommField(comm [16]byte) string {
	return strings.TrimRight(string(comm[:]), "\x00")
}

// GetFlowKey 生成流的唯一键
func GetFlowKey(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) string {
	return fmt.Sprintf("%s:%d->%s:%d/%s", srcIP, srcPort, dstIP, dstPort, proto)
}

// ReverseFlowKey 反转流键（用于双向流匹配）
func ReverseFlowKey(key string) string {
	parts := strings.Split(key, "->")
	if len(parts) != 2 {
		return key
	}
	
	protoSplit := strings.Split(parts[1], "/")
	if len(protoSplit) != 2 {
		return key
	}
	
	return fmt.Sprintf("%s->%s/%s", protoSplit[0], parts[0], protoSplit[1])
}

// CalculateRetransRatio 计算重传比例
func CalculateRetransRatio(retransPackets, totalPackets uint64) float64 {
	if totalPackets == 0 {
		return 0.0
	}
	return float64(retransPackets) / float64(totalPackets)
}

// MicrosecondsToString 微秒转字符串
func MicrosecondsToString(us uint32) string {
	if us == 0 {
		return "0"
	}
	
	if us < 1000 {
		return fmt.Sprintf("%dµs", us)
	} else if us < 1000000 {
		return fmt.Sprintf("%.2fms", float64(us)/1000)
	} else {
		return fmt.Sprintf("%.2fs", float64(us)/1000000)
	}
}

// IsPrivateIP 判断是否为私有 IP
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	
	// 10.0.0.0/8
	if ip[0] == 10 {
		return true
	}
	
	// 172.16.0.0/12
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return true
	}
	
	// 192.168.0.0/16
	if ip[0] == 192 && ip[1] == 168 {
		return true
	}
	
	return false
}

// GetProtocolName 获取协议名称
func GetProtocolName(proto uint8) string {
	switch proto {
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	default:
		return fmt.Sprintf("PROTO_%d", proto)
	}
}

// GetDirectionName 获取方向名称
func GetDirectionName(direction uint8) string {
	switch direction {
	case FlowDirectionEgress:
		return "EGRESS"
	case FlowDirectionIngress:
		return "INGRESS"
	default:
		return "UNKNOWN"
	}
}

// IfIndexToName 将网卡 index 转为名称（通过 /sys/class/net 查找）
func IfIndexToName(ifindex uint32) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Sprintf("if%d", ifindex)
	}
	for _, iface := range ifaces {
		if uint32(iface.Index) == ifindex {
			return iface.Name
		}
	}
	return fmt.Sprintf("if%d", ifindex)
}
