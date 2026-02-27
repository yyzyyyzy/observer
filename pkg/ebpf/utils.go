// pkg/ebpf/utils.go — eBPF 辅助工具函数

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// Uint32ToIP 将 uint32（小端 BPF 格式）转换为 IPv4 字符串
func Uint32ToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// IPToUint32 将 IPv4 字符串转换为 uint32
func IPToUint32(ip string) (uint32, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ip)
	}
	v4 := parsed.To4()
	if v4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ip)
	}
	return binary.LittleEndian.Uint32(v4), nil
}

// Bytes16ToIPv6 将 16 字节数组转换为 IPv6 字符串
func Bytes16ToIPv6(b [16]byte) string {
	return net.IP(b[:]).String()
}

// ParseCommField 解析进程名（去除 null 字节）
func ParseCommField(comm [16]byte) string {
	return strings.TrimRight(string(comm[:]), "\x00")
}

// FormatBytes 格式化字节数为人类可读形式
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

// FormatDurationUs 格式化微秒时长
func FormatDurationUs(us uint32) string {
	switch {
	case us >= 1000000:
		return fmt.Sprintf("%.2f s", float64(us)/1000000)
	case us >= 1000:
		return fmt.Sprintf("%.2f ms", float64(us)/1000)
	default:
		return fmt.Sprintf("%d µs", us)
	}
}

// CalculateRetransRatio 计算重传比例
func CalculateRetransRatio(retransPkts, totalPkts uint64) float64 {
	if totalPkts == 0 {
		return 0
	}
	return float64(retransPkts) / float64(totalPkts)
}

// GetProtocolName 协议数字转名称
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

// GetDirectionName 方向数字转名称
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

// IsLoopback 判断是否为回环地址
func IsLoopback(ip uint32) bool {
	// 127.x.x.x → 0x7f000000（大端），BPF 中为小端：byte(ip) == 0x7f
	return byte(ip) == 0x7f
}

// IsPrivateIP 判断是否为私有地址
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// IfIndexToName 网卡 index 转名称
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
