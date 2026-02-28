// pkg/l7/portfilter.go
// Go 层 L7 端口黑名单过滤器（对齐 DeepFlow l7_skip_port_set 实现）。
//
// ── 设计说明 ──────────────────────────────────────────────────────────────────
//
// 为什么需要两层过滤？
//
//   层一（BPF）：在 kretprobe__tcp_sendmsg/recvmsg 的 ringbuf submit 前查表。
//               彻底阻止无效 payload 写入 ring buffer，降低内核→用户态 copy 量。
//               适合"确定无用"的端口：SSH(22)、VNC、自身监听端口等。
//
//   层二（Go）：在 HandleL7Event 入口处，对事件做 O(1) set lookup。
//               补充处理：
//               - BPF 对象未带 skip_ports map（旧 .o 文件兼容）
//               - 运行时动态新增端口（热更新场景）
//               - 更细粒度的 src+dst 组合过滤（未来扩展）
//
// PortFilter 是无锁结构（初始化后只读），可被多个 goroutine 并发调用。

package l7

// PortFilter 端口黑名单过滤器。
// 使用 [65536]bool 数组实现 O(1) lookup，内存占用 64KB，对 CPU cache 友好。
type PortFilter struct {
	skip [65536]bool
}

// NewPortFilter 构造端口过滤器，ports 为需要跳过的端口号列表。
func NewPortFilter(ports []uint16) *PortFilter {
	f := &PortFilter{}
	for _, p := range ports {
		f.skip[p] = true
	}
	return f
}

// ShouldSkip 判断该 L7 事件是否应被跳过（不进入 parser 流程）。
// 只要 sport 或 dport 在黑名单中即返回 true。
func (f *PortFilter) ShouldSkip(sport, dport uint16) bool {
	return f.skip[sport] || f.skip[dport]
}
