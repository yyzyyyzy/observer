// pkg/wasm/runtime.go
// WASM 插件运行时 —— wazero（纯 Go，零 CGo）
//
// ─────────────────────────────────────────────────────────
// 为什么选 wazero 而非 wasmtime-go？
// ─────────────────────────────────────────────────────────
//   wasmtime-go 的问题：
//     • 依赖 CGo + 预编译的 wasmtime C 库（libwasmtime.a ~40MB）
//     • 交叉编译：GOOS=linux GOARCH=arm64 直接失败，需要额外工具链
//     • Docker 多阶段构建必须安装 Rust/Clang，镜像臃肿
//     • API 与 Go 风格不匹配（大量 unsafe.Pointer）
//     • 版本耦合严重：go.sum 中 wasmtime C 库版本必须与 go 模块严格对齐
//
//   wazero 的优势：
//     • 纯 Go 实现，零 CGo，`go build` 直接编译，无额外工具链
//     • 静态链接，Docker 镜像无需安装任何 C/Rust 动态库
//     • 完整 WASI preview1 支持（文件系统、时钟、随机数）
//     • Interpreter 模式：任意平台即时启动，AOT 可选（加速高频调用）
//     • Context 集成完善，超时控制、goroutine 安全
//     • 内存安全：WASM 线性内存沙箱 + Go GC 双重保障
//     • 活跃开源社区，TetrateLabs + Red Hat 维护
//
// ─────────────────────────────────────────────────────────
// 插件接口约定（对齐 DeepFlow WASM 扩展协议）
// ─────────────────────────────────────────────────────────
//   导出函数（必须）：
//     on_check_payload(ptr i32, len i32) i32
//       输入：JSON 字节（见下文），返回 1=匹配 0=不匹配
//     on_parse_payload(ptr i32, len i32) i32
//       输入：JSON 字节，返回指向结果 JSON 的内存指针（null-terminated）
//     malloc(size i32) i32   — 标准 WASI libc 提供
//     free(ptr i32)          — 标准 WASI libc 提供
//
//   输入 JSON（on_check_payload / on_parse_payload）：
//     {"payload":[72,84,84,80],"src_port":12345,"dst_port":8080,"direction":1}
//
//   输出 JSON（on_parse_payload 返回指针所指内容）：
//     {"response_status":"ok","response_msg":"","my_field":"val"}
//     response_status: "ok"|"client_error"|"server_error"
//
// ─────────────────────────────────────────────────────────
// 并发模型：每个插件一把 Mutex，单实例串行执行
// WASM 线性内存非线程安全，mu 保护所有内存读写操作
// ─────────────────────────────────────────────────────────

package wasm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	log "github.com/sirupsen/logrus"

	"observer/pkg/config"
	"observer/pkg/ebpf"
	"observer/pkg/l7"
)

// ── WASMPlugin：单个插件实例 ─────────────────────────────

// WASMPlugin 封装已加载的 WASM 模块，实现 l7.Parser 接口。
// 每个插件有独立的 wazero Runtime，完全隔离，互不影响。
type WASMPlugin struct {
	name     string
	protocol string

	// wazero 运行时（每插件独立，不共享）
	runtime  wazero.Runtime
	compiled wazero.CompiledModule

	// 串行锁（WASM 线性内存非线程安全）
	mu       sync.Mutex
	instance api.Module
	ctx      context.Context
}

func loadPlugin(cfg config.WASMPlugin) (*WASMPlugin, error) {
	wasmBytes, err := os.ReadFile(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("read wasm %s: %w", cfg.Path, err)
	}

	ctx := context.Background()

	// NewRuntimeWithConfig: Interpreter 模式无需 JIT，任意平台直接运行
	// WithCloseOnContextDone(false): 避免 ctx 取消时意外关闭 runtime
	rt := wazero.NewRuntimeWithConfig(ctx,
		wazero.NewRuntimeConfig().WithCloseOnContextDone(false))

	// 注入 WASI snapshot_preview1（支持 printf/malloc/free 等 C 标准库）
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		rt.Close(ctx)
		return nil, fmt.Errorf("wasi instantiate for %s: %w", cfg.Name, err)
	}

	// 编译模块（缓存 CompiledModule，后续 Instantiate 无需重新编译）
	compiled, err := rt.CompileModule(ctx, wasmBytes)
	if err != nil {
		rt.Close(ctx)
		return nil, fmt.Errorf("compile %s: %w", cfg.Name, err)
	}

	// 实例化模块（创建独立执行环境）
	modCfg := wazero.NewModuleConfig().
		WithName(cfg.Name).
		WithStdout(os.Stdout).
		WithStderr(os.Stderr).
		WithSysNanosleep() // 支持 time.Sleep 等 WASM 系统调用
	instance, err := rt.InstantiateModule(ctx, compiled, modCfg)
	if err != nil {
		compiled.Close(ctx)
		rt.Close(ctx)
		return nil, fmt.Errorf("instantiate %s: %w", cfg.Name, err)
	}

	p := &WASMPlugin{
		name: cfg.Name, protocol: cfg.Protocol,
		runtime: rt, compiled: compiled,
		instance: instance, ctx: ctx,
	}

	log.WithFields(log.Fields{
		"name": cfg.Name, "path": cfg.Path, "protocol": cfg.Protocol,
		"runtime": "wazero (pure-go, zero-CGo)",
	}).Info("WASM plugin loaded")

	return p, nil
}

// Protocol 返回协议枚举（WASM 扩展使用 L7ProtocolCustom）
func (p *WASMPlugin) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolCustom }

// CanParse 调用 on_check_payload，判断是否可以解析该 payload
func (p *WASMPlugin) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	inputJSON, _ := json.Marshal(map[string]interface{}{
		"payload":  payload,
		"src_port": srcPort,
		"dst_port": dstPort,
	})
	p.mu.Lock()
	defer p.mu.Unlock()
	ret, err := p.callWithMem("on_check_payload", inputJSON)
	return err == nil && ret == 1
}

// Parse 调用 on_parse_payload，返回解析结果
func (p *WASMPlugin) Parse(payload []byte, direction uint8, ts time.Time) *l7.ParseResult {
	inputJSON, _ := json.Marshal(map[string]interface{}{
		"payload":   payload,
		"direction": direction,
	})
	p.mu.Lock()
	defer p.mu.Unlock()

	// on_parse_payload 返回指向结果 JSON 的内存指针
	resultPtr, err := p.callWithMem("on_parse_payload", inputJSON)
	if err != nil || resultPtr == 0 {
		return nil
	}

	// 从 WASM 线性内存读取 null-terminated JSON（调用方已持有 mu）
	resultJSON := p.readCString(uint32(resultPtr), 65536)
	if len(resultJSON) == 0 {
		return nil
	}

	var output map[string]string
	if err := json.Unmarshal(resultJSON, &output); err != nil {
		return nil
	}

	result := &l7.ParseResult{
		Protocol:      ebpf.L7ProtocolCustom,
		ReqType:       ebpf.L7RequestTypeSession,
		StartTime:     ts,
		EndTime:       ts,
		ExtAttributes: string(resultJSON),
	}
	switch output["response_status"] {
	case "client_error", "1":
		result.ResponseStatus = 1
	case "server_error", "2":
		result.ResponseStatus = 2
	}
	if v, ok := output["response_msg"]; ok {
		result.ResponseErrMsg = v
	}
	return result
}

// callWithMem 核心调用：malloc → write → call → free → return result
// 调用方必须持有 p.mu
func (p *WASMPlugin) callWithMem(funcName string, inputJSON []byte) (int32, error) {
	mem := p.instance.Memory()
	if mem == nil {
		return 0, fmt.Errorf("plugin %s: no memory export", p.name)
	}

	// 1. malloc 分配输入缓冲
	mallocFn := p.instance.ExportedFunction("malloc")
	if mallocFn == nil {
		return 0, fmt.Errorf("plugin %s: malloc not exported", p.name)
	}
	allocRes, err := mallocFn.Call(p.ctx, uint64(len(inputJSON)))
	if err != nil || len(allocRes) == 0 {
		return 0, fmt.Errorf("plugin %s: malloc(%d) failed: %w", p.name, len(inputJSON), err)
	}
	ptr := uint32(allocRes[0])
	defer func() {
		// 确保 free（无论调用是否成功）
		if freeFn := p.instance.ExportedFunction("free"); freeFn != nil {
			freeFn.Call(p.ctx, uint64(ptr)) //nolint:errcheck
		}
	}()

	// 2. 写入 JSON 数据到 WASM 线性内存
	if !mem.Write(ptr, inputJSON) {
		return 0, fmt.Errorf("plugin %s: write(%d bytes @ %d) failed", p.name, len(inputJSON), ptr)
	}

	// 3. 调用目标函数
	fn := p.instance.ExportedFunction(funcName)
	if fn == nil {
		return 0, fmt.Errorf("plugin %s: function %s not exported", p.name, funcName)
	}
	results, callErr := fn.Call(p.ctx, uint64(ptr), uint64(len(inputJSON)))
	if callErr != nil {
		return 0, fmt.Errorf("plugin %s: call %s: %w", p.name, funcName, callErr)
	}
	if len(results) == 0 {
		return 0, nil
	}
	return int32(results[0]), nil
}

// readCString 从 WASM 线性内存的指定偏移读取 null-terminated 字符串
// 调用方必须持有 p.mu
func (p *WASMPlugin) readCString(ptr, maxLen uint32) []byte {
	mem := p.instance.Memory()
	if mem == nil {
		return nil
	}
	var buf []byte
	for i := uint32(0); i < maxLen; i++ {
		b, ok := mem.ReadByte(ptr + i)
		if !ok || b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return buf
}

// Close 关闭插件，释放所有 wazero 资源
func (p *WASMPlugin) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx := context.Background()
	if p.instance != nil {
		p.instance.Close(ctx)
		p.instance = nil
	}
	if p.compiled != nil {
		p.compiled.Close(ctx)
		p.compiled = nil
	}
	if p.runtime != nil {
		p.runtime.Close(ctx)
		p.runtime = nil
	}
}

// ── Runtime：管理所有 WASM 插件 ─────────────────────────

// Runtime 持有所有已加载插件的生命周期
type Runtime struct {
	plugins []*WASMPlugin
}

// NewRuntime 按配置加载所有 WASM 插件（失败的插件打 warn 日志但不中止）
func NewRuntime(cfg config.WASMConfig) (*Runtime, error) {
	r := &Runtime{}
	if !cfg.Enabled {
		log.Info("WASM plugin runtime disabled")
		return r, nil
	}

	successCount := 0
	for _, pluginCfg := range cfg.Plugins {
		// 相对路径 → 相对于 plugin_dir
		if !filepath.IsAbs(pluginCfg.Path) {
			pluginCfg.Path = filepath.Join(cfg.PluginDir, pluginCfg.Path)
		}
		p, err := loadPlugin(pluginCfg)
		if err != nil {
			log.WithError(err).WithField("plugin", pluginCfg.Name).
				Warn("WASM plugin load failed, skipping")
			continue
		}
		r.plugins = append(r.plugins, p)
		successCount++
	}

	log.WithFields(log.Fields{
		"loaded":  successCount,
		"failed":  len(cfg.Plugins) - successCount,
		"runtime": "wazero",
	}).Info("WASM runtime initialized")
	return r, nil
}

// Parsers 将所有已加载插件作为 l7.Parser 列表返回
func (r *Runtime) Parsers() []l7.Parser {
	result := make([]l7.Parser, len(r.plugins))
	for i, p := range r.plugins {
		result[i] = p
	}
	return result
}

// Close 关闭所有插件，释放 wazero 运行时资源
func (r *Runtime) Close() {
	for _, p := range r.plugins {
		p.Close()
	}
}
