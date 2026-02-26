# WASM 插件开发指南（wazero）

Observer v6 使用 **wazero**（纯 Go，零 CGo）运行 WASM 扩展插件。

## 接口约定

```c
// 必须导出（wasi-libc 自动提供 malloc/free）

int32_t on_check_payload(int32_t ptr, int32_t len);  // 1=匹配 0=不匹配
int32_t on_parse_payload(int32_t ptr, int32_t len);  // 返回结果JSON指针
```

**输入 JSON：**
```json
{"payload":[72,84,84,80],"src_port":12345,"dst_port":8080,"direction":1}
```

**输出 JSON（on_parse_payload 返回指针所指内容）：**
```json
{"response_status":"ok","response_msg":"","protocol":"dubbo","my_field":"val"}
```

## C 语言示例（Dubbo 协议解析器）

```c
// dubbo_parser.c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Dubbo magic header: 0xDABB
static int is_dubbo(const char *json) {
    return strstr(json, "\\u00da\\u00bb") != NULL ||
           (json[11] == 0xda && json[12] == 0xbb);
}

__attribute__((export_name("on_check_payload")))
int32_t on_check_payload(int32_t ptr, int32_t len) {
    return is_dubbo((char *)ptr) ? 1 : 0;
}

__attribute__((export_name("on_parse_payload")))
int32_t on_parse_payload(int32_t ptr, int32_t len) {
    char *result = malloc(256);
    if (!result) return 0;
    snprintf(result, 256,
        "{\"response_status\":\"ok\",\"protocol\":\"dubbo\","
        "\"framework\":\"dubbo2.x\",\"serialization\":\"hessian2\"}");
    return (int32_t)result;
}
```

**编译（需要 wasi-sdk 22+）：**
```bash
# 安装 wasi-sdk
wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-22/wasi-sdk-22.0-linux.tar.gz
tar xf wasi-sdk-22.0-linux.tar.gz

# 编译
/opt/wasi-sdk/bin/clang \
  --target=wasm32-wasi \
  --sysroot=/opt/wasi-sdk/share/wasi-sysroot \
  -O2 -o dubbo_parser.wasm dubbo_parser.c

# 验证导出函数
wasm-objdump -x dubbo_parser.wasm | grep -E "on_check|on_parse|malloc|free"
```

## Rust 示例

```toml
# Cargo.toml
[lib]
crate-type = ["cdylib"]
```

```rust
// src/lib.rs
use std::ffi::CString;
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn on_check_payload(ptr: *const u8, len: i32) -> i32 {
    let payload = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    // 检查 JSON 中的 payload 字段（实际需要解析 JSON）
    if payload.windows(2).any(|w| w == &[0xda, 0xbb]) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn on_parse_payload(ptr: *const u8, _len: i32) -> *const c_char {
    let s = CString::new(r#"{"response_status":"ok","protocol":"dubbo"}"#).unwrap();
    let ptr = s.as_ptr();
    std::mem::forget(s); // 由 WASM host 负责 free
    ptr
}
```

```bash
cargo build --target wasm32-wasip1 --release
cp target/wasm32-wasip1/release/my_plugin.wasm plugins/
```

## 配置注册

```yaml
wasm:
  enabled: true
  plugin_dir: "./plugins"
  plugins:
    - name: "dubbo-parser"
      path: "dubbo_parser.wasm"   # 相对于 plugin_dir
      protocol: "dubbo"
    - name: "thrift-parser"
      path: "thrift_parser.wasm"
      protocol: "thrift"
```

## wazero vs wasmtime-go 对比

| 项目 | wasmtime-go | wazero |
|------|------------|--------|
| Go 编译 | 需要 CGo + libwasmtime.a | 纯 Go，无额外依赖 |
| 交叉编译 | GOOS=linux GOARCH=arm64 失败 | 直接 go build |
| Docker 镜像 | 需安装 Rust/LLVM 动态库 | 无额外依赖 |
| 二进制大小 | +40MB（C 库） | 仅 Go 运行时 |
| WASI 支持 | 完整 | 完整 |
| 启动速度 | JIT 预热延迟 | 毫秒级（Interpreter）|
