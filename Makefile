.PHONY: all build bpf test clean docker run fmt lint

BINARY  := observer-agent
BPF_DIR := ./bpf
GOFLAGS := -ldflags="-s -w"

# eBPF 编译参数
# 优先使用系统 libbpf 头文件（/usr/include/bpf/）
# 回退到 BPF_DIR/headers/（手动安装场景）
SYSTEM_BPF_HEADERS := /usr/include/bpf
BPF_HEADERS := $(BPF_DIR)/headers

# 检测系统是否有 libbpf-dev
HAS_LIBBPF_DEV := $(shell test -f $(SYSTEM_BPF_HEADERS)/bpf_helpers.h && echo yes || echo no)

ifeq ($(HAS_LIBBPF_DEV),yes)
    BPF_INCLUDE_FLAGS := -I$(SYSTEM_BPF_HEADERS) -I$(BPF_HEADERS)
else
    BPF_INCLUDE_FLAGS := -I$(BPF_HEADERS)
endif

BPF_CFLAGS := -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    $(BPF_INCLUDE_FLAGS)

all: bpf build

# ── Go 编译 ───────────────────────────────────────────────
build:
	CGO_ENABLED=0 GOOS=linux go build $(GOFLAGS) -o $(BINARY) ./cmd/agent

# ── eBPF C 编译 ───────────────────────────────────────────
bpf:
	@echo "Compiling eBPF programs (libbpf: $(HAS_LIBBPF_DEV))..."
	clang $(BPF_CFLAGS) -c $(BPF_DIR)/tcp_tracer.c   -o $(BPF_DIR)/tcp_tracer.o
	clang $(BPF_CFLAGS) -c $(BPF_DIR)/udp_tracer.c   -o $(BPF_DIR)/udp_tracer.o
	clang $(BPF_CFLAGS) -c $(BPF_DIR)/l7_tracer.c    -o $(BPF_DIR)/l7_tracer.o
	clang $(BPF_CFLAGS) -c $(BPF_DIR)/tc_tracer.c    -o $(BPF_DIR)/tc_tracer.o
	@echo "eBPF programs compiled"

# ── 测试 ──────────────────────────────────────────────────
test:
	go test ./... -v -race

# ── 格式化 ────────────────────────────────────────────────
fmt:
	gofmt -w .

# ── Lint ──────────────────────────────────────────────────
lint:
	golangci-lint run ./...

# ── Docker ────────────────────────────────────────────────
docker:
	docker build -t observer-agent:v8 .

# ── 本地运行（需要 root + eBPF .o 已编译） ───────────────
run: bpf build
	sudo ./$(BINARY) --config config.yaml --log-level debug

# ── 一键启动完整栈 ────────────────────────────────────────
up:
	docker-compose up -d

down:
	docker-compose down

clean:
	rm -f $(BINARY)
	rm -f $(BPF_DIR)/*.o
