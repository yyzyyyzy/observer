.PHONY: all build bpf clean test install docker

# 变量定义
BPF_SOURCE = bpf/tcp_tracer.c bpf/udp_tracer.c bpf/tc_tracer.c
BPF_OBJECTS = $(BPF_SOURCE:.c=.o)
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
GO ?= go
INSTALL_DIR ?= /usr/local/bin

# 架构检测
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# 编译标志
BPF_CFLAGS = -O2 -g -Wall -Werror -D__TARGET_ARCH_$(ARCH)
BPF_INCLUDES = -I/usr/include/bpf -I./bpf/headers

# 默认目标
all: bpf build

# 编译 eBPF 程序
bpf: $(BPF_OBJECTS)

%.o: %.c
	@echo "Compiling eBPF program: $<"
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -target bpf -c $< -o $@
	$(LLVM_STRIP) -g $@

# 编译 Go 程序
build: bpf
	@echo "Building observer-agent..."
	@mkdir -p bin
	$(GO) build -o bin/observer-agent ./cmd/agent

# 安装
install: build
	@echo "Installing observer-agent to $(INSTALL_DIR)..."
	install -m 755 bin/observer-agent $(INSTALL_DIR)/

# 测试
test:
	@echo "Running tests..."
	$(GO) test -v -race -cover ./...

# 性能测试
benchmark:
	@echo "Running benchmarks..."
	$(GO) test -v -bench=. -benchmem ./...

# 清理
clean:
	@echo "Cleaning..."
	rm -f $(BPF_OBJECTS)
	rm -rf bin/
	$(GO) clean

# Docker 镜像
docker:
	@echo "Building Docker image..."
	docker build -t network-observer:latest .

# 代码格式化
fmt:
	@echo "Formatting Go code..."
	$(GO) fmt ./...
	@echo "Formatting C code..."
	clang-format -i $(BPF_SOURCE) bpf/headers/*.h

# 代码检查
lint:
	@echo "Running golangci-lint..."
	golangci-lint run ./...

# 生成依赖
deps:
	@echo "Downloading dependencies..."
	$(GO) mod download
	$(GO) mod tidy

# 开发环境设置
dev-setup:
	@echo "Setting up development environment..."
	@echo "Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y \
		clang \
		llvm \
		libbpf-dev \
		linux-headers-$(shell uname -r) \
		make \
		gcc
	@echo "Installing Go tools..."
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# 运行 (开发模式)
run: build
	@echo "Running observer-agent..."
	sudo ./bin/observer-agent --config config.yaml

# 帮助
help:
	@echo "Available targets:"
	@echo "  all         - Build everything (default)"
	@echo "  bpf         - Compile eBPF programs"
	@echo "  build       - Build Go binary"
	@echo "  install     - Install to $(INSTALL_DIR)"
	@echo "  test        - Run tests"
	@echo "  benchmark   - Run performance tests"
	@echo "  clean       - Clean build artifacts"
	@echo "  docker      - Build Docker image"
	@echo "  fmt         - Format code"
	@echo "  lint        - Run linters"
	@echo "  deps        - Download dependencies"
	@echo "  dev-setup   - Setup development environment"
	@echo "  run         - Build and run (requires sudo)"
	@echo "  help        - Show this help"
