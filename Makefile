.PHONY: all build generate clean install run help

BINARY_NAME=network-observer
BINARY_PATH=./bin/$(BINARY_NAME)
GO=go
CLANG=clang
BPF_SOURCE_DIR=./bpf
PKG_EBPF_DIR=./pkg/ebpf

all: generate build

generate:
	@echo "Generating eBPF programs..."
	@cd $(PKG_EBPF_DIR) && $(GO) generate -v
	@echo "eBPF programs generated successfully"

build: generate
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p bin
	@CGO_ENABLED=0 $(GO) build -ldflags="-s -w" -o $(BINARY_PATH) ./cmd/agent
	@echo "Build complete: $(BINARY_PATH)"

install:
	@echo "Installing dependencies..."
	@$(GO) mod download
	@$(GO) mod tidy
	@echo "Dependencies installed"

run: build
	@echo "Running $(BINARY_NAME) (requires root)..."
	@sudo $(BINARY_PATH) --tcp --udp --tc-interface=eth0 --stats --log-level=info

clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f $(PKG_EBPF_DIR)/*_bpfel.go
	@rm -f $(PKG_EBPF_DIR)/*_bpfel.o
	@rm -f $(PKG_EBPF_DIR)/*_bpfeb.go
	@rm -f $(PKG_EBPF_DIR)/*_bpfeb.o
	@echo "Clean complete"

check-tools:
	@echo "Checking required tools..."
	@which clang > /dev/null || (echo "Error: clang not found" && exit 1)
	@which llvm-strip > /dev/null || (echo "Error: llvm-strip not found" && exit 1)
	@which go > /dev/null || (echo "Error: go not found" && exit 1)
	@echo "All required tools are installed"

fmt:
	@echo "Formatting Go code..."
	@$(GO) fmt ./...
	@echo "Formatting complete"

test:
	@echo "Running tests..."
	@$(GO) test -v ./...

help:
	@echo "Available targets:"
	@echo "  all          - Generate eBPF and build binary (default)"
	@echo "  generate     - Generate eBPF bytecode and Go bindings"
	@echo "  build        - Build the binary"
	@echo "  install      - Install Go dependencies"
	@echo "  run          - Build and run (requires root)"
	@echo "  clean        - Remove build artifacts"
	@echo "  check-tools  - Check if required tools are installed"
	@echo "  fmt          - Format Go code"
	@echo "  test         - Run tests"
	@echo "  help         - Show this help message"
