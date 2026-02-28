.PHONY: all build bpf test clean run fmt lint up down

BINARY  := observer-agent
BPF_DIR := ./bpf
GOFLAGS := -ldflags="-s -w"

SYSTEM_BPF_HEADERS := /usr/include/bpf
BPF_HEADERS := $(BPF_DIR)/headers

HAS_LIBBPF_DEV := $(shell test -f $(SYSTEM_BPF_HEADERS)/bpf_helpers.h && echo yes || echo no)

ifeq ($(HAS_LIBBPF_DEV),yes)
    BPF_INCLUDE_FLAGS := -I$(SYSTEM_BPF_HEADERS) -I$(BPF_HEADERS)
else
    BPF_INCLUDE_FLAGS := -I$(BPF_HEADERS)
endif

# -g 保留 BTF 调试信息，供 CO-RE 字段重定位使用
BPF_CFLAGS := -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    $(BPF_INCLUDE_FLAGS)

all: bpf build

build:
	CGO_ENABLED=0 GOOS=linux go build $(GOFLAGS) -o $(BINARY) ./cmd/agent

bpf:
	@echo "Compiling eBPF programs (CO-RE enabled, libbpf: $(HAS_LIBBPF_DEV))..."
	clang $(BPF_CFLAGS) -c $(BPF_DIR)/tcp_tracer.c   -o $(BPF_DIR)/tcp_tracer.o
	clang $(BPF_CFLAGS) -c $(BPF_DIR)/udp_tracer.c   -o $(BPF_DIR)/udp_tracer.o
	clang $(BPF_CFLAGS) -c $(BPF_DIR)/l7_tracer.c    -o $(BPF_DIR)/l7_tracer.o
	clang $(BPF_CFLAGS) -c $(BPF_DIR)/tc_tracer.c    -o $(BPF_DIR)/tc_tracer.o
	clang $(BPF_CFLAGS) -c $(BPF_DIR)/tls_tracer.c   -o $(BPF_DIR)/tls_tracer.o
	@echo "eBPF programs compiled (BTF-annotated .o files ready)"

test:
	go test ./... -v -race

fmt:
	gofmt -w .

lint:
	golangci-lint run ./...

docker:
	docker build -t observer-agent:latest .

run: bpf build
	sudo ./$(BINARY) --config config.yaml --log-level debug

up:
	docker-compose up -d

down:
	docker-compose down

clean:
	rm -f $(BINARY)
	rm -f $(BPF_DIR)/*.o
