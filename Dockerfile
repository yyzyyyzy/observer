# Build stage
FROM golang:1.25-bookworm AS builder

WORKDIR /build

# 安装 clang/llvm/libbpf（编译 eBPF）
# libbpf-dev 提供 bpf/bpf_helpers.h bpf/bpf_core_read.h bpf/bpf_tracing.h
# libelf-dev 是 libbpf 运行时依赖
# llvm 提供 llvm-strip（减小 .o 文件体积）
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# 编译 eBPF 程序（使用系统 libbpf 头文件）
RUN make bpf

# 编译 Go 程序（CGO_ENABLED=0：纯静态，无 libc 依赖）
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o observer-agent ./cmd/agent

# ──────────────────────────────────────────────────────────
# Runtime stage（最小化镜像）
FROM debian:bookworm-slim

WORKDIR /app

# 仅需要 libelf（libbpf 运行时）和 CA 证书
RUN apt-get update && apt-get install -y \
    libelf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/observer-agent .
COPY --from=builder /build/bpf/*.o ./bpf/
COPY config.yaml /etc/observer/config.yaml

EXPOSE 8080

ENTRYPOINT ["/app/observer-agent", "--config", "/etc/observer/config.yaml"]
