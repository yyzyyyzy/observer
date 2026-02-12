# 多阶段构建

# 阶段 1: 构建 eBPF 程序
FROM ubuntu:22.04 AS bpf-builder

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY bpf/ ./bpf/
COPY Makefile .

RUN make bpf

# 阶段 2: 构建 Go 程序
FROM golang:1.21-alpine AS go-builder

RUN apk add --no-cache git make gcc musl-dev

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=bpf-builder /build/bpf/*.o ./bpf/

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o observer-agent ./cmd/agent

# 阶段 3: 最终镜像
FROM ubuntu:22.04

# 安装必要的运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libbpf0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 从构建阶段复制文件
COPY --from=go-builder /build/observer-agent .
COPY --from=bpf-builder /build/bpf/*.o ./bpf/
COPY config.yaml .

# 创建必要的目录
RUN mkdir -p /var/log/observer

# 暴露端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# 运行程序（需要特权模式）
ENTRYPOINT ["/app/observer-agent"]
CMD ["--config", "/app/config.yaml"]
