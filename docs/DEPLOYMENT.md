# 部署指南

## 系统要求

### 最低要求
- Linux Kernel >= 5.4
- CPU: 2 cores
- Memory: 2GB RAM
- Disk: 10GB

### 推荐配置
- Linux Kernel >= 5.10
- CPU: 4+ cores
- Memory: 4GB+ RAM
- Disk: 50GB SSD
- 支持 BTF (BPF Type Format)

### 内核特性检查

```bash
# 检查内核版本
uname -r

# 检查 BTF 支持
ls /sys/kernel/btf/vmlinux

# 检查 eBPF 支持
zgrep CONFIG_BPF /proc/config.gz
zgrep CONFIG_BPF_SYSCALL /proc/config.gz
```

## 部署方式

### 方式 1: 二进制部署

#### 1. 安装依赖

Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r)
```

CentOS/RHEL:
```bash
sudo yum install -y \
    clang \
    llvm \
    libbpf-devel \
    kernel-devel-$(uname -r)
```

#### 2. 编译

```bash
# 克隆代码
git clone https://github.com/your-org/network-observer.git
cd network-observer

# 编译
make all

# 安装
sudo make install
```

#### 3. 配置

```bash
# 复制配置文件
sudo mkdir -p /etc/observer
sudo cp config.yaml /etc/observer/

# 编辑配置
sudo vim /etc/observer/config.yaml
```

#### 4. 运行

```bash
# 前台运行
sudo observer-agent --config /etc/observer/config.yaml

# Systemd 服务
sudo cp deployments/systemd/observer-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable observer-agent
sudo systemctl start observer-agent
```

### 方式 2: Docker 部署

#### 1. 使用 Docker Compose

```bash
# 启动所有服务
docker-compose up -d

# 查看日志
docker-compose logs -f observer-agent

# 停止服务
docker-compose down
```

#### 2. 单独运行 Observer

```bash
# 构建镜像
docker build -t network-observer:latest .

# 运行容器
docker run -d \
  --name network-observer \
  --privileged \
  --pid=host \
  --network=host \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  network-observer:latest
```

### 方式 3: Kubernetes 部署

#### 1. 创建 DaemonSet

```yaml
# deployments/kubernetes/daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: network-observer
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: network-observer
  template:
    metadata:
      labels:
        app: network-observer
    spec:
      hostNetwork: true
      hostPID: true
      serviceAccountName: network-observer
      containers:
      - name: observer-agent
        image: network-observer:2.0.0
        imagePullPolicy: Always
        securityContext:
          privileged: true
        volumeMounts:
        - name: sys
          mountPath: /sys
          readOnly: true
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
        ports:
        - containerPort: 8080
          name: metrics
      volumes:
      - name: sys
        hostPath:
          path: /sys
      - name: config
        configMap:
          name: observer-config
```

#### 2. 部署

```bash
# 创建命名空间
kubectl create namespace monitoring

# 创建配置
kubectl create configmap observer-config \
  --from-file=config.yaml \
  -n monitoring

# 部署 DaemonSet
kubectl apply -f deployments/kubernetes/daemonset.yaml

# 创建 Service
kubectl apply -f deployments/kubernetes/service.yaml
```

## 验证部署

### 1. 检查服务状态

```bash
# 二进制部署
sudo systemctl status observer-agent

# Docker 部署
docker ps | grep observer

# K8s 部署
kubectl get pods -n monitoring -l app=network-observer
```

### 2. 检查指标

```bash
# 访问 metrics 端点
curl http://localhost:8080/metrics | grep network_tcp

# 检查健康状态
curl http://localhost:8080/health
```

### 3. 查看日志

```bash
# Systemd
sudo journalctl -u observer-agent -f

# Docker
docker logs -f network-observer

# K8s
kubectl logs -f -n monitoring -l app=network-observer
```

## Prometheus 集成

### 1. 配置 Prometheus

在 `prometheus.yml` 中添加：

```yaml
scrape_configs:
  - job_name: 'network-observer'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
          - monitoring
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        action: keep
        regex: network-observer
```

### 2. 导入 Dashboard

访问 Grafana (http://localhost:3000)：
1. 登录 (admin/admin)
2. 导入 Dashboard: `deployments/grafana/dashboards/network-overview.json`

## Grafana Dashboard

### 预置 Dashboard

1. **网络性能总览** (ID: 10001)
   - 吞吐量、连接数、时延概览
   
2. **TCP 时延分析** (ID: 10002)
   - 建连、传输、系统时延详细分析
   
3. **TCP 异常监控** (ID: 10003)
   - 重传、零窗口、RST 等异常事件

### 导入方式

```bash
# 方式 1: UI 导入
# Dashboard -> Import -> Upload JSON file

# 方式 2: API 导入
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @deployments/grafana/dashboards/network-overview.json
```

## 故障排查

### eBPF 程序加载失败

```bash
# 检查内核配置
zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz

# 查看详细错误
sudo dmesg | tail -50

# 检查 BPF 程序
sudo bpftool prog show
```

### 权限问题

```bash
# 确保以 root 运行
sudo observer-agent

# 或添加 capabilities
sudo setcap cap_sys_admin,cap_bpf=ep /usr/local/bin/observer-agent
```

### 性能问题

```bash
# 检查 CPU 使用
top -p $(pidof observer-agent)

# 检查内存
ps aux | grep observer-agent

# 减少采样率（在 config.yaml 中）
ebpf:
  sampling_rate: 50  # 降低到 50%
```

## 卸载

### 二进制部署

```bash
sudo systemctl stop observer-agent
sudo systemctl disable observer-agent
sudo rm /etc/systemd/system/observer-agent.service
sudo rm /usr/local/bin/observer-agent
sudo rm -rf /etc/observer
```

### Docker 部署

```bash
docker-compose down -v
```

### Kubernetes 部署

```bash
kubectl delete -f deployments/kubernetes/
kubectl delete namespace monitoring
```
