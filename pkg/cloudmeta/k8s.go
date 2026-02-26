// pkg/cloudmeta/k8s.go
// K8s 云标签注入器 —— 使用 SharedInformerFactory（Informer 模式）
//
// ─────────────────────────────────────────────────────────
// 为什么用 Informer 而非 Watch/List？
// ─────────────────────────────────────────────────────────
//   手动 Watch/List 的问题：
//     • 需要自己处理断线重连（Watch stream 中断后重新 List + Watch）
//     • List 全量数据 + 手动维护 IP→Tag 映射表，代码复杂
//     • 周期性全量 re-sync 实现繁琐，且有竞态条件
//     • 无法正确处理 API Server 压力（大量 List 请求）
//     • Delete 事件中 cache.DeletedFinalStateUnknown 处理容易漏掉
//
//   SharedInformerFactory（Informer）的优势：
//     • 内置 ListWatch + 本地缓存 + 自动断线重连，生产级稳健
//     • SharedInformer 多处复用同一 Watch 连接，不重复订阅
//     • WaitForCacheSync 确保启动时缓存已全量填充，不会漏数据
//     • EventHandler（OnAdd/OnUpdate/OnDelete）增量更新，O(1) 维护
//     • Lister 接口支持本地缓存查询，零 API Server 访问（热路径安全）
//     • Resync 机制防止长期运行后缓存与 API Server 漂移
//     • 正确处理 cache.DeletedFinalStateUnknown（GC 窗口内的删除事件）
//     • 这是 K8s controller 生态的标准做法（controller-runtime 底层原理）
//
// ─────────────────────────────────────────────────────────
// 注入字段（对齐 DeepFlow cloud_tag）：
//   pod_name / pod_namespace / node_name / service_name
//   pod_ip / region / az / app_labels（JSON）
//
// 热路径：GetTag(ip) → sync.Map O(1) 无锁查找
// 冷路径：Informer EventHandler → sync.Map 写入（增量，极低频）
// ─────────────────────────────────────────────────────────

package cloudmeta

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	"observer/pkg/config"
)

// ── CloudTag：注入到流记录的云标签 ──────────────────────

// CloudTag 对应 DeepFlow cloud_tag 字段集合
type CloudTag struct {
	PodName      string
	PodNamespace string
	ServiceName  string
	NodeName     string
	PodIP        string
	Region       string            // topology.kubernetes.io/region
	AZ           string            // topology.kubernetes.io/zone
	AppLabels    map[string]string // app/app.kubernetes.io/name 等标签
}

// AppLabelsJSON 返回 AppLabels 的 JSON 字符串（写入 ClickHouse 用）
func (t *CloudTag) AppLabelsJSON() string {
	if len(t.AppLabels) == 0 {
		return "{}"
	}
	b, _ := json.Marshal(t.AppLabels)
	return string(b)
}

// ── MetaProvider 接口 ────────────────────────────────────

// MetaProvider 云标签查询接口（热路径，必须 O(1)，不阻塞）
type MetaProvider interface {
	GetTag(ip string) *CloudTag
}

// ── NoopMetaProvider：未启用时的空实现 ──────────────────

type NoopMetaProvider struct{}

func (n *NoopMetaProvider) GetTag(_ string) *CloudTag { return nil }

// ── K8sMetaProvider：基于 Informer 的实现 ───────────────

// K8sMetaProvider 使用 SharedInformerFactory 维护 IP→CloudTag 映射
type K8sMetaProvider struct {
	client  kubernetes.Interface
	cfg     config.CloudMetaConfig

	// SharedInformerFactory 管理 Pod/Service/Node 的 Informer 生命周期
	// 多个 controller 可共享同一 factory 的 Informer（不重复 Watch）
	factory informers.SharedInformerFactory

	// 各资源 Informer（启动后通过 EventHandler 自动维护本地缓存）
	podInformer  cache.SharedIndexInformer
	svcInformer  cache.SharedIndexInformer
	nodeInformer cache.SharedIndexInformer

	// IP → CloudTag 快速查找表
	// 由 Informer EventHandler 回调更新（极低频写）
	// 由 GetTag 读取（高频读）
	// sync.Map 保证无锁并发安全
	ipTagMap sync.Map // map[podIP string]*CloudTag

	stopCh chan struct{}
}

// NewK8sMetaProvider 创建 K8s 云标签提供者（不启动 Informer，调用 Start 启动）
func NewK8sMetaProvider(cfg config.CloudMetaConfig) (*K8sMetaProvider, error) {
	restCfg, err := buildRestConfig(cfg.Kubernetes)
	if err != nil {
		return nil, fmt.Errorf("build k8s rest config: %w", err)
	}

	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("create k8s client: %w", err)
	}

	// SharedInformerFactory：
	//   - defaultResync = cfg.SyncInterval（定期触发 EventHandler 的 UpdateFunc，防止漂移）
	//   - 若 SyncInterval=0，使用 2min 默认值
	resync := cfg.SyncInterval
	if resync <= 0 {
		resync = 2 * time.Minute
	}
	factory := informers.NewSharedInformerFactory(client, resync)

	p := &K8sMetaProvider{
		client:       client,
		cfg:          cfg,
		factory:      factory,
		podInformer:  factory.Core().V1().Pods().Informer(),
		svcInformer:  factory.Core().V1().Services().Informer(),
		nodeInformer: factory.Core().V1().Nodes().Informer(),
		stopCh:       make(chan struct{}),
	}

	// 注册 Pod EventHandler（增量维护 IP→CloudTag 映射）
	p.podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if pod, ok := obj.(*corev1.Pod); ok {
				p.upsertPodTag(pod)
			}
		},
		UpdateFunc: func(_, newObj interface{}) {
			if pod, ok := newObj.(*corev1.Pod); ok {
				p.upsertPodTag(pod)
			}
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				// 处理 DeletedFinalStateUnknown：
				// 当 Watch 断线期间发生删除，Informer 用 tombstone 传递
				// 必须处理此情况，否则会漏掉 GC 窗口内的删除事件
				if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
					pod, ok = tombstone.Obj.(*corev1.Pod)
					if !ok {
						return
					}
				} else {
					return
				}
			}
			if pod.Status.PodIP != "" {
				p.ipTagMap.Delete(pod.Status.PodIP)
				log.WithField("pod_ip", pod.Status.PodIP).Debug("CloudTag deleted (pod removed)")
			}
		},
	})

	return p, nil
}

// Start 启动所有 Informer 并等待缓存初次同步完成
//
// WaitForCacheSync 保证：
//   1. List 全量 API 调用已完成
//   2. EventHandler 的 AddFunc 已对所有现有对象回调完毕
//   3. 本地缓存（ipTagMap）与 API Server 完全一致
//   超时 30s 后返回错误，但 Informer 仍继续运行
func (p *K8sMetaProvider) Start(ctx context.Context) error {
	// 启动 factory 中所有已注册的 Informer
	// 内部用 goroutine 运行 ListWatch，stopCh 关闭时停止
	p.factory.Start(p.stopCh)

	log.Info("Waiting for K8s Informer caches to sync (Pod/Service/Node)...")

	// WaitForCacheSync 会阻塞直到：
	//   • HasSynced 全部返回 true（List 完成 + 初始 AddFunc 回调完成）
	//   • ctx 超时（30s）
	syncCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	synced := cache.WaitForCacheSync(
		syncCtx.Done(),
		p.podInformer.HasSynced,
		p.svcInformer.HasSynced,
		p.nodeInformer.HasSynced,
	)
	if !synced {
		// 超时不是致命错误：Informer 仍在运行，只是启动时数据可能不完整
		// 返回 warn 级别错误，调用方可选择继续
		return fmt.Errorf("k8s informer cache sync timeout (30s), continuing anyway")
	}

	count := 0
	p.ipTagMap.Range(func(_, _ interface{}) bool { count++; return true })
	log.WithFields(log.Fields{
		"cached_pod_ips": count,
		"resync":         p.cfg.SyncInterval,
	}).Info("K8s Informer caches synced")
	return nil
}

// GetTag 根据 IP 查找云标签（O(1)，无锁，热路径安全）
func (p *K8sMetaProvider) GetTag(ip string) *CloudTag {
	if v, ok := p.ipTagMap.Load(ip); ok {
		return v.(*CloudTag)
	}
	return nil
}

// upsertPodTag 从 Pod 对象构建 CloudTag 并存入 ipTagMap
// 由 Informer EventHandler 回调，运行在 Informer goroutine 中
func (p *K8sMetaProvider) upsertPodTag(pod *corev1.Pod) {
	if pod.Status.PodIP == "" {
		return // Pod 尚未分配 IP（Pending 状态），跳过
	}

	tag := p.buildCloudTag(pod)
	p.ipTagMap.Store(pod.Status.PodIP, tag)

	log.WithFields(log.Fields{
		"pod_ip":    pod.Status.PodIP,
		"pod":       pod.Namespace + "/" + pod.Name,
		"service":   tag.ServiceName,
		"node":      tag.NodeName,
		"region":    tag.Region,
		"az":        tag.AZ,
	}).Debug("CloudTag upserted")
}

// buildCloudTag 从 Pod 对象构建完整的 CloudTag
func (p *K8sMetaProvider) buildCloudTag(pod *corev1.Pod) *CloudTag {
	tag := &CloudTag{
		PodName:      pod.Name,
		PodNamespace: pod.Namespace,
		NodeName:     pod.Spec.NodeName,
		PodIP:        pod.Status.PodIP,
		AppLabels:    make(map[string]string),
	}

	// 提取 app 相关标签（对齐 DeepFlow app_labels 字段）
	appLabelKeys := []string{
		"app",
		"app.kubernetes.io/name",
		"app.kubernetes.io/component",
		"app.kubernetes.io/part-of",
		"app.kubernetes.io/version",
		"version",
		"tier",
		"component",
		"environment",
		"env",
	}
	for _, k := range appLabelKeys {
		if v, ok := pod.Labels[k]; ok {
			tag.AppLabels[k] = v
		}
	}

	// 注入用户自定义额外标签（config.cloud_meta.extra_labels）
	for k, v := range p.cfg.ExtraLabels {
		tag.AppLabels[k] = v
	}

	// 通过 Service Informer 本地缓存反查 Service 名称（零 API 调用）
	tag.ServiceName = p.resolveServiceName(pod)

	// 通过 Node Informer 本地缓存获取 region/az（拓扑标签）
	if pod.Spec.NodeName != "" {
		tag.Region, tag.AZ = p.resolveNodeTopology(pod.Spec.NodeName)
	}

	return tag
}

// resolveServiceName 在本地 Service 缓存中查找 selector 匹配该 Pod 的 Service
// 使用 Lister 接口（纯本地查询，不访问 API Server）
func (p *K8sMetaProvider) resolveServiceName(pod *corev1.Pod) string {
	svcLister := p.factory.Core().V1().Services().Lister()
	svcs, err := svcLister.Services(pod.Namespace).List(labels.Everything())
	if err != nil {
		return ""
	}

	podLabelSet := labels.Set(pod.Labels)
	for _, svc := range svcs {
		if len(svc.Spec.Selector) == 0 {
			continue // Headless service 或 ExternalName，无 selector
		}
		sel := labels.Set(svc.Spec.Selector).AsSelector()
		if sel.Matches(podLabelSet) {
			return svc.Name
		}
	}
	return ""
}

// resolveNodeTopology 从 Node 本地缓存读取拓扑标签（region/az）
func (p *K8sMetaProvider) resolveNodeTopology(nodeName string) (region, az string) {
	nodeLister := p.factory.Core().V1().Nodes().Lister()
	node, err := nodeLister.Get(nodeName)
	if err != nil {
		return "", ""
	}

	// 优先使用新版拓扑标签（K8s 1.17+）
	region = node.Labels["topology.kubernetes.io/region"]
	az = node.Labels["topology.kubernetes.io/zone"]

	// 兜底使用旧版 beta 标签（K8s < 1.17）
	if region == "" {
		region = node.Labels["failure-domain.beta.kubernetes.io/region"]
	}
	if az == "" {
		az = node.Labels["failure-domain.beta.kubernetes.io/zone"]
	}
	return region, az
}

// Stats 返回当前缓存统计信息（用于监控/debug）
func (p *K8sMetaProvider) Stats() map[string]interface{} {
	count := 0
	p.ipTagMap.Range(func(_, _ interface{}) bool { count++; return true })
	return map[string]interface{}{
		"cached_pod_ips": count,
		"pod_synced":     p.podInformer.HasSynced(),
		"svc_synced":     p.svcInformer.HasSynced(),
		"node_synced":    p.nodeInformer.HasSynced(),
	}
}

// DumpTags 返回所有 IP→Tag 快照（debug/admin API 用）
func (p *K8sMetaProvider) DumpTags() map[string]*CloudTag {
	result := make(map[string]*CloudTag)
	p.ipTagMap.Range(func(k, v interface{}) bool {
		result[k.(string)] = v.(*CloudTag)
		return true
	})
	return result
}

// Stop 优雅停止所有 Informer
func (p *K8sMetaProvider) Stop() {
	close(p.stopCh)
	log.Info("K8s Informer stopped")
}

// ── K8s REST Config 构建 ─────────────────────────────────

func buildRestConfig(cfg config.K8sConfig) (*rest.Config, error) {
	// 优先 InCluster（运行在 Pod 内）
	if cfg.InCluster {
		restCfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("in-cluster config: %w", err)
		}
		return restCfg, nil
	}

	// kubeconfig 文件路径
	kubeconfig := cfg.KubeConfigPath
	if kubeconfig == "" {
		// 默认 ~/.kube/config
		home := os.Getenv("HOME")
		if home == "" {
			home = "/root"
		}
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig %s: %w", kubeconfig, err)
	}
	return restCfg, nil
}
