// pkg/l7/kafka.go
// Kafka 协议解析器（Kafka 二进制协议 v0~v9）。
//
// Kafka 请求帧格式：
//   [0:4]   Message Length（int32，不含自身）
//   [4:6]   API Key（int16）
//   [6:8]   API Version（int16）
//   [8:12]  Correlation ID（int32，用于请求/响应配对）
//   [12:]   Client ID（string，len int16 + bytes）...
//
// Kafka 响应帧格式：
//   [0:4]   Message Length（int32）
//   [4:8]   Correlation ID（int32）
//   [8:]    Response Body...
//
// 已知 API Key 常量：
//   0=Produce 1=Fetch 3=Metadata 8=OffsetCommit 9=OffsetFetch
//  11=FindCoordinator 12=JoinGroup 14=LeaveGroup 15=SyncGroup
//  16=DescribeGroups 17=ListGroups 18=SaslHandshake 19=ApiVersions
//  32=DescribeConfigs

package l7

import (
	"encoding/binary"
	"time"

	"observer/pkg/ebpf"
)

// Kafka API Key 枚举
const (
	kafkaAPIKeyProduce       uint16 = 0
	kafkaAPIKeyFetch         uint16 = 1
	kafkaAPIKeyMetadata      uint16 = 3
	kafkaAPIKeyOffsetCommit  uint16 = 8
	kafkaAPIKeyOffsetFetch   uint16 = 9
	kafkaAPIKeyFindCoord     uint16 = 11
	kafkaAPIKeyJoinGroup     uint16 = 12
	kafkaAPIKeyLeaveGroup    uint16 = 14
	kafkaAPIKeySyncGroup     uint16 = 15
	kafkaAPIKeyApiVersions   uint16 = 18
	kafkaAPIKeySaslHandshake uint16 = 17
)

var kafkaAPIKeyNames = map[uint16]string{
	kafkaAPIKeyProduce:       "Produce",
	kafkaAPIKeyFetch:         "Fetch",
	kafkaAPIKeyMetadata:      "Metadata",
	kafkaAPIKeyOffsetCommit:  "OffsetCommit",
	kafkaAPIKeyOffsetFetch:   "OffsetFetch",
	kafkaAPIKeyFindCoord:     "FindCoordinator",
	kafkaAPIKeyJoinGroup:     "JoinGroup",
	kafkaAPIKeyLeaveGroup:    "LeaveGroup",
	kafkaAPIKeySyncGroup:     "SyncGroup",
	kafkaAPIKeyApiVersions:   "ApiVersions",
	kafkaAPIKeySaslHandshake: "SaslHandshake",
}

// KafkaParser Kafka 二进制协议解析器。
type KafkaParser struct{}

func NewKafkaParser() *KafkaParser { return &KafkaParser{} }

func (p *KafkaParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolKafka }

func (p *KafkaParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	// Kafka 默认端口
	if srcPort == 9092 || dstPort == 9092 ||
		srcPort == 9093 || dstPort == 9093 {
		return true
	}
	if len(payload) < 12 {
		return false
	}
	// 检查帧长度合法性（Message Length 必须 > 4 且 < 100MB）
	msgLen := int32(binary.BigEndian.Uint32(payload[0:4]))
	if msgLen < 4 || msgLen > 100*1024*1024 {
		return false
	}
	// API Key 必须在已知范围内（0~67）
	apiKey := binary.BigEndian.Uint16(payload[4:6])
	return apiKey <= 67
}

func (p *KafkaParser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	if len(payload) < 12 {
		return nil
	}

	msgLen := int32(binary.BigEndian.Uint32(payload[0:4]))
	if msgLen < 4 {
		return nil
	}

	apiKey := binary.BigEndian.Uint16(payload[4:6])
	correlID := int32(binary.BigEndian.Uint32(payload[8:12]))

	result := &ParseResult{
		Protocol:      ebpf.L7ProtocolKafka,
		StartTime:     ts,
		EndTime:       ts,
		KafkaAPIKey:   apiKey,
		KafkaCorrelID: correlID,
	}

	// 判断请求 vs 响应：请求帧有 API Key 和版本信息，响应只有 Correlation ID
	// 启发式：payload[4:6] 是 API Key（请求）或高字节为 0 的响应数据（响应）
	// 更可靠的方法：根据端口方向判断
	isRequest := direction == 0 // ingress = 请求进入服务端

	if isRequest && apiKey <= 67 {
		// Kafka 请求
		result.ReqType = ebpf.L7RequestTypeRequest
		apiName := kafkaAPIKeyName(apiKey)
		result.RequestType = apiName
		result.RequestResource = apiName

		// 解析 Produce 请求（提取 topic）
		if apiKey == kafkaAPIKeyProduce && len(payload) >= 20 {
			topic, partition, msgCount, msgBytes := parseProduceRequest(payload)
			result.KafkaTopic = topic
			result.KafkaPartition = partition
			result.KafkaMsgCount = msgCount
			result.KafkaMsgBytes = msgBytes
			result.RequestResource = topic
		}
		// 解析 Fetch 请求（提取 topic）
		if apiKey == kafkaAPIKeyFetch && len(payload) >= 24 {
			topic, partition := parseFetchRequest(payload)
			result.KafkaTopic = topic
			result.KafkaPartition = partition
			result.RequestResource = topic
		}
	} else {
		// Kafka 响应（根据 Correlation ID 与请求配对）
		result.ReqType = ebpf.L7RequestTypeResponse
		// 响应错误码在 payload[8] 之后，具体偏移取决于 API
		if len(payload) >= 10 {
			errCode := int16(binary.BigEndian.Uint16(payload[8:10]))
			result.KafkaErrCode = errCode
			if errCode != 0 {
				result.ResponseStatus = 2
				result.ResponseCode = int64(errCode)
			} else {
				result.ResponseStatus = 0
			}
		}
	}

	return result
}

// kafkaAPIKeyName 返回 API Key 的可读名称。
func kafkaAPIKeyName(key uint16) string {
	if name, ok := kafkaAPIKeyNames[key]; ok {
		return name
	}
	return "Unknown"
}

// parseProduceRequest 从 Produce 请求中提取 topic/partition/消息数量/消息字节数。
// v0/v1 格式（简化解析，跳过 Client ID）：
//   [12:14]  Client ID len
//   [14:14+n] Client ID
//   [14+n:16+n] 2 bytes acks（required_acks）
//   [16+n:20+n] 4 bytes timeout_ms
//   [20+n:24+n] 4 bytes array length（topic partitions）
//   [24+n:26+n] 2 bytes topic len
//   [26+n:...]  topic bytes
func parseProduceRequest(payload []byte) (topic string, partition int32, msgCount int32, msgBytes int64) {
	offset := 12
	if len(payload) < offset+2 {
		return
	}
	// Client ID
	clientIDLen := int(int16(binary.BigEndian.Uint16(payload[offset : offset+2])))
	offset += 2
	if clientIDLen > 0 {
		offset += clientIDLen
	}
	// acks(2) + timeout_ms(4) + array_len(4) = 10 bytes
	offset += 10
	if len(payload) < offset+2 {
		return
	}
	// Topic
	topicLen := int(int16(binary.BigEndian.Uint16(payload[offset : offset+2])))
	offset += 2
	if topicLen > 0 && len(payload) >= offset+topicLen {
		topic = string(payload[offset : offset+topicLen])
		offset += topicLen
	}
	// Partition array: array_len(4) + partition(4) + partition_size(4) ...
	offset += 4 // array_len
	if len(payload) >= offset+4 {
		partition = int32(binary.BigEndian.Uint32(payload[offset : offset+4]))
		offset += 4
	}
	// Record batch size
	if len(payload) >= offset+4 {
		batchSize := int64(binary.BigEndian.Uint32(payload[offset : offset+4]))
		msgBytes = batchSize
		// 简单估算消息数量（每条消息平均至少 14 字节开销）
		if batchSize > 0 {
			msgCount = int32(batchSize / 64) // 粗略估算
			if msgCount == 0 {
				msgCount = 1
			}
		}
	}
	return
}

// parseFetchRequest 从 Fetch 请求中提取 topic/partition（简化版）。
func parseFetchRequest(payload []byte) (topic string, partition int32) {
	offset := 12
	if len(payload) < offset+2 {
		return
	}
	clientIDLen := int(int16(binary.BigEndian.Uint16(payload[offset : offset+2])))
	offset += 2 + clientIDLen
	// max_wait_ms(4) + min_bytes(4) + array_len(4) = 12
	offset += 12
	if len(payload) < offset+2 {
		return
	}
	topicLen := int(int16(binary.BigEndian.Uint16(payload[offset : offset+2])))
	offset += 2
	if topicLen > 0 && len(payload) >= offset+topicLen {
		topic = string(payload[offset : offset+topicLen])
		offset += topicLen
	}
	// partition_data array_len(4) + partition(4)
	offset += 4
	if len(payload) >= offset+4 {
		partition = int32(binary.BigEndian.Uint32(payload[offset : offset+4]))
	}
	return
}
