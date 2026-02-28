// pkg/l7/kafka.go
// Kafka 二进制协议解析器（Kafka Wire Protocol）
//
// ── 请求帧结构（Request Header v1，Kafka 0.10+）─────────────────────────────
//
//   ┌──────────────────────────────────────────────────────┐
//   │  message_size  (4 B, int32, 不含自身)                │  偏移 0
//   │  api_key       (2 B, int16)                          │  偏移 4
//   │  api_version   (2 B, int16)                          │  偏移 6
//   │  correlation_id(4 B, int32)                          │  偏移 8
//   │  client_id     (2+N B, nullable string)              │  偏移 12
//   │  request body  (variable)                            │
//   └──────────────────────────────────────────────────────┘
//
// ── 响应帧结构（Response Header v0）────────────────────────────────────────
//
//   ┌──────────────────────────────────────────────────────┐
//   │  message_size  (4 B, int32)                          │  偏移 0
//   │  correlation_id(4 B, int32)                          │  偏移 4
//   │  response body (variable)                            │  偏移 8
//   └──────────────────────────────────────────────────────┘
//
// ── API Key 常量（Kafka 3.x，https://kafka.apache.org/protocol.html）────────
//
//   0=Produce  1=Fetch  2=ListOffsets  3=Metadata  4=LeaderAndIsr
//   5=StopReplica  6=UpdateMetadata  7=ControlledShutdown  8=OffsetCommit
//   9=OffsetFetch  10=FindCoordinator  11=JoinGroup  12=Heartbeat
//   13=LeaveGroup  14=SyncGroup  15=DescribeGroups  16=ListGroups
//   17=SaslHandshake  18=ApiVersions  19=CreateTopics  20=DeleteTopics
//   21=DeleteRecords  22=InitProducerId  23=OffsetForLeaderEpoch
//   24=AddPartitionsToTxn  25=AddOffsetsToTxn  26=EndTxn
//   36=SaslAuthenticate  37=CreatePartitions  42=DeleteGroups
//   50=DescribeUserScramCredentials
//
// ── 协议识别策略 ─────────────────────────────────────────────────────────────
//
//   CanParse：
//     端口 9092/9093（最强特征）。
//     无端口时：4 字节 BE message_size 合法性（4 ≤ size ≤ 100MB）
//     + api_key ∈ [0, 67]（Kafka 3.x 最大已知 API）
//     + api_version ∈ [0, 12]（已知版本范围）
//     三个条件 AND，假阳性率极低。
//
//   Parse：
//     direction=0（ingress）→ 请求包
//     direction=1（egress）→ 响应包
//     对 Produce/Fetch 请求额外解析 topic 字段。

package l7

import (
	"encoding/binary"
	"time"

	"observer/pkg/ebpf"
)

// ── Kafka API Key 常量 ────────────────────────────────────────────────────────

const (
	kafkaProduce          uint16 = 0
	kafkaFetch            uint16 = 1
	kafkaListOffsets      uint16 = 2
	kafkaMetadata         uint16 = 3
	kafkaOffsetCommit     uint16 = 8
	kafkaOffsetFetch      uint16 = 9
	kafkaFindCoordinator  uint16 = 10
	kafkaJoinGroup        uint16 = 11
	kafkaHeartbeat        uint16 = 12
	kafkaLeaveGroup       uint16 = 13
	kafkaSyncGroup        uint16 = 14
	kafkaDescribeGroups   uint16 = 15
	kafkaListGroups       uint16 = 16
	kafkaSaslHandshake    uint16 = 17
	kafkaApiVersions      uint16 = 18
	kafkaCreateTopics     uint16 = 19
	kafkaDeleteTopics     uint16 = 20
	kafkaInitProducerId   uint16 = 22
	kafkaSaslAuthenticate uint16 = 36
	kafkaMaxKnownAPI      uint16 = 67 // Kafka 3.x 已知最大 API Key
)

var kafkaAPINames = map[uint16]string{
	kafkaProduce:          "Produce",
	kafkaFetch:            "Fetch",
	kafkaListOffsets:      "ListOffsets",
	kafkaMetadata:         "Metadata",
	kafkaOffsetCommit:     "OffsetCommit",
	kafkaOffsetFetch:      "OffsetFetch",
	kafkaFindCoordinator:  "FindCoordinator",
	kafkaJoinGroup:        "JoinGroup",
	kafkaHeartbeat:        "Heartbeat",
	kafkaLeaveGroup:       "LeaveGroup",
	kafkaSyncGroup:        "SyncGroup",
	kafkaDescribeGroups:   "DescribeGroups",
	kafkaListGroups:       "ListGroups",
	kafkaSaslHandshake:    "SaslHandshake",
	kafkaApiVersions:      "ApiVersions",
	kafkaCreateTopics:     "CreateTopics",
	kafkaDeleteTopics:     "DeleteTopics",
	kafkaInitProducerId:   "InitProducerId",
	kafkaSaslAuthenticate: "SaslAuthenticate",
}

// KafkaParser Kafka Wire Protocol 解析器。
type KafkaParser struct{}

func NewKafkaParser() *KafkaParser { return &KafkaParser{} }

func (p *KafkaParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolKafka }

func (p *KafkaParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	if srcPort == 9092 || dstPort == 9092 || srcPort == 9093 || dstPort == 9093 {
		return true
	}
	if len(payload) < 12 {
		return false
	}
	msgSize := int32(binary.BigEndian.Uint32(payload[0:4]))
	apiKey := binary.BigEndian.Uint16(payload[4:6])
	apiVersion := binary.BigEndian.Uint16(payload[6:8])

	return msgSize >= 4 && // 最小有效帧
		msgSize <= 100*1024*1024 && // ≤ 100 MB
		apiKey <= kafkaMaxKnownAPI &&
		apiVersion <= 12 // 已知最大版本
}

func (p *KafkaParser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	if len(payload) < 8 {
		return nil
	}

	msgSize := int32(binary.BigEndian.Uint32(payload[0:4]))
	if msgSize < 4 || msgSize > 100*1024*1024 {
		return nil
	}

	result := &ParseResult{
		Protocol:  ebpf.L7ProtocolKafka,
		StartTime: ts,
		EndTime:   ts,
	}

	// ingress（direction=0）→ 请求；egress → 响应
	isRequest := direction == 0

	if isRequest && len(payload) >= 12 {
		apiKey := binary.BigEndian.Uint16(payload[4:6])
		correlID := int32(binary.BigEndian.Uint32(payload[8:12]))

		if apiKey > kafkaMaxKnownAPI {
			return nil
		}

		result.ReqType = ebpf.L7RequestTypeRequest
		result.KafkaAPIKey = apiKey
		result.KafkaCorrelID = correlID
		result.RequestType = kafkaAPIName(apiKey)
		result.RequestResource = result.RequestType

		switch apiKey {
		case kafkaProduce:
			topic, partition, msgCount, msgBytes := parseKafkaProduceReq(payload)
			result.KafkaTopic = topic
			result.KafkaPartition = partition
			result.KafkaMsgCount = int32(msgCount)
			result.KafkaMsgBytes = msgBytes
			if topic != "" {
				result.RequestResource = topic
			}
		case kafkaFetch:
			topic, partition := parseKafkaFetchReq(payload)
			result.KafkaTopic = topic
			result.KafkaPartition = partition
			if topic != "" {
				result.RequestResource = topic
			}
		}
	} else {
		// 响应帧：[message_size(4)][correlation_id(4)][body...]
		if len(payload) < 8 {
			return nil
		}
		correlID := int32(binary.BigEndian.Uint32(payload[4:8]))
		result.ReqType = ebpf.L7RequestTypeResponse
		result.KafkaCorrelID = correlID

		// 尝试从响应体首部提取错误码
		// Produce/Fetch 响应的错误码偏移因版本而异，此处做保守估算
		if len(payload) >= 12 {
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

// ── Produce 请求解析 ──────────────────────────────────────────────────────────
//
// Produce Request v0/v1（简化版，支持单 topic 单 partition）：
//   [message_size(4)][api_key(2)][api_version(2)][correlation_id(4)]
//   [client_id_len(2)][client_id(N)]
//   [required_acks(2)][timeout_ms(4)]
//   [topic_array_len(4)]
//     [topic_len(2)][topic(N)]
//     [partition_array_len(4)]
//       [partition(4)][record_batch_size(4)][...]

func parseKafkaProduceReq(payload []byte) (topic string, partition int32, msgCount, msgBytes int64) {
	offset := 12
	if len(payload) < offset+2 {
		return
	}
	// client_id
	clientIDLen := int(int16(binary.BigEndian.Uint16(payload[offset : offset+2])))
	offset += 2
	if clientIDLen > 0 && clientIDLen < 1024 {
		offset += clientIDLen
	}
	// required_acks(2) + timeout_ms(4) + topic_array_len(4) = 10
	offset += 10
	if len(payload) < offset+2 {
		return
	}
	topicLen := int(int16(binary.BigEndian.Uint16(payload[offset : offset+2])))
	offset += 2
	if topicLen > 0 && topicLen < 4096 && len(payload) >= offset+topicLen {
		topic = string(payload[offset : offset+topicLen])
		offset += topicLen
	}
	// partition_array_len(4) + partition(4)
	offset += 4
	if len(payload) >= offset+4 {
		partition = int32(binary.BigEndian.Uint32(payload[offset : offset+4]))
		offset += 4
	}
	// record_batch_size(4)
	if len(payload) >= offset+4 {
		batchSize := int64(binary.BigEndian.Uint32(payload[offset : offset+4]))
		msgBytes = batchSize
		if batchSize > 0 {
			msgCount = batchSize/64 + 1 // 粗略估算
		}
	}
	return
}

// parseKafkaFetchReq 从 Fetch 请求中提取 topic/partition。
func parseKafkaFetchReq(payload []byte) (topic string, partition int32) {
	offset := 12
	if len(payload) < offset+2 {
		return
	}
	clientIDLen := int(int16(binary.BigEndian.Uint16(payload[offset : offset+2])))
	offset += 2
	if clientIDLen > 0 && clientIDLen < 1024 {
		offset += clientIDLen
	}
	// max_wait_ms(4) + min_bytes(4) + topic_array_len(4) = 12
	offset += 12
	if len(payload) < offset+2 {
		return
	}
	topicLen := int(int16(binary.BigEndian.Uint16(payload[offset : offset+2])))
	offset += 2
	if topicLen > 0 && topicLen < 4096 && len(payload) >= offset+topicLen {
		topic = string(payload[offset : offset+topicLen])
		offset += topicLen
	}
	// partition_array_len(4) + partition(4)
	offset += 4
	if len(payload) >= offset+4 {
		partition = int32(binary.BigEndian.Uint32(payload[offset : offset+4]))
	}
	return
}

func kafkaAPIName(key uint16) string {
	if name, ok := kafkaAPINames[key]; ok {
		return name
	}
	return "Unknown"
}
