// pkg/l7/mqtt.go
// MQTT 协议解析器（MQTT 3.1.1 / MQTT 5.0，OASIS 标准）
//
// ── MQTT 固定头格式 ──────────────────────────────────────────────────────────
//
//   ┌──────────────────────────────────────────────┐
//   │  Byte 1: [PacketType(4)|Flags(4)]            │
//   │  Byte 2+: Remaining Length（变长 LE，1~4 B） │
//   └──────────────────────────────────────────────┘
//
//   PacketType（高 4 位）：
//     0x1=CONNECT    0x2=CONNACK    0x3=PUBLISH    0x4=PUBACK
//     0x5=PUBREC     0x6=PUBREL     0x7=PUBCOMP    0x8=SUBSCRIBE
//     0x9=SUBACK     0xA=UNSUBSCRIBE 0xB=UNSUBACK   0xC=PINGREQ
//     0xD=PINGRESP   0xE=DISCONNECT  0xF=AUTH（MQTT 5.0）
//
//   PUBLISH Flags（低 4 位）：
//     DUP(3) QoS(2:1) RETAIN(0)
//
// ── Remaining Length 编码 ────────────────────────────────────────────────────
//
//   可变字节整数：每字节低 7 位是有效位，高位（continuation bit）= 1 表示后续还有字节。
//   最多 4 字节，最大值 268435455（≈ 256MB）。
//
// ── 协议识别策略 ─────────────────────────────────────────────────────────────
//
//   CanParse：
//     端口 1883（MQTT over TCP）或 8883（MQTT over TLS）。
//     无端口时：Byte 1 高 4 位 ∈ [1,15]，且 CONNECT magic bytes：
//       CONNECT 报文第 5~10 字节为 "MQTT"（MQTT 3.1.1）或 "MQIsdp"（MQTT 3.1）。
//
//   Parse：
//     CONNECT：提取 ClientID、Keep-Alive、Protocol Level
//     PUBLISH：提取 Topic、QoS、Payload 大小
//     CONNACK：提取 Return Code（3.1.1）或 Reason Code（5.0）
//     其余控制报文：识别类型，不深度解析

package l7

import (
	"encoding/binary"
	"time"

	"observer/pkg/ebpf"
)

// ── MQTT 包类型常量 ───────────────────────────────────────────────────────────

const (
	mqttConnect     = 0x1
	mqttConnack     = 0x2
	mqttPublish     = 0x3
	mqttPuback      = 0x4
	mqttPubrec      = 0x5
	mqttPubrel      = 0x6
	mqttPubcomp     = 0x7
	mqttSubscribe   = 0x8
	mqttSuback      = 0x9
	mqttUnsubscribe = 0xA
	mqttUnsuback    = 0xB
	mqttPingreq     = 0xC
	mqttPingresp    = 0xD
	mqttDisconnect  = 0xE
	mqttAuth        = 0xF // MQTT 5.0
)

var mqttPacketNames = map[uint8]string{
	mqttConnect:     "CONNECT",
	mqttConnack:     "CONNACK",
	mqttPublish:     "PUBLISH",
	mqttPuback:      "PUBACK",
	mqttPubrec:      "PUBREC",
	mqttPubrel:      "PUBREL",
	mqttPubcomp:     "PUBCOMP",
	mqttSubscribe:   "SUBSCRIBE",
	mqttSuback:      "SUBACK",
	mqttUnsubscribe: "UNSUBSCRIBE",
	mqttUnsuback:    "UNSUBACK",
	mqttPingreq:     "PINGREQ",
	mqttPingresp:    "PINGRESP",
	mqttDisconnect:  "DISCONNECT",
	mqttAuth:        "AUTH",
}

// MQTTParser MQTT 3.1.1 / 5.0 协议解析器。
type MQTTParser struct{}

func NewMQTTParser() *MQTTParser { return &MQTTParser{} }

func (p *MQTTParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolMQTT }

func (p *MQTTParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	if srcPort == 1883 || dstPort == 1883 || srcPort == 8883 || dstPort == 8883 {
		return true
	}
	if len(payload) < 4 {
		return false
	}
	pktType := payload[0] >> 4
	if pktType < 1 || pktType > 15 {
		return false
	}
	// CONNECT 报文特征：固定头 0x10，可变头中含 "MQTT" 或 "MQIsdp"
	if pktType == mqttConnect && len(payload) >= 8 {
		// 跳过固定头（2 B）+ 协议名长度（2 B）→ 偏移 4
		// MQTT 3.1.1: "MQTT"（4 字节）
		// MQTT 3.1:   "MQIsdp"（6 字节）
		if len(payload) >= 8 &&
			payload[4] == 'M' && payload[5] == 'Q' && payload[6] == 'T' && payload[7] == 'T' {
			return true
		}
		if len(payload) >= 10 &&
			payload[4] == 'M' && payload[5] == 'Q' && payload[6] == 'I' && payload[7] == 's' {
			return true
		}
	}
	return false
}

func (p *MQTTParser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	if len(payload) < 2 {
		return nil
	}

	pktType := payload[0] >> 4
	flags := payload[0] & 0x0F

	// 解析 Remaining Length（可变字节整数）
	remainLen, headerLen, ok := decodeMQTTVarInt(payload[1:])
	if !ok {
		return nil
	}
	headerLen++ // 加上第一个字节（固定头 byte 1）

	result := &ParseResult{
		Protocol:       ebpf.L7ProtocolMQTT,
		StartTime:      ts,
		EndTime:        ts,
		MQTTPacketType: pktType,
		RequestType:    mqttPacketName(pktType),
	}

	body := payload[headerLen:]
	if len(body) > int(remainLen) {
		body = body[:remainLen]
	}

	switch pktType {
	case mqttConnect:
		result.ReqType = ebpf.L7RequestTypeRequest
		parseConnectPayload(result, body)

	case mqttConnack:
		result.ReqType = ebpf.L7RequestTypeResponse
		parseConnackPayload(result, body)

	case mqttPublish:
		// QoS 在 Flags 的 [2:1] 位
		qos := (flags >> 1) & 0x3
		result.MQTTQoS = qos
		if qos == 0 {
			result.ReqType = ebpf.L7RequestTypeSession
		} else {
			result.ReqType = ebpf.L7RequestTypeRequest
		}
		parsePublishPayload(result, body, flags)

	case mqttPuback, mqttPubrec, mqttPubrel, mqttPubcomp,
		mqttSuback, mqttUnsuback:
		result.ReqType = ebpf.L7RequestTypeResponse
		result.ResponseStatus = 0

	case mqttSubscribe:
		result.ReqType = ebpf.L7RequestTypeRequest
		parseSusbcribePayload(result, body)

	case mqttUnsubscribe:
		result.ReqType = ebpf.L7RequestTypeRequest

	case mqttPingreq:
		result.ReqType = ebpf.L7RequestTypeRequest

	case mqttPingresp:
		result.ReqType = ebpf.L7RequestTypeResponse

	case mqttDisconnect:
		result.ReqType = ebpf.L7RequestTypeSession

	case mqttAuth: // MQTT 5.0
		result.ReqType = ebpf.L7RequestTypeSession

	default:
		return nil
	}

	return result
}

// ── MQTT 各报文解析子函数 ────────────────────────────────────────────────────

// parseConnectPayload 解析 CONNECT 报文可变头 + Payload。
// 格式：[ProtocolName(2+N)][ProtocolLevel(1)][ConnectFlags(1)][KeepAlive(2)]
//        [ClientID(2+N)][Will..?][Username..?][Password..?]
func parseConnectPayload(result *ParseResult, body []byte) {
	offset := 0
	// Protocol Name（2 字节长度 + N 字节名称）
	if len(body) < 2 {
		return
	}
	protoNameLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2 + protoNameLen

	if offset >= len(body) {
		return
	}
	// Protocol Level（1 字节）：4=MQTT 3.1.1，5=MQTT 5.0
	offset++

	// Connect Flags + Keep-Alive
	offset += 3

	// Client ID
	if offset+2 > len(body) {
		return
	}
	clientIDLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if clientIDLen > 0 && offset+clientIDLen <= len(body) {
		result.MQTTClientID = string(body[offset : offset+clientIDLen])
		result.RequestResource = result.MQTTClientID
	}
}

// parseConnackPayload 解析 CONNACK 报文。
// MQTT 3.1.1：[ConnAckFlags(1)][ReturnCode(1)]
// MQTT 5.0：  [ConnAckFlags(1)][ReasonCode(1)][Properties...]
func parseConnackPayload(result *ParseResult, body []byte) {
	if len(body) < 2 {
		result.ResponseStatus = 0
		return
	}
	returnCode := body[1]
	result.MQTTReturnCode = returnCode
	if returnCode == 0 {
		result.ResponseStatus = 0
	} else {
		result.ResponseStatus = 2
		result.ResponseCode = int64(returnCode)
	}
}

// parsePublishPayload 解析 PUBLISH 报文，提取 Topic 和 Payload 大小。
// 格式：[TopicName(2+N)][PacketID(2，仅 QoS>0)][Payload]
func parsePublishPayload(result *ParseResult, body []byte, flags uint8) {
	if len(body) < 2 {
		return
	}
	topicLen := int(binary.BigEndian.Uint16(body[0:2]))
	offset := 2
	if topicLen > 0 && offset+topicLen <= len(body) {
		result.MQTTTopic = string(body[offset : offset+topicLen])
		result.RequestResource = result.MQTTTopic
		offset += topicLen
	}
	qos := (flags >> 1) & 0x3
	if qos > 0 {
		offset += 2 // Packet Identifier
	}
	if offset < len(body) {
		result.MQTTPayloadSize = int32(len(body) - offset)
	}
}

// parseSusbcribePayload 从 SUBSCRIBE 报文提取第一个订阅 topic。
func parseSusbcribePayload(result *ParseResult, body []byte) {
	if len(body) < 4 {
		return
	}
	// [PacketID(2)][TopicLen(2)][Topic(N)][QoS(1)]
	offset := 2
	topicLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if topicLen > 0 && offset+topicLen <= len(body) {
		result.MQTTTopic = string(body[offset : offset+topicLen])
		result.RequestResource = result.MQTTTopic
	}
}

// decodeMQTTVarInt 解析 MQTT 可变字节整数（最多 4 字节）。
// 返回：值、消耗的字节数、是否成功。
func decodeMQTTVarInt(data []byte) (value uint32, size int, ok bool) {
	var multiplier uint32 = 1
	for size < 4 && size < len(data) {
		b := data[size]
		value += uint32(b&0x7F) * multiplier
		size++
		if b&0x80 == 0 {
			return value, size, true
		}
		multiplier *= 128
	}
	return 0, 0, false
}

func mqttPacketName(pktType uint8) string {
	if name, ok := mqttPacketNames[pktType]; ok {
		return name
	}
	return "UNKNOWN"
}
