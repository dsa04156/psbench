package proto

// 고정형 8B 헤더 직렬화/역직렬화 도우미 (Go 사이드에서 필요시 사용)

import "encoding/binary"

type TopicHdr struct {
	Topic uint32
	Flags uint16
	Hop   uint16
}

func (h *TopicHdr) MarshalTo(b []byte) {
	binary.BigEndian.PutUint32(b[:4], h.Topic)
	binary.BigEndian.PutUint16(b[4:6], h.Flags)
	binary.BigEndian.PutUint16(b[6:8], h.Hop)
}
