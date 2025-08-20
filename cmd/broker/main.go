package main

// 비교군 (A) 사용자공간 브로커 (단일 단계)
// publisher -> broker(0.0.0.0:32000) -> subscribers (라벨/서비스 디스커버리 없이 ENV로 목록 주입)

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"strings"
)

type topicHdr struct {
	Topic uint32
	Flags uint16
	Hop   uint16
}

func parseHdr(b []byte) (topicHdr, []byte, bool) {
	if len(b) < 8 { return topicHdr{}, nil, false }
	h := topicHdr{
		Topic: binary.BigEndian.Uint32(b[:4]),
		Flags: binary.BigEndian.Uint16(b[4:6]),
		Hop:   binary.BigEndian.Uint16(b[6:8]),
	}
	return h, b[8:], true
}

func main() {
	subs := strings.Split(os.Getenv("SUBS"), ",") // "10.0.0.10:31001,10.0.0.11:31001"
	addr, _ := net.ResolveUDPAddr("udp", ":32000")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil { log.Fatal(err) }
	defer conn.Close()
	buf := make([]byte, 65535)

	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil { continue }
		_ = src
		h, payload, ok := parseHdr(buf[:n])
		if !ok { continue }
		h.Hop = 1
		for _, s := range subs {
			ra, err := net.ResolveUDPAddr("udp", s)
			if err != nil { continue }
			pkt := make([]byte, 8+len(payload))
			binary.BigEndian.PutUint32(pkt[:4], h.Topic)
			binary.BigEndian.PutUint16(pkt[4:6], h.Flags)
			binary.BigEndian.PutUint16(pkt[6:8], h.Hop)
			copy(pkt[8:], payload)
			_, _ = conn.WriteToUDP(pkt, ra)
		}
	}
}
