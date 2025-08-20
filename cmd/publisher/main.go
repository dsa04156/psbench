package main

// 퍼블리셔: UDP 32000으로 hop=0 패킷 송신. QPS 제어, 페이로드 사이즈, 토픽 설정.

import (
	"encoding/binary"
	"flag"
	"log"
	"math/rand"
	"net"
	"time"
)

func main() {
	topic := flag.Uint("topic", 1, "topic id")
	qps := flag.Int("qps", 50000, "messages per second")
	payload := flag.Int("payload", 100, "payload bytes (not including 8B header)")
	dst := flag.String("dst", "255.255.255.255:32000", "dst (for TC(B)/C use nodeIP:32000 of local node)")
	flag.Parse()

	raddr, _ := net.ResolveUDPAddr("udp", *dst)
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil { log.Fatal(err) }
	defer conn.Close()

	msg := make([]byte, 8+*payload)
	binary.BigEndian.PutUint32(msg[:4], uint32(*topic))
	binary.BigEndian.PutUint16(msg[4:6], 0)
	binary.BigEndian.PutUint16(msg[6:8], 0)
	rand.Read(msg[8:])

	tick := time.NewTicker(time.Second / time.Duration(*qps))
	defer tick.Stop()
	sent := 0
	start := time.Now()
	for {
		<-tick.C
		// mutate few bytes for entropy
		binary.BigEndian.PutUint64(msg[8:], uint64(time.Now().UnixNano()))
		if _, err := conn.Write(msg); err == nil {
			sent++
		}
		if sent%100000 == 0 {
			el := time.Since(start).Seconds()
			log.Printf("sent=%d rate=%.1fk/s", sent, float64(sent)/el/1000)
		}
	}
}
