package main

// 구독자: UDP 수신, p50/p99 측정(간이), JSON 로그 표준출력.

import (
	"encoding/binary"
	"encoding/json"
	"log"
	"math"
	"net"
	"os"
	"time"
)

type Rec struct {
	TS    time.Time `json:"ts"`
	P50   float64   `json:"p50_us"`
	P99   float64   `json:"p99_us"`
	QPS   float64   `json:"qps"`
	Drops uint64    `json:"drops"`
}

func main() {
	port := os.Getenv("PS_UDP_PORT")
	if port == "" { port = "31001" }
	addr, _ := net.ResolveUDPAddr("udp", ":"+port)
	conn, err := net.ListenUDP("udp", addr)
	if err != nil { log.Fatal(err) }
	defer conn.Close()

	var lat []float64
	buf := make([]byte, 65535)
	var recv, lastRecv uint64
	ticker := time.NewTicker(1 * time.Second)
	start := time.Now()

	for {
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err == nil && n >= 16 {
			// payload 첫 8바이트에 publisher 타임스탬프가 들어온다고 가정 (publisher가 넣음)
			sendNs := int64(binary.BigEndian.Uint64(buf[8:16]))
			latUs := float64(time.Now().UnixNano()-sendNs) / 1000.0
			lat = append(lat, latUs)
			recv++
		}
		select {
		case <-ticker.C:
			el := time.Since(start).Seconds()
			qps := float64(recv-lastRecv)
			lastRecv = recv
			if len(lat) > 0 {
				cp := append([]float64(nil), lat...)
				lat = lat[:0]
				p50 := quantile(cp, 0.50)
				p99 := quantile(cp, 0.99)
				rec := Rec{TS: time.Now(), P50: p50, P99: p99, QPS: qps, Drops: 0}
				j, _ := json.Marshal(rec)
				os.Stdout.Write(j); os.Stdout.Write([]byte("\n"))
			} else {
				rec := Rec{TS: time.Now(), P50: 0, P99: 0, QPS: qps, Drops: 0}
				j, _ := json.Marshal(rec)
				os.Stdout.Write(j); os.Stdout.Write([]byte("\n"))
			}
			_ = el
		default:
		}
	}
}

func quantile(x []float64, q float64) float64 {
	if len(x) == 0 { return 0 }
	quickselect(x, int(math.Ceil(q*float64(len(x))))-1)
	return x[int(math.Ceil(q*float64(len(x))))-1]
}

func quickselect(a []float64, k int) {
	l, r := 0, len(a)-1
	for l < r {
		p := partition(a, l, r)
		if k == p { return }
		if k < p { r = p-1 } else { l = p+1 }
	}
}

func partition(a []float64, l, r int) int {
	p := a[r]; i := l
	for j := l; j < r; j++ {
		if a[j] < p { a[i], a[j] = a[j], a[i]; i++ }
	}
	a[i], a[r] = a[r], a[i]
	return i
}
