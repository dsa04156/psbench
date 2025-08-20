package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"log"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Shopify/sarama"
)

type Rec struct {
	TS    time.Time `json:"ts"`
	P50   float64   `json:"p50_us"`
	P99   float64   `json:"p99_us"`
	QPS   float64   `json:"qps"`
	Drops uint64    `json:"drops"`
}

type handler struct {
	mu   sync.Mutex
	lat  []float64
	recv uint64
}

func (h *handler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (h *handler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }
func (h *handler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for m := range claim.Messages() {
		b := m.Value
		if len(b) >= 16 {
			sendNs := int64(binary.BigEndian.Uint64(b[8:16]))
			lus := float64(time.Now().UnixNano()-sendNs) / 1000.0
			h.mu.Lock()
			h.lat = append(h.lat, lus)
			h.recv++
			h.mu.Unlock()
		}
		sess.MarkMessage(m, "")
	}
	return nil
}

func main() {
	bs := os.Getenv("KAFKA_BOOTSTRAP")
	if bs == "" { bs = "kafka.psbench.svc.cluster.local:9092" }
	topic := "t-" + os.Getenv("KAFKA_TOPIC_ID")
	if os.Getenv("KAFKA_TOPIC_ID") == "" { topic = "t-1" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" {
		// 각 구독자가 전체 메시지를 받도록, consumer-group을 Pod별 고유값으로 설정
		group = "psbench-" + time.Now().Format("150405.000000000")
	}

	cfg := sarama.NewConfig()
	cfg.Version = sarama.V3_7_0_0
	cfg.Consumer.Return.Errors = false
	cfg.Consumer.Offsets.Initial = sarama.OffsetNewest
	cg, err := sarama.NewConsumerGroup(strings.Split(bs, ","), group, cfg)
	if err != nil { log.Fatal(err) }
	defer cg.Close()

	h := &handler{}
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	go func() {
		for {
			if err := cg.Consume(context.Background(), []string{topic}, h); err != nil {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	var last uint64
	for range ticker.C {
		h.mu.Lock()
		cp := append([]float64(nil), h.lat...); h.lat = h.lat[:0]
		recv := h.recv; dqps := float64(recv-last); last = recv
		h.mu.Unlock()

		var p50, p99 float64
		if len(cp) > 0 { p50 = quant(cp, 0.5); p99 = quant(cp, 0.99) }
		rec := Rec{TS: time.Now(), P50: p50, P99: p99, QPS: dqps, Drops: 0}
		j, _ := json.Marshal(rec); os.Stdout.Write(j); os.Stdout.Write([]byte("\n"))
	}
}

func quant(x []float64, q float64) float64 {
	if len(x) == 0 { return 0 }
	quickselect(x, int(math.Ceil(q*float64(len(x))))-1)
	return x[int(math.Ceil(q*float64(len(x))))-1]
}
func quickselect(a []float64, k int) { l,r:=0,len(a)-1; for l<r { p:=part(a,l,r); if k==p{return}; if k<p{r=p-1}else{l=p+1} } }
func part(a []float64,l,r int)int{ p:=a[r]; i:=l; for j:=l;j<r;j++{ if a[j]<p{ a[i],a[j]=a[j],a[i]; i++ } } a[i],a[r]=a[r],a[i]; return i }

