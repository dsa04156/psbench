package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"log"
	"math"
	"os"
	"sync"
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
	broker := os.Getenv("MQTT_BROKER")
	if broker == "" { broker = "tcp://mosquitto.psbench.svc.cluster.local:1883" }
	topicID := os.Getenv("MQTT_TOPIC_ID"); if topicID == "" { topicID = "1" }
	topic := fmt.Sprintf("t/%s", topicID)

	opts := mqtt.NewClientOptions().
		AddBroker(broker).
		SetClientID(fmt.Sprintf("sub-%d", time.Now().UnixNano())).
		SetCleanSession(true).
		SetAutoReconnect(false).
		SetTLSConfig(&tls.Config{InsecureSkipVerify: true})
	c := mqtt.NewClient(opts)
	if tok := c.Connect(); tok.Wait() && tok.Error() != nil { log.Fatal(tok.Error()) }
	defer c.Disconnect(250)

	var mu sync.Mutex
	var lat []float64
	var recv, last uint64
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	cb := func(_ mqtt.Client, m mqtt.Message) {
		b := m.Payload()
		if len(b) < 16 { return }
		sendNs := int64(binary.BigEndian.Uint64(b[8:16]))
		lus := float64(time.Now().UnixNano()-sendNs) / 1000.0
		mu.Lock()
		lat = append(lat, lus)
		recv++
		mu.Unlock()
	}
	if tok := c.Subscribe(topic, 0, cb); tok.Wait() && tok.Error() != nil { log.Fatal(tok.Error()) }

	for range ticker.C {
		mu.Lock()
		cp := append([]float64(nil), lat...); lat = lat[:0]
		rx := recv; dqps := float64(rx-last); last = rx
		mu.Unlock()
		var p50, p99 float64
		if len(cp) > 0 {
			p50 = quant(cp, 0.5); p99 = quant(cp, 0.99)
		}
		r := Rec{TS: time.Now(), P50: p50, P99: p99, QPS: dqps, Drops: 0}
		j, _ := json.Marshal(r); os.Stdout.Write(j); os.Stdout.Write([]byte("\n"))
	}
}

func quant(x []float64, q float64) float64 {
	if len(x) == 0 { return 0 }
	quickselect(x, int(math.Ceil(q*float64(len(x))))-1)
	return x[int(math.Ceil(q*float64(len(x))))-1]
}
func quickselect(a []float64, k int) { l,r:=0,len(a)-1; for l<r { p:=part(a,l,r); if k==p{return}; if k<p{r=p-1}else{l=p+1} } }
func part(a []float64,l,r int)int{ p:=a[r]; i:=l; for j:=l;j<r;j++{ if a[j]<p{ a[i],a[j]=a[j],a[i]; i++ } } a[i],a[r]=a[r],a[i]; return i }

