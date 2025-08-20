package main

// MQTT 퍼블리셔 (QoS0, 베스트에포트)
import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"log"
	"math/rand"
	"os"
	"time"
)

func main() {
	topicID := flag.Uint("topic", 1, "topic id")
	qps := flag.Int("qps", 50000, "messages per second")
	payload := flag.Int("payload", 512, "payload bytes (excluding 8B topic hdr)")
	flag.Parse()

	broker := os.Getenv("MQTT_BROKER")
	if broker == "" { broker = "tcp://mosquitto.psbench.svc.cluster.local:1883" }
	topic := fmt.Sprintf("t/%d", *topicID)

	opts := mqtt.NewClientOptions().
		AddBroker(broker).
		SetClientID(fmt.Sprintf("pub-%d", time.Now().UnixNano())).
		SetCleanSession(true).
		SetAutoReconnect(false).
		SetTLSConfig(&tls.Config{InsecureSkipVerify: true})
	c := mqtt.NewClient(opts)
	if tok := c.Connect(); tok.Wait() && tok.Error() != nil { log.Fatal(tok.Error()) }
	defer c.Disconnect(250)

	msg := make([]byte, 8+*payload)
	// 고정형 8B header: topic(u32), flags(u16=0), hop(u16=0) — MQTT에서는 파싱만 맞추기용
	binary.BigEndian.PutUint32(msg[:4], uint32(*topicID))
	binary.BigEndian.PutUint16(msg[4:6], 0)
	binary.BigEndian.PutUint16(msg[6:8], 0)

	rand.Read(msg[16:]) // 타임스탬프 뒤 영역 임의값
	interval := time.Second / time.Duration(*qps)
	if interval == 0 { interval = time.Microsecond } // 안전조치
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		// payload[0:8]에 송신 타임스탬프(ns) 삽입 (구독자 지연 계산용)
		binary.BigEndian.PutUint64(msg[8:16], uint64(time.Now().UnixNano()))
		// QoS0, Retain=false
		if tok := c.Publish(topic, 0, false, msg); tok.Error() != nil {
			// 베스트에포트: 에러는 드롭
			_ = tok.Error()
		}
	}
}

