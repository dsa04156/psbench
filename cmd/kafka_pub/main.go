package main

// Kafka 퍼블리셔 (acks=0, 베스트에포트)
import (
	"encoding/binary"
	"flag"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/Shopify/sarama"
)

func main() {
	topicID := flag.Uint("topic", 1, "topic id")
	qps := flag.Int("qps", 50000, "messages per second")
	payload := flag.Int("payload", 512, "payload bytes (excluding 8B header)")
	flag.Parse()

	bs := os.Getenv("KAFKA_BOOTSTRAP")
	if bs == "" { bs = "kafka.psbench.svc.cluster.local:9092" }
	topic := "t-" + os.Getenv("KAFKA_TOPIC_ID")
	if os.Getenv("KAFKA_TOPIC_ID") == "" { topic = "t-1" }

	cfg := sarama.NewConfig()
	cfg.Producer.RequiredAcks = sarama.NoResponse
	cfg.Producer.Return.Successes = false
	cfg.Producer.Idempotent = false
	cfg.Producer.Compression = sarama.CompressionNone
	cfg.Producer.Flush.Frequency = 0
	cfg.Producer.Flush.Bytes = 0
	cfg.Net.MaxOpenRequests = 1

	prod, err := sarama.NewAsyncProducer(strings.Split(bs, ","), cfg)
	if err != nil { log.Fatal(err) }
	defer prod.Close()

	msg := make([]byte, 8+*payload)
	binary.BigEndian.PutUint32(msg[:4], uint32(*topicID))
	binary.BigEndian.PutUint16(msg[4:6], 0)
	binary.BigEndian.PutUint16(msg[6:8], 0)
	rand.Read(msg[16:])

	interval := time.Second / time.Duration(*qps)
	if interval == 0 { interval = time.Microsecond }
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		binary.BigEndian.PutUint64(msg[8:16], uint64(time.Now().UnixNano()))
		prod.Input() <- &sarama.ProducerMessage{
			Topic: topic,
			Value: sarama.ByteEncoder(msg),
		}
	}
}
       
