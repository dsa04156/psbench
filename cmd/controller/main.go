package main

// 컨트롤러: K8s API에서 subscriber Pods를 스캔하여
// topic→node_set, node→local_sub 맵을 비활성 세대에 preload 후 flip.
//
// 규칙(합리적 가정):
// - 구독자 Pod 라벨: app=subscriber, ps/topic=<u32>
// - 구독자 포트: env PS_UDP_PORT (기본 31001)
// - 노드 ID: 노드명 사전순 인덱싱(0..M-1)
// - 1차 노드 dport: 32000
// - BPFFS 핀 루트: /sys/fs/bpf/psbench

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	pinRoot         = "/sys/fs/bpf/psbench"
	ns              = "psbench"
	firstTierPort   = 32000 // hop=1 수신 노드 포트
)

type nodeDest struct {
	NodeID uint32
	Daddr  uint32
	Dport  uint16
	Pad    uint16
}

type subDest struct {
	Ifindex uint32
	Daddr   uint32
	Dport   uint16
	Pad     uint16
}

func mustOpen(name string) *ebpf.Map {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinRoot, name), nil)
	if err != nil { log.Fatalf("open map %s: %v", name, err) }
	return m
}

func getNodes(client *kubernetes.Clientset) ([]v1.Node, map[string]uint32, map[string]string) {
	list, err := client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil { log.Fatalf("list nodes: %v", err) }
	nodes := list.Items
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	idxMap := map[string]uint32{}
	ipMap := map[string]string{}
	for i, n := range nodes {
		idxMap[n.Name] = uint32(i)
		// pick InternalIP
		var ip string
		for _, a := range n.Status.Addresses {
			if a.Type == v1.NodeInternalIP { ip = a.Address; break }
		}
		ipMap[n.Name] = ip
	}
	return nodes, idxMap, ipMap
}

func toNBO(ip string) uint32 {
	var b [4]byte
	fmt.Sscanf(ip, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3])
	return binary.BigEndian.Uint32(b[:])
}

func getPodPort(p v1.Pod) int {
	for _, c := range p.Spec.Containers {
		for _, e := range c.Env {
			if e.Name == "PS_UDP_PORT" {
				if v, err := strconv.Atoi(e.Value); err == nil { return v }
			}
		}
	}
	return 31001
}

func main() {
	cfg, err := rest.InClusterConfig()
	if err != nil { log.Fatalf("kube: %v", err) }
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil { log.Fatalf("kube client: %v", err) }

	_, nodeID, nodeIP := getNodes(client)
	topics := mustOpen("topic_to_node_set_gen0")   // we'll decide inactive dynamically
	topics1 := mustOpen("topic_to_node_set_gen1")
	tcnt0 := mustOpen("topic_fanout_cnt_gen0")
	tcnt1 := mustOpen("topic_fanout_cnt_gen1")
	nsubs0 := mustOpen("node_to_local_sub_gen0")
	nsubs1 := mustOpen("node_to_local_sub_gen1")
	ncnt0 := mustOpen("node_local_cnt_gen0")
	ncnt1 := mustOpen("node_local_cnt_gen1")
	active := mustOpen("m_active_gen")

	for {
		// 1) 현재 활성 세대 읽기
		var k uint32 = 0
		var ag uint32
		if err := active.Lookup(&k, &ag); err != nil { log.Fatalf("active_gen: %v", err) }
		inactive := uint32(1 - ag)

		// 2) K8s에서 subscriber 수집
		pods, err := client.CoreV1().Pods(ns).List(context.Background(), metav1.ListOptions{
			LabelSelector: "app=subscriber",
		})
		if err != nil { log.Fatalf("list pods: %v", err) }

		// topic → node set
		type nodeKey struct{ node string }
		type topicKey struct{ topic uint32 }
		topicNodes := map[uint32]map[string]struct{}{}
		// node → local subs
		nodeSubs := map[string][]v1.Pod{}

		for _, p := range pods.Items {
			if p.Status.PodIP == "" || p.Spec.NodeName == "" { continue }
			// topic id
			var tID uint32 = 1
			if v, ok := p.Labels["ps/topic"]; ok {
				if x, err := strconv.Atoi(v); err == nil { tID = uint32(x) }
			}
			if _, ok := topicNodes[tID]; !ok { topicNodes[tID] = map[string]struct{}{} }
			topicNodes[tID][p.Spec.NodeName] = struct{}{}
			nodeSubs[p.Spec.NodeName] = append(nodeSubs[p.Spec.NodeName], p)
		}

		// 3) 비활성 세대에 preload
		var tmap, tcnt, nmap, ncnt *ebpf.Map
		if inactive == 0 {
			tmap, tcnt, nmap, ncnt = topics, tcnt0, nsubs0, ncnt0
		} else {
			tmap, tcnt, nmap, ncnt = topics1, tcnt1, nsubs1, ncnt1
		}

		// clear: 간단화 위해 전체 삭제(실험용)
		_ = tmap.Close(); _ = tcnt.Close(); _ = nmap.Close(); _ = ncnt.Close()
		// 재-open (clear는 bpftool 사용이 이상적이나, 여기선 재시작/재배포로 관리 권장)
		topics = mustOpen("topic_to_node_set_gen0")
		topics1 = mustOpen("topic_to_node_set_gen1")
		tcnt0 = mustOpen("topic_fanout_cnt_gen0")
		tcnt1 = mustOpen("topic_fanout_cnt_gen1")
		nsubs0 = mustOpen("node_to_local_sub_gen0")
		nsubs1 = mustOpen("node_to_local_sub_gen1")
		ncnt0 = mustOpen("node_local_cnt_gen0")
		ncnt1 = mustOpen("node_local_cnt_gen1")
		if inactive == 0 {
			tmap, tcnt, nmap, ncnt = topics, tcnt0, nsubs0, ncnt0
		} else {
			tmap, tcnt, nmap, ncnt = topics1, tcnt1, nsubs1, ncnt1
		}

		// topic → node inner
		for tID, set := range topicNodes {
			inner, err := ebpf.NewMap(&ebpf.MapSpec{
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  12,
				MaxEntries: 256, // MAX_FANOUT
				Pinning:    ebpf.PinByName,
				Name:       fmt.Sprintf("topic_%d_nodes", tID),
			})
			if err != nil { log.Fatalf("inner nodes: %v", err) }
			i := uint32(0)
			for n := range set {
				nd := nodeDest{
					NodeID: nodeID[n],
					Daddr:  toNBO(nodeIP[n]),
					Dport:  uint16(firstTierPort),
				}
				if err := inner.Update(&i, &nd, ebpf.UpdateAny); err != nil {
					log.Fatalf("inner update: %v", err)
				}
				i++
			}
			if err := tmap.Update(&tID, inner.FD(), ebpf.UpdateAny); err != nil {
				log.Fatalf("outer topic map update: %v", err)
			}
			if err := tcnt.Update(&tID, &i, ebpf.UpdateAny); err != nil {
				log.Fatalf("topic cnt: %v", err)
			}
		}

		// node → local subs
		for n, pods := range nodeSubs {
			nid := nodeID[n]
			inner, err := ebpf.NewMap(&ebpf.MapSpec{
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  12,
				MaxEntries: 512, // MAX_LOCAL_SUB
				Pinning:    ebpf.PinByName,
				Name:       fmt.Sprintf("node_%d_subs", nid),
			})
			if err != nil { log.Fatalf("inner subs: %v", err) }
			for i := uint32(0); i < uint32(len(pods)); i++ {
				p := pods[i]
				port := getPodPort(p)
				sd := subDest{
					Ifindex: 0, // cfg.local_route_ifindex 사용
					Daddr:   toNBO(p.Status.PodIP),
					Dport:   uint16(port),
				}
				if err := inner.Update(&i, &sd, ebpf.UpdateAny); err != nil {
					log.Fatalf("inner sub update: %v", err)
				}
			}
			cnt := uint32(len(pods))
			if err := nmap.Update(&nid, inner.FD(), ebpf.UpdateAny); err != nil {
				log.Fatalf("outer node map update: %v", err)
			}
			if err := ncnt.Update(&nid, &cnt, ebpf.UpdateAny); err != nil {
				log.Fatalf("node cnt: %v", err)
			}
		}

		// 4) flip
		if err := active.Update(&k, &inactive, ebpf.UpdateAny); err != nil {
			log.Fatalf("flip: %v", err)
		}
		log.Printf("flipped active_gen=%d", inactive)

		time.Sleep(5 * time.Second)
	}
}
