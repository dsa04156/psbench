package main

// Loader DaemonSet: 각 노드에서 bpf .o 로드, clsact/ingress attach, 맵 핀 + cfg 설정.
// 권한: NET_ADMIN, BPF, SYS_RESOURCE

import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	pinRoot = "/sys/fs/bpf/psbench"
	objPath = "/usr/local/bin/tc_hier_pubsub_kern.o"
)

func ifindex(name string) (int, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifi.Index, nil
}

func mustEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func ensureDir(p string) {
	_ = os.MkdirAll(p, 0755)
}

func main() {
	ensureDir(pinRoot)

	egressIf := mustEnv("PS_EGRESS_IF", "eth0")
	localRouteIf := mustEnv("PS_LOCAL_ROUTE_IF", "cilium_host")
	nodeIDStr := mustEnv("PS_NODE_ID", "0")

	egressIdx, err := ifindex(egressIf)
	if err != nil { log.Fatalf("egress ifindex: %v", err) }
	localIdx, err := ifindex(localRouteIf)
	if err != nil { log.Fatalf("local route ifindex: %v", err) }
	nodeID, _ := strconv.Atoi(nodeIDStr)

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil { log.Fatalf("load spec: %v", err) }

	// 핀 경로 주입
	for name := range spec.Maps {
		spec.Maps[name].Pinning = ebpf.PinByName
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinRoot},
	})
	if err != nil { log.Fatalf("new collection: %v", err) }
	defer coll.Close()

	// cfg 세팅
	cfg := coll.Maps["m_cfg"]
	key := uint32(0)
	type cfgRec struct {
		EgressIfidx      uint32
		LocalRouteIfidx  uint32
		LocalNodeID      uint32
		Reserved         uint32
	}
	val := cfgRec{uint32(egressIdx), uint32(localIdx), uint32(nodeID), 0}
	if err := cfg.Update(&key, &val, ebpf.UpdateAny); err != nil {
		log.Fatalf("cfg update: %v", err)
	}

	// active_gen 초기값 0
	act := coll.Maps["m_active_gen"]
	zero := uint32(0)
	if err := act.Update(&key, &zero, ebpf.UpdateAny); err != nil {
		log.Fatalf("active_gen init: %v", err)
	}

	// clsact/ingress attach
	prog := coll.Programs["tc_hier_pubsub"]
	dev := mustEnv("PS_ATTACH_DEV", egressIf) // ingress에만 attach, 필요시 여러개 attach
	l, err := link.AttachTC(link.TCOptions{
		Interface:  uint32(egressIdx),
		AttachPoint: link.Ingress,
		Program:    prog,
	})
	if err != nil {
		log.Fatalf("tc attach(%s): %v", dev, err)
	}
	defer l.Close()

	// 핀 확인 로그
	files, _ := os.ReadDir(pinRoot)
	var names []string
	for _, f := range files { names = append(names, f.Name()) }

	log.Printf("psbench loader up. maps pinned in %s: %s", pinRoot, strings.Join(names, ","))
	for { time.Sleep(1 * time.Hour) }
}
