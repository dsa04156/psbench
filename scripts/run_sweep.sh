#!/usr/bin/env bash
set -euo pipefail
NS=psbench
DUR=60
F_SET=(1 4 16 64 256)
M_SET=(1 2 4)
P_SET=(100 512 1024)
CASES=(A Q K B C)  # A:UDP, Q:MQTT, K:Kafka, B:Kernel-1, C:Kernel-2

ts() { date -u +"%Y%m%dT%H%M%SZ"; }
ensure_ns(){ kubectl get ns $NS >/dev/null 2>&1 || kubectl create ns $NS; }

ensure_ns

for case in "${CASES[@]}"; do
  for m in "${M_SET[@]}"; do
    # M은 구독자 노드수 의미. 중앙 브로커(Q/K/A)는 단일 인스턴스 유지(일반 배치 가정).
    for f in "${F_SET[@]}"; do
      for p in "${P_SET[@]}"; do
        echo "RUN case=$case M=$m F=$f payload=$p"

        case $case in
          A)
            kubectl -n $NS scale deploy/psbench-broker --replicas 1 || true
            kubectl -n $NS scale deploy/psbench-publisher --replicas 1 || true
            kubectl -n $NS scale deploy/psbench-subscriber --replicas $f || true
            kubectl -n $NS set args deploy/psbench-publisher -- -topic=1 -qps=100000 -payload=$p -dst=$(kubectl -n $NS get pod -l app=psbench-publisher -o jsonpath='{.items[0].status.hostIP}'):32000
            ;;
          Q)
            kubectl -n $NS apply -f deploy/mqtt.yaml
            kubectl -n $NS apply -f deploy/mqtt_clients.yaml
            kubectl -n $NS scale deploy/psbench-mqtt-subscriber --replicas $f
            kubectl -n $NS set args deploy/psbench-mqtt-publisher -- -topic=1 -qps=100000 -payload=$p
            ;;
          K)
            kubectl -n $NS apply -f deploy/kafka.yaml
            kubectl -n $NS apply -f deploy/kafka_clients.yaml
            kubectl -n $NS scale deploy/psbench-kafka-subscriber --replicas $f
            kubectl -n $NS set args deploy/psbench-kafka-publisher -- -topic=1 -qps=100000 -payload=$p
            ;;
          B)
            kubectl -n $NS set env ds/psbench-loader PS_MODE=B || true
            kubectl -n $NS scale deploy/psbench-subscriber --replicas $f || true
            ;;
          C)
            kubectl -n $NS set env ds/psbench-loader PS_MODE=C || true
            kubectl -n $NS scale deploy/psbench-subscriber --replicas $f || true
            ;;
        esac

        sleep $DUR

        FN="out_${case}_M${m}_F${f}_P${p}_$(ts).jsonl"
        case $case in
          A|B|C)
            kubectl -n $NS logs -l app=subscriber --tail=-1 > "results/${FN}" || true ;;
          Q)
            kubectl -n $NS logs -l app=psbench-mqtt-subscriber --tail=-1 > "results/${FN}" || true ;;
          K)
            kubectl -n $NS logs -l app=psbench-kafka-subscriber --tail=-1 > "results/${FN}" || true ;;
        esac
      done
    done
  done
done

