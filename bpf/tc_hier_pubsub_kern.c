// SPDX-License-Identifier: GPL-2.0
#include "commons.h"

// -------------------------- BPF MAPS --------------------------

// 1) 내부 템플릿(반드시 .maps 섹션에서 앞에 위치)
//    - topic->node_set 의 inner array (node_dest)
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_FANOUT);
  __type(key, __u32);
  __type(value, struct node_dest);
} inner_node_set_tmpl SEC(".maps");

//    - node_id->local_sub 의 inner array (sub_dest)
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_LOCAL_SUB);
  __type(key, __u32);
  __type(value, struct sub_dest);
} inner_local_sub_tmpl SEC(".maps");

// 2) topic -> node_set (gen0/gen1), ARRAY_OF_MAPS
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __uint(max_entries, MAX_TOPICS);
  __type(key, __u32);
  __type(value, __u32);      // inner map fd slot
  __uint(inner_map_idx, 0);  // inner_node_set_tmpl
} topic_to_node_set_gen0 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __uint(max_entries, MAX_TOPICS);
  __type(key, __u32);
  __type(value, __u32);
  __uint(inner_map_idx, 0);  // inner_node_set_tmpl
} topic_to_node_set_gen1 SEC(".maps");

// 3) topic fanout count (gen0/gen1)
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_TOPICS);
  __type(key, __u32);
  __type(value, __u32);
} topic_fanout_cnt_gen0 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_TOPICS);
  __type(key, __u32);
  __type(value, __u32);
} topic_fanout_cnt_gen1 SEC(".maps");

// 4) node_id -> local_sub (gen0/gen1), ARRAY_OF_MAPS
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __uint(max_entries, MAX_NODES);
  __type(key, __u32);
  __type(value, __u32);
  __uint(inner_map_idx, 1);  // inner_local_sub_tmpl
} node_to_local_sub_gen0 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __uint(max_entries, MAX_NODES);
  __type(key, __u32);
  __type(value, __u32);
  __uint(inner_map_idx, 1);  // inner_local_sub_tmpl
} node_to_local_sub_gen1 SEC(".maps");

// 5) local_sub count (gen0/gen1)
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_NODES);
  __type(key, __u32);
  __type(value, __u32);
} node_local_cnt_gen0 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_NODES);
  __type(key, __u32);
  __type(value, __u32);
} node_local_cnt_gen1 SEC(".maps");

// 6) cfg (키=0)
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct cfg_rec);
} m_cfg SEC(".maps");

// 7) metrics(per-CPU)
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct metrics);
} m_metrics SEC(".maps");

// 8) ringbuf (옵션)
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, RINGBUF_SZ);
} m_ring SEC(".maps");

// ------------------------ UTIL/HELPERS ------------------------

static __always_inline void count_drop(__u32 idx, __u32 reason) {
  __u32 zero = 0;
  struct metrics *m = bpf_map_lookup_elem(&m_metrics, &zero);
  if (!m) return;
  if (reason < DR_MAX) __sync_fetch_and_add(&m->drops[reason], 1);
}

static __always_inline void count_clone(__u32 tier) {
  __u32 zero = 0;
  struct metrics *m = bpf_map_lookup_elem(&m_metrics, &zero);
  if (!m) return;
  if (tier == 1)
    __sync_fetch_and_add(&m->tier1_clones, 1);
  else if (tier == 2)
    __sync_fetch_and_add(&m->tier2_clones, 1);
}

static __always_inline int parse_headers(
    struct __sk_buff *skb, void **data_p, void **data_end_p,
    struct ethhdr **eth_p, struct iphdr **ip_p, struct udphdr **udp_p,
    struct topic_hdr **th_p, __u32 *l3_off_p, __u32 *l4_off_p) {
  // data/data_end
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  // 이더넷 최소 길이 보장
  if ((void *)((struct ethhdr *)data + 1) > data_end) {
    if (bpf_skb_pull_data(skb, 14)) return -1;
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    if ((void *)((struct ethhdr *)data + 1) > data_end) return -1;
  }

  struct ethhdr *eth = data;
  __u16 h_proto = bpf_ntohs(eth->h_proto);
  if (h_proto != ETH_P_IP) return -1;

  // IPv4
  __u32 l3_off = 14;
  if (data + l3_off + sizeof(struct iphdr) > data_end) {
    if (bpf_skb_pull_data(skb, l3_off + sizeof(struct iphdr))) return -1;
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    if (data + l3_off + sizeof(struct iphdr) > data_end) return -1;
  }
  struct iphdr *ip = (void *)(data + l3_off);
  if (ip->protocol != IPPROTO_UDP) return -1;
  __u32 ihl = ip->ihl * 4;
  if (ihl < sizeof(*ip)) return -1;

  // UDP
  __u32 l4_off = l3_off + ihl;
  if (data + l4_off + sizeof(struct udphdr) > data_end) {
    if (bpf_skb_pull_data(skb, l4_off + sizeof(struct udphdr))) return -1;
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    ip = (void *)(data + l3_off);
    if (data + l4_off + sizeof(struct udphdr) > data_end) return -1;
  }
  struct udphdr *udp = (void *)(data + l4_off);

  // topic header (8B) 존재 확인
  if (data + l4_off + sizeof(*udp) + sizeof(struct topic_hdr) > data_end)
    return -1;
  struct topic_hdr *th = (void *)(data + l4_off + sizeof(*udp));

  *data_p = data;
  *data_end_p = data_end;
  *eth_p = eth;
  *ip_p = ip;
  *udp_p = udp;
  *th_p = th;
  *l3_off_p = l3_off;
  *l4_off_p = l4_off;
  return 0;
}

// --------------------------- MAIN -----------------------------

SEC("tc")
int tc_hier_pubsub(struct __sk_buff *skb) {
  // 설정 읽기
  __u32 zero = 0;
  struct cfg_rec *cfg = bpf_map_lookup_elem(&m_cfg, &zero);
  if (!cfg) return TC_ACT_OK;

  void *data, *data_end;
  struct ethhdr *eth;
  struct iphdr *ip;
  struct udphdr *udp;
  struct topic_hdr *th;
  __u32 l3_off = 0, l4_off = 0;

  if (parse_headers(skb, &data, &data_end, &eth, &ip, &udp, &th, &l3_off,
                    &l4_off) < 0) {
    count_drop(0, DR_NOT_UDP);
    return TC_ACT_OK;
  }

  // 체크섬 오프셋 (IPv4)
  __u32 l3_csum_off = l3_off + 10;  // offsetof(struct iphdr, check)
  __u32 l4_csum_off = l4_off + 6;   // offsetof(struct udphdr, check)

  __u32 topic_id = th->topic_id;
  __u16 hop = th->hop;

  // 활성 세대 선택
  __u32 gen = cfg->active_gen ? 1 : 0;
  void *topic2nodes =
      gen ? (void *)&topic_to_node_set_gen1 : (void *)&topic_to_node_set_gen0;
  void *topic_cnt =
      gen ? (void *)&topic_fanout_cnt_gen1 : (void *)&topic_fanout_cnt_gen0;
  void *node2subs =
      gen ? (void *)&node_to_local_sub_gen1 : (void *)&node_to_local_sub_gen0;
  void *node_cnt =
      gen ? (void *)&node_local_cnt_gen1 : (void *)&node_local_cnt_gen0;

  if (hop == 0) {
    // 1차: topic -> node_set
    void *inner = bpf_map_lookup_elem(topic2nodes, &topic_id);
    if (!inner) {
      count_drop(0, DR_NO_NODESET);
      return TC_ACT_OK;
    }
    __u32 *fanoutp = bpf_map_lookup_elem(topic_cnt, &topic_id);
    __u32 fanout = fanoutp ? *fanoutp : 0;
    if (fanout == 0) {
      count_drop(0, DR_NO_NODESET);
      return TC_ACT_OK;
    }

    // hop 증가 (원본 skb가 마지막 dest에 남는다)
    th->hop = hop + 1;

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < MAX_FANOUT; i++) {
      if (i >= fanout) break;
      struct node_dest *nd = bpf_map_lookup_elem(inner, &i);
      if (!nd) continue;

      __u32 daddr = nd->daddr;  // NBO
      __u16 dport = nd->dport;  // NBO

      // 체크섬 업데이트 + 필드 변경
      bpf_l3_csum_replace(skb, l3_csum_off, ip->daddr, daddr, sizeof(daddr));
      ip->daddr = daddr;

      if (udp->check)  // IPv4에서 0이면 미사용
        bpf_l4_csum_replace(skb, l4_csum_off, udp->dest, dport, sizeof(dport));
      udp->dest = dport;

      // 복제: 마지막 대상은 원본 skb로 전달, 그 외는 clone
      if (i + 1 < fanout) {
        long rc = bpf_clone_redirect(skb, cfg->egress_ifindex, 0);
        if (rc == 0)
          count_clone(1);
        else
          count_drop(0, DR_CLONE_FAIL);
      } else {
        // 원본은 통과
      }
    }
    return TC_ACT_OK;
  } else if (hop == 1) {
    // 2차: node_id -> local_sub
    __u32 nid = cfg->local_node_id;
    void *inner2 = bpf_map_lookup_elem(node2subs, &nid);
    if (!inner2) {
      count_drop(0, DR_NO_LOCALSET);
      return TC_ACT_OK;
    }
    __u32 *localcntp = bpf_map_lookup_elem(node_cnt, &nid);
    __u32 localcnt = localcntp ? *localcntp : 0;
    if (localcnt == 0) {
      count_drop(0, DR_NO_LOCALSET);
      return TC_ACT_OK;
    }

    th->hop = hop + 1;

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < MAX_LOCAL_SUB; i++) {
      if (i >= localcnt) break;
      struct sub_dest *sd = bpf_map_lookup_elem(inner2, &i);
      if (!sd) continue;

      __u32 daddr = sd->daddr;  // NBO
      __u16 dport = sd->dport;  // NBO
      __u32 ifi = sd->ifindex ? sd->ifindex : cfg->local_route_ifindex;

      bpf_l3_csum_replace(skb, l3_csum_off, ip->daddr, daddr, sizeof(daddr));
      ip->daddr = daddr;

      if (udp->check)
        bpf_l4_csum_replace(skb, l4_csum_off, udp->dest, dport, sizeof(dport));
      udp->dest = dport;

      if (i + 1 < localcnt) {
        long rc = bpf_clone_redirect(skb, ifi, 0);
        if (rc == 0)
          count_clone(2);
        else
          count_drop(0, DR_CLONE_FAIL);
      } else {
        // 마지막 대상은 원본 skb로
      }
    }
    return TC_ACT_OK;
  }

  // hop >= 2: 패스스루
  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
