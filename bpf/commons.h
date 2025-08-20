// SPDX-License-Identifier: GPL-2.0
#pragma once

// CO-RE: 커널 타입/구조체는 vmlinux.h 단일 소스에서 가져온다.
#include "vmlinux.h"

// BPF helpers
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// 표준/커널 헤더에 의존하지 않도록 __u* / __s* 별칭을 직접 정의한다.
#ifndef __u8
typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef long long __s64;
#endif

// UAPI 헤더를 include하지 않으므로 필요한 상수만 정의
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

// ------- 프로토콜 고정형 토픽 헤더 -------
struct topic_hdr {
  __u32 topic_id;  // host order
  __u16 flags;     // reserved
  __u16 hop;       // 0:소스, 1:노드, >=2:패스스루
} __attribute__((packed));

// ------- map value 구조 -------
struct node_dest {
  __u32 node_id;
  __u32 daddr;  // NBO
  __u16 dport;  // NBO
  __u16 _pad;
};

struct sub_dest {
  __u32 ifindex;  // 0이면 cfg.local_route_ifindex 사용
  __u32 daddr;    // NBO
  __u16 dport;    // NBO
  __u16 _pad;
};

// 런타임 설정 (키=0 고정)
struct cfg_rec {
  __u32 egress_ifindex;       // 1차 복제 출력 ifindex(소스)
  __u32 local_route_ifindex;  // 2차 복제 기본 ifindex(노드)
  __u32 local_node_id;        // 현재 노드 ID
  __u32 active_gen;           // 0 또는 1 (세대 플립)
};

// 드롭/계측
enum drop_reason {
  DR_OK = 0,
  DR_NOT_UDP,
  DR_TOO_SHORT,
  DR_NO_TOPIC,
  DR_NO_NODESET,
  DR_NO_LOCALSET,
  DR_CLONE_FAIL,
  DR_HELPER_ERR,
  DR_MAX
};

struct metrics {
  __u64 tier1_clones;
  __u64 tier2_clones;
  __u64 drops[DR_MAX];
};

// 상수 바운드 (검증기 우선)
#define MAX_TOPICS 4096
#define MAX_NODES 256
#define MAX_FANOUT 256
#define MAX_LOCAL_SUB 512
#define RINGBUF_SZ (1 << 20)

// 계측 헬퍼 선언(정의는 .c)
static __always_inline void count_drop(__u32 idx, __u32 reason);
static __always_inline void count_clone(__u32 tier);
