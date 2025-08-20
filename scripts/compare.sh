#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PY'
import pandas as pd, matplotlib.pyplot as plt
df = pd.read_csv('results/summary.csv')
for m in sorted(df.M.unique()):
    for p in sorted(df.payload.unique()):
        d = df[(df.M==m)&(df.payload==p)]
        plt.figure()
        for case in ['A','B','C']:
            dd = d[d['case']==case].sort_values('F')
            plt.plot(dd['F'], dd['qps'], marker='o', label=f'{case}-QPS')
        plt.xscale('log', basex=2)
        plt.xlabel('Fanout F'); plt.ylabel('QPS'); plt.legend(); plt.title(f'QPS vs F (M={m}, payload={p}B)')
        plt.savefig(f'results/qps_M{m}_P{p}.png', bbox_inches='tight')
        plt.close()

        plt.figure()
        for case in ['A','B','C']:
            dd = d[d['case']==case].sort_values('F')
            plt.plot(dd['F'], dd['p99_us'], marker='o', label=f'{case}-p99')
        plt.xscale('log', basex=2)
        plt.xlabel('Fanout F'); plt.ylabel('p99 latency (us)'); plt.legend(); plt.title(f'p99 vs F (M={m}, payload={p}B)')
        plt.savefig(f'results/p99_M{m}_P{p}.png', bbox_inches='tight')
        plt.close()
PY
echo "PNG 그래프가 results/ 에 생성되었습니다."
