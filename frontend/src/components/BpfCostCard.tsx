'use client';
import type { BpfProgStat } from '@/types';

interface Props {
  bpfProgStats: BpfProgStat[];
}

// classify_and_shape run_time_ns/run_cnt delta between paired before/after
// bpftool snapshots — isolates the classifier's own CPU cost (ns/packet) from
// overall throughput, per protocol across trials.
export default function BpfCostCard({ bpfProgStats }: Props) {
  const byKey: Record<string, { before?: BpfProgStat; after?: BpfProgStat }> = {};
  for (const r of bpfProgStats) {
    const key = `${r.protocol}|${r.trial_no}`;
    if (!byKey[key]) byKey[key] = {};
    byKey[key][r.phase] = r;
  }

  const nsPerPacket: Record<string, number[]> = {};
  for (const { before, after } of Object.values(byKey)) {
    if (!before || !after) continue;
    const dTime = Number(after.run_time_ns) - Number(before.run_time_ns);
    const dCnt  = Number(after.run_cnt)    - Number(before.run_cnt);
    if (dCnt > 0) {
      const proto = after.protocol;
      (nsPerPacket[proto] ??= []).push(dTime / dCnt);
    }
  }

  const protocols = Object.keys(nsPerPacket);
  if (!protocols.length) return null;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
      {protocols.map(proto => {
        const vals = nsPerPacket[proto];
        const mean = vals.reduce((a, b) => a + b, 0) / vals.length;
        const min  = Math.min(...vals);
        const max  = Math.max(...vals);
        return (
          <div key={proto} className="card p-4">
            <p className="font-mono text-xs text-muted uppercase tracking-wider mb-1">{proto.toUpperCase()} — classify_and_shape cost</p>
            <p className="font-mono text-2xl font-bold text-accent leading-none mb-1">{mean.toFixed(1)}<span className="text-sm text-muted"> ns/packet</span></p>
            <p className="font-mono text-xs text-muted">min {min.toFixed(1)} · max {max.toFixed(1)} · n={vals.length} trials</p>
          </div>
        );
      })}
    </div>
  );
}
