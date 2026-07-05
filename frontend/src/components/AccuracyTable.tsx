import clsx from 'clsx';
import type { QosMetrics } from '@/types';

interface Props {
  metrics: { no_qos?: QosMetrics; htb?: QosMetrics; ebpf?: QosMetrics };
}

const TARGETS: Record<string, number> = { ef: 500, af: 300, be: 200 };
const TC_LABELS: Record<string, string> = { ef: 'EF', af: 'AF', be: 'BE' };

function accClass(pct: number) {
  if (pct >= 95) return 'text-green-400';
  if (pct >= 80) return 'text-yellow-400';
  return 'text-red-400';
}

function pill(pct: number, label: string) {
  const cls = pct >= 95 ? 'bg-green-400/10 text-green-400 border-green-400/20'
            : pct >= 80  ? 'bg-yellow-400/10 text-yellow-400 border-yellow-400/20'
            :               'bg-red-400/10 text-red-400 border-red-400/20';
  return (
    <span className={clsx('inline-block font-mono text-xs font-semibold px-1.5 py-0.5 rounded border', cls)}>
      {label}
    </span>
  );
}

export default function AccuracyTable({ metrics }: Props) {
  const rows: JSX.Element[] = [];

  const qosList: Array<[string, string, string]> = [
    ['no_qos', 'No QoS', 'tag-noqos'],
    ['htb',    'HTB',    'tag-htb'],
    ['ebpf',   'eBPF',   'tag-ebpf'],
  ];

  for (const [qos, label, tagCls] of qosList) {
    const q = metrics[qos as keyof typeof metrics];
    for (const tc of ['ef', 'af', 'be']) {
      const m   = q?.[tc as 'ef' | 'af' | 'be'];
      const tgt = TARGETS[tc];
      const actual = m?.throughputMbps ?? null;
      const delta  = actual !== null ? actual - tgt : null;
      const pct    = actual !== null ? (actual / tgt) * 100 : null;

      rows.push(
        <tr key={`${qos}_${tc}`} className="border-b border-border hover:bg-surface2 transition-colors">
          <td className="px-3 py-2"><span className={clsx('tag text-xs', tagCls)}>{label}</span></td>
          <td className="px-3 py-2 font-mono text-xs text-textdim">{TC_LABELS[tc]}</td>
          <td className="px-3 py-2 font-mono text-xs text-muted">{tgt}</td>
          <td className="px-3 py-2 font-mono text-xs text-textdim">{actual?.toFixed(1) ?? '—'}</td>
          <td className={clsx('px-3 py-2 font-mono text-xs', delta !== null && delta < 0 ? 'text-red-400' : 'text-green-400')}>
            {delta !== null ? (delta >= 0 ? '+' : '') + delta.toFixed(1) : '—'}
          </td>
          <td className="px-3 py-2">
            {pct !== null ? pill(pct, `${pct.toFixed(1)}%`) : <span className="text-muted font-mono text-xs">—</span>}
          </td>
          <td className="px-3 py-2 font-mono text-xs text-muted">{m?.avgRttUs?.toFixed(0) ?? '—'} µs</td>
          <td className="px-3 py-2 font-mono text-xs text-muted">{m?.retransmits?.toLocaleString() ?? '—'}</td>
        </tr>
      );
    }
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left border-collapse">
        <thead>
          <tr className="bg-surface border-b border-border">
            {['QoS', 'Class', 'Target (Mbps)', 'Actual (Mbps)', 'Delta', 'Accuracy', 'Avg RTT', 'Retransmits'].map(h => (
              <th key={h} className="px-3 py-2 font-mono text-xs font-bold text-muted uppercase tracking-wider whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  );
}
