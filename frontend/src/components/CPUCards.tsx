import clsx from 'clsx';
import type { CpuMetrics } from '@/types';

interface Props {
  metrics: { no_qos?: { cpu?: CpuMetrics }; htb?: { cpu?: CpuMetrics }; ebpf?: { cpu?: CpuMetrics } };
}

interface BarRowProps { label: string; value: number; max?: number; color: string }
function BarRow({ label, value, max = 100, color }: BarRowProps) {
  const pct = Math.min((value / max) * 100, 100);
  return (
    <div className="flex items-center gap-2 font-mono text-xs">
      <span className="w-10 text-muted flex-shrink-0">{label}</span>
      <div className="flex-1 h-1 bg-border rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="w-10 text-right text-muted">{value.toFixed(1)}%</span>
    </div>
  );
}

const configs = [
  { key: 'no_qos', label: 'No QoS', color: '#5b7fa6', bigCls: 'text-noqos' },
  { key: 'htb',    label: 'HTB',    color: '#f59e0b', bigCls: 'text-htb'   },
  { key: 'ebpf',   label: 'eBPF',   color: '#f87171', bigCls: 'text-red-400' },
] as const;

export default function CPUCards({ metrics }: Props) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
      {configs.map(({ key, label, color, bigCls }) => {
        const cpu = metrics[key]?.cpu;
        const total = cpu?.avgTotal ?? 0;
        return (
          <div key={key} className="card p-4">
            <div className="font-mono text-xs font-bold uppercase tracking-widest mb-3" style={{ color }}>
              {label}
            </div>
            <div className={clsx('font-mono font-bold leading-none mb-0.5', bigCls)} style={{ fontSize: '1.9rem' }}>
              {total.toFixed(1)}<span className="text-lg">%</span>
            </div>
            <div className="text-xs text-muted mb-4">avg CPU (usr+sys+soft)</div>
            {cpu ? (
              <div className="flex flex-col gap-2">
                <BarRow label="%usr"  value={cpu.avgUsr}  color={color} />
                <BarRow label="%sys"  value={cpu.avgSys}  color={color} />
                <BarRow label="%soft" value={cpu.avgSoft} color={color} />
                <BarRow label="%idle" value={cpu.avgIdle} color={color} />
              </div>
            ) : (
              <p className="text-muted text-xs font-mono">ไม่มีข้อมูล CPU</p>
            )}
          </div>
        );
      })}
    </div>
  );
}
