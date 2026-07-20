'use client';
import {
  ComposedChart, Bar, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  Legend, ResponsiveContainer,
} from 'recharts';
import type { BorrowScenarioPoint, TrafficClass } from '@/types';

interface Props {
  borrowCurve: BorrowScenarioPoint[];
}

const SCENARIO_ORDER = ['below_guaranteed', 'at_guaranteed', 'mid_borrow_zone', 'at_ceiling', 'above_ceiling', 'at_target'];
const SCENARIO_LABELS: Record<string, string> = {
  below_guaranteed: 'Below\nguaranteed', at_guaranteed: 'At\nguaranteed', mid_borrow_zone: 'Mid borrow\nzone',
  at_ceiling: 'At\nceiling', above_ceiling: 'Above\nceiling', at_target: 'At\ntarget',
};
const TC_LABEL: Record<string, string> = { ef: 'EF', af: 'AF', be: 'BE' };
const TC_COLOR: Record<string, string> = { ef: '#22d3ee', af: '#a78bfa', be: '#fb923c' };

export default function BorrowCurveChart({ borrowCurve }: Props) {
  if (!borrowCurve.length) return null;

  const classes = Array.from(new Set(borrowCurve.map(r => r.traffic_class))) as TrafficClass[];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {classes.map(tc => {
        const rows = borrowCurve
          .filter(r => r.traffic_class === tc)
          .sort((a, b) => SCENARIO_ORDER.indexOf(a.scenario) - SCENARIO_ORDER.indexOf(b.scenario));
        const data = rows.map(r => ({
          scenario: SCENARIO_LABELS[r.scenario] || r.scenario,
          target:   r.target_bitrate_mbps ?? 0,
          actual:   r.throughput_mbps ?? 0,
          borrowed: r.borrowed_delta ?? 0,
        }));
        const color = TC_COLOR[tc] || '#5b7fa6';
        return (
          <div key={tc} className="card p-4">
            <p className="font-mono text-xs font-bold mb-3" style={{ color }}>
              {TC_LABEL[tc] || tc.toUpperCase()} — target vs actual rate & borrowed packets per demand point
            </p>
            <ResponsiveContainer width="100%" height={220}>
              <ComposedChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" vertical={false} />
                <XAxis dataKey="scenario" tick={{ fontSize: 9, fill: 'var(--color-muted)', fontFamily: 'monospace' }} interval={0} />
                <YAxis yAxisId="mbps" tick={{ fontSize: 10, fill: 'var(--color-muted)' }} unit=" Mbps" width={56} />
                <YAxis yAxisId="pkts" orientation="right" tick={{ fontSize: 10, fill: 'var(--color-muted)' }} width={56} />
                <Tooltip
                  contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 4, fontSize: 11, fontFamily: 'monospace' }}
                  formatter={(v: number, name: string) => name === 'Borrowed Δ' ? [v.toLocaleString('en-US'), name] : [`${v.toFixed(1)} Mbps`, name]}
                />
                <Legend wrapperStyle={{ fontFamily: 'monospace', fontSize: 10 }} />
                <Bar yAxisId="mbps" dataKey="target" name="Target Mbps" fill="var(--color-border)" radius={[2, 2, 0, 0]} />
                <Bar yAxisId="mbps" dataKey="actual" name="Actual Mbps" fill={color} radius={[2, 2, 0, 0]} />
                <Line yAxisId="pkts" dataKey="borrowed" name="Borrowed Δ" stroke="#facc15" strokeWidth={2} dot={{ r: 3 }} />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        );
      })}
    </div>
  );
}
