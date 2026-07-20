'use client';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts';
import type { EbpfClass } from '@/types';

interface Props {
  ebpfClasses: EbpfClass[];
}

const TC_LABEL: Record<string, string> = { EF: 'EF', AF: 'AF', BE: 'BE' };

// Answers "where does loss come from" — drop/delay/borrow as % of that class's
// own packet count. Not a 100% stacked partition: a packet can be both
// delayed and borrowed, so these are independent rates, shown side by side.
export default function LossAttributionChart({ ebpfClasses }: Props) {
  const data = ebpfClasses
    .filter(c => c.packets > 0)
    .map(c => ({
      name: TC_LABEL[c.class_name] || c.class_name,
      'Dropped %':  (c.dropped  / c.packets) * 100,
      'Delayed %':  (c.delayed  / c.packets) * 100,
      'Borrowed %': (c.borrowed / c.packets) * 100,
    }));

  if (!data.length) return null;

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }} barCategoryGap="25%" barGap={2}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" vertical={false} />
        <XAxis dataKey="name" tick={{ fontSize: 11, fill: 'var(--color-textdim)', fontFamily: 'monospace' }} />
        <YAxis tick={{ fontSize: 10, fill: 'var(--color-muted)' }} unit="%" width={44} />
        <Tooltip
          contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 4, fontSize: 11, fontFamily: 'monospace' }}
          formatter={(v: number) => [`${v.toFixed(3)}%`]}
        />
        <Legend wrapperStyle={{ fontFamily: 'monospace', fontSize: 10 }} />
        <Bar dataKey="Dropped %"  fill="#f87171" radius={[2, 2, 0, 0]} />
        <Bar dataKey="Delayed %"  fill="#a78bfa" radius={[2, 2, 0, 0]} />
        <Bar dataKey="Borrowed %" fill="#facc15" radius={[2, 2, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
