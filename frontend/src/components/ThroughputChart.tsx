'use client';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  Legend, ReferenceLine, ResponsiveContainer,
} from 'recharts';

interface Props {
  metrics: {
    no_qos?: { ef?: { throughputMbps: number }; af?: { throughputMbps: number }; be?: { throughputMbps: number } };
    htb?:    { ef?: { throughputMbps: number }; af?: { throughputMbps: number }; be?: { throughputMbps: number } };
    ebpf?:   { ef?: { throughputMbps: number }; af?: { throughputMbps: number }; be?: { throughputMbps: number } };
  };
}

const TARGETS = { EF: 500, AF: 300, BE: 200 };

export default function ThroughputChart({ metrics }: Props) {
  const data = (['EF', 'AF', 'BE'] as const).map(tc => {
    const k = tc.toLowerCase() as 'ef' | 'af' | 'be';
    return {
      name: tc,
      target: TARGETS[tc],
      'No QoS': +(metrics.no_qos?.[k]?.throughputMbps ?? 0).toFixed(2),
      HTB:      +(metrics.htb?.[k]?.throughputMbps     ?? 0).toFixed(2),
      eBPF:     +(metrics.ebpf?.[k]?.throughputMbps    ?? 0).toFixed(2),
    };
  });

  return (
    <ResponsiveContainer width="100%" height={280}>
      <BarChart data={data} margin={{ top: 20, right: 20, left: 0, bottom: 5 }}
        barCategoryGap="25%" barGap={2}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1a2b40" vertical={false} />
        <XAxis dataKey="name" tick={{ fill: '#c8daea', fontFamily: 'monospace', fontSize: 11 }}
          axisLine={{ stroke: '#1a2b40' }} tickLine={false} />
        <YAxis tick={{ fill: '#4d6880', fontFamily: 'monospace', fontSize: 10 }}
          axisLine={false} tickLine={false} unit=" Mbps" domain={[0, 560]} />
        <Tooltip
          contentStyle={{ background: '#0c1420', border: '1px solid #1a2b40', borderRadius: 4, fontFamily: 'monospace', fontSize: 12 }}
          labelStyle={{ color: '#c8daea' }} itemStyle={{ color: '#4d6880' }}
          formatter={(v: number) => [`${v.toFixed(1)} Mbps`]} />
        <Legend wrapperStyle={{ fontFamily: 'monospace', fontSize: 11 }} />
        <ReferenceLine y={500} stroke="rgba(255,255,255,0.12)" strokeDasharray="4 4" label={{ value: 'EF target', fill: 'rgba(255,255,255,0.25)', fontSize: 9, fontFamily: 'monospace' }} />
        <ReferenceLine y={300} stroke="rgba(255,255,255,0.10)" strokeDasharray="4 4" />
        <ReferenceLine y={200} stroke="rgba(255,255,255,0.08)" strokeDasharray="4 4" />
        <Bar dataKey="No QoS" fill="#5b7fa6" radius={[2, 2, 0, 0]} />
        <Bar dataKey="HTB"    fill="#f59e0b" radius={[2, 2, 0, 0]} />
        <Bar dataKey="eBPF"   fill="#00ddb0" radius={[2, 2, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
