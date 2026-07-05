'use client';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  Legend, ResponsiveContainer,
} from 'recharts';

interface Props {
  metrics: {
    no_qos?: { ef?: { avgRttUs: number }; af?: { avgRttUs: number }; be?: { avgRttUs: number } };
    htb?:    { ef?: { avgRttUs: number }; af?: { avgRttUs: number }; be?: { avgRttUs: number } };
    ebpf?:   { ef?: { avgRttUs: number }; af?: { avgRttUs: number }; be?: { avgRttUs: number } };
  };
}

export default function RTTChart({ metrics }: Props) {
  const data = (['EF', 'AF', 'BE'] as const).map(tc => {
    const k = tc.toLowerCase() as 'ef' | 'af' | 'be';
    return {
      name: tc,
      'No QoS': +(metrics.no_qos?.[k]?.avgRttUs ?? 0).toFixed(0),
      HTB:      +(metrics.htb?.[k]?.avgRttUs     ?? 0).toFixed(0),
      eBPF:     +(metrics.ebpf?.[k]?.avgRttUs    ?? 0).toFixed(0),
    };
  });

  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data} margin={{ top: 10, right: 20, left: 0, bottom: 5 }}
        barCategoryGap="25%" barGap={2}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1a2b40" vertical={false} />
        <XAxis dataKey="name" tick={{ fill: '#c8daea', fontFamily: 'monospace', fontSize: 11 }}
          axisLine={{ stroke: '#1a2b40' }} tickLine={false} />
        <YAxis tick={{ fill: '#4d6880', fontFamily: 'monospace', fontSize: 10 }}
          axisLine={false} tickLine={false} unit=" µs" />
        <Tooltip
          contentStyle={{ background: '#0c1420', border: '1px solid #1a2b40', borderRadius: 4, fontFamily: 'monospace', fontSize: 12 }}
          labelStyle={{ color: '#c8daea' }}
          formatter={(v: number) => [`${v.toLocaleString()} µs`]} />
        <Legend wrapperStyle={{ fontFamily: 'monospace', fontSize: 11 }} />
        <Bar dataKey="No QoS" fill="#5b7fa6" radius={[2, 2, 0, 0]} />
        <Bar dataKey="HTB"    fill="#f59e0b" radius={[2, 2, 0, 0]} />
        <Bar dataKey="eBPF"   fill="#00ddb0" radius={[2, 2, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
