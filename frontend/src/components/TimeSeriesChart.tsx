'use client';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import type { TimePoint } from '@/types';

interface Props {
  timeSeries: Record<string, TimePoint[]>;
  metric: 'bitsPerSecond' | 'rttUs';
  trafficClass: 'ef' | 'af' | 'be';
}

const COLORS: Record<string, string> = {
  no_qos: '#5b7fa6',
  htb:    '#f59e0b',
  ebpf:   '#00ddb0',
};

export default function TimeSeriesChart({ timeSeries, metric, trafficClass }: Props) {
  const keys = Object.keys(timeSeries).filter(k => k.endsWith(`_${trafficClass}`));
  if (!keys.length) return <p className="text-muted text-xs font-mono text-center py-8">ไม่มีข้อมูล time series</p>;

  const maxLen = Math.max(...keys.map(k => timeSeries[k].length));
  const data = Array.from({ length: maxLen }, (_, i) => {
    const point: Record<string, number | null> = { t: i };
    for (const key of keys) {
      const qos = key.replace(`_${trafficClass}`, '');
      const iv  = timeSeries[key][i];
      point[qos] = iv ? (metric === 'bitsPerSecond' ? iv.bitsPerSecond / 1e6 : iv.rttUs) : null;
    }
    return point;
  });

  const unit = metric === 'bitsPerSecond' ? ' Mbps' : ' µs';

  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart data={data} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1a2b40" />
        <XAxis dataKey="t" tick={{ fill: '#4d6880', fontFamily: 'monospace', fontSize: 9 }}
          axisLine={false} tickLine={false} label={{ value: 'seconds', position: 'insideBottom', offset: -2, fill: '#4d6880', fontSize: 9, fontFamily: 'monospace' }} />
        <YAxis tick={{ fill: '#4d6880', fontFamily: 'monospace', fontSize: 9 }}
          axisLine={false} tickLine={false} unit={unit} width={60} />
        <Tooltip contentStyle={{ background: '#0c1420', border: '1px solid #1a2b40', borderRadius: 4, fontFamily: 'monospace', fontSize: 11 }}
          formatter={(v: number) => [`${v?.toFixed(1)}${unit}`]} />
        <Legend wrapperStyle={{ fontFamily: 'monospace', fontSize: 10 }} />
        {keys.map(key => {
          const qos = key.replace(`_${trafficClass}`, '');
          return <Line key={key} type="monotone" dataKey={qos} stroke={COLORS[qos] || '#888'}
            dot={false} strokeWidth={1.5} connectNulls />;
        })}
      </LineChart>
    </ResponsiveContainer>
  );
}
