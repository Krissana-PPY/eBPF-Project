'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft, FileDown, Loader2, Activity, Cpu, BarChart2,
  Clock, AlertTriangle, Database, TrendingUp, Info, Wifi,
} from 'lucide-react';
import {
  BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend, ReferenceLine, Cell,
} from 'recharts';
import { api } from '@/lib/api';
import type { ModeData, QosType, TrafficClass, ModeIperfEntry, IperfSummaryRow } from '@/types';

// ── Constants ─────────────────────────────────────────────────────────────────
const QOS_META: Record<QosType, { label: string; color: string; accent: string; desc: string }> = {
  no_qos: { label: 'No QoS',  color: 'text-noqos',  accent: 'var(--color-noqos)',  desc: 'Baseline — no traffic shaping or classification' },
  htb:    { label: 'HTB',     color: 'text-htb',    accent: 'var(--color-htb)',    desc: 'Hierarchical Token Bucket — kernel tc qdisc' },
  ebpf:   { label: 'eBPF',    color: 'text-accent', accent: 'var(--color-accent)', desc: 'XDP-based eBPF packet classification at kernel ingress' },
};
const TC_KEYS    = ['ef', 'af', 'be'] as const;
const TC_LABEL: Record<string, string> = { ef: 'EF', af: 'AF', be: 'BE' };
const TC_FULL:  Record<string, string> = { ef: 'Expedited Forwarding', af: 'Assured Forwarding', be: 'Best Effort' };
const TC_COLOR: Record<string, string> = { ef: '#22d3ee', af: '#a78bfa', be: '#fb923c' };

function fmt(n: number | null | undefined, d = 2): string {
  if (n == null || isNaN(Number(n))) return '—';
  return Number(n).toFixed(d);
}
function fmtK(n: number | null | undefined): string {
  if (n == null) return '—';
  return Number(n).toLocaleString('en-US');
}

const SECTION = ({
  icon: Icon, title, tag, children,
}: { icon: React.ElementType; title: string; tag?: string; children: React.ReactNode }) => (
  <section className="mb-8">
    <div className="flex items-center gap-2 mb-3">
      <Icon size={13} className="text-muted" />
      <h2 className="font-mono text-xs font-semibold text-textdim tracking-wide uppercase">{title}</h2>
      {tag && <span className="font-mono text-xs text-muted">{tag}</span>}
      <div className="flex-1 h-px bg-border" />
    </div>
    {children}
  </section>
);

const StatTile = ({ label, value, sub, color }: { label: string; value: string; sub?: string; color?: string }) => (
  <div className="card p-3">
    <p className="font-mono text-xs text-muted uppercase tracking-wider mb-1">{label}</p>
    <p className={`font-mono text-lg font-bold leading-none ${color ?? 'text-textdim'}`}>{value}</p>
    {sub && <p className="font-mono text-xs text-muted mt-1">{sub}</p>}
  </div>
);

// ── Protocol throughput section ───────────────────────────────────────────────
function ProtocolSection({
  proto, iperf, accentColor, qosType,
}: {
  proto: string;
  iperf: Partial<Record<TrafficClass, ModeIperfEntry>>;
  accentColor: string;
  qosType: string;
}) {
  const isUdp = proto === 'udp';
  const chartData = TC_KEYS.map(tc => ({
    tc:   TC_LABEL[tc],
    sent: iperf[tc]?.summary?.sent_throughput_mbps ?? 0,
    rcv:  iperf[tc]?.summary?.throughput_mbps      ?? 0,
    dr:   iperf[tc]?.summary?.delivery_ratio       ?? null,
    rtt:  iperf[tc]?.summary?.avg_rtt_us           ?? 0,
  }));
  const hasRtt = !isUdp && TC_KEYS.some(tc => (iperf[tc]?.summary?.avg_rtt_us ?? 0) > 0);

  // eBPF UDP EF delivery anomaly
  const efDr = iperf.ef?.summary?.delivery_ratio;
  const beDr = iperf.be?.summary?.delivery_ratio;
  const udpAnomaly = isUdp && qosType === 'ebpf' && efDr != null && beDr != null && efDr < beDr;

  return (
    <div className="mb-6">
      <div className="flex items-center gap-2 mb-3">
        <span className="font-mono text-xs font-bold uppercase tracking-widest px-2 py-0.5 rounded border border-border text-textdim">
          {proto.toUpperCase()}
        </span>
        {isUdp && <span className="font-mono text-xs text-muted">— no congestion control · drop-based enforcement</span>}
        {!isUdp && <span className="font-mono text-xs text-muted">— CUBIC congestion control · RTT available</span>}
      </div>

      {udpAnomaly && (
        <div className="card border-l-2 border-l-red-500 p-3 mb-3 flex gap-2 items-start">
          <AlertTriangle size={13} className="text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-mono text-xs font-bold text-red-400 uppercase tracking-wider mb-1">UDP Priority Anomaly</p>
            <p className="font-mono text-xs text-muted leading-relaxed">
              EF delivery {efDr?.toFixed(1)}% &lt; BE {beDr?.toFixed(1)}% — priority inversion.
              eBPF EF uses drop-based enforcement (0 delayed events) vs AF/BE delay-based shaping.
              Verify EF UDP token-bucket rate configuration.
            </p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="card p-4">
          <p className="font-mono text-xs text-muted mb-3">Sent vs Received (Mbps) — gap = shaping overhead</p>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={chartData} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
              <XAxis dataKey="tc" tick={{ fontSize: 11, fill: 'var(--color-muted)' }} />
              <YAxis tick={{ fontSize: 10, fill: 'var(--color-muted)' }} unit=" M" width={50} />
              <Tooltip contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 4, fontSize: 11 }}
                formatter={(v: number, name: string) => [`${Number(v).toFixed(2)} Mbps`, name === 'sent' ? 'Sent' : 'Received']} />
              <Legend iconSize={10} wrapperStyle={{ fontSize: 11 }} formatter={n => n === 'sent' ? 'Sent' : 'Received'} />
              <Bar dataKey="sent" fill="var(--color-muted)" opacity={0.45} radius={[2, 2, 0, 0]} />
              <Bar dataKey="rcv" radius={[3, 3, 0, 0]}>
                {chartData.map(entry => <Cell key={entry.tc} fill={TC_COLOR[entry.tc.toLowerCase()] ?? accentColor} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card p-4">
          <p className="font-mono text-xs text-muted mb-3">
            {isUdp ? 'Delivery Ratio (%) — rcv / sent bytes' : 'Avg RTT (µs) — TCP ACK round-trip'}
          </p>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={chartData} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
              <XAxis dataKey="tc" tick={{ fontSize: 11, fill: 'var(--color-muted)' }} />
              <YAxis tick={{ fontSize: 10, fill: 'var(--color-muted)' }}
                unit={isUdp ? '%' : ' µs'} domain={isUdp ? [0, 100] : undefined} width={56} />
              <Tooltip contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 4, fontSize: 11 }}
                formatter={(v: number) => [isUdp ? `${Number(v).toFixed(1)}%` : `${Number(v).toFixed(0)} µs`, isUdp ? 'Delivery Ratio' : 'Avg RTT']} />
              <Bar dataKey={isUdp ? 'dr' : 'rtt'} radius={[3, 3, 0, 0]}>
                {chartData.map(entry => <Cell key={entry.tc} fill={TC_COLOR[entry.tc.toLowerCase()] ?? accentColor} opacity={0.85} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* detail table */}
      <div className="card overflow-x-auto">
        <table className="w-full text-left border-collapse font-mono text-xs">
          <thead>
            <tr className="bg-surface border-b border-border">
              {['Class', 'Sent Mbps', 'Rcv Mbps', 'DR%', 'RTT avg µs', 'RTT min', 'RTT max', 'RTT σ', 'Retx', 'CPU Host%'].map(h => (
                <th key={h} className="px-3 py-2 text-muted uppercase tracking-wider font-bold whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {TC_KEYS.map(tc => {
              const s = iperf[tc]?.summary;
              const dr = s?.delivery_ratio;
              const drC = dr == null ? 'text-muted' : dr >= 99 ? 'text-green-400' : dr >= 90 ? 'text-yellow-400' : 'text-red-400';
              const rtt = s?.avg_rtt_us ?? 0;
              return (
                <tr key={tc} className="border-b border-border hover:bg-surface2">
                  <td className="px-3 py-2 font-bold" style={{ color: TC_COLOR[tc] }}>
                    {TC_LABEL[tc]} <span className="font-normal text-muted">— {TC_FULL[tc]}</span>
                  </td>
                  <td className="px-3 py-2 text-muted">{s ? fmt(s.sent_throughput_mbps) : '—'}</td>
                  <td className="px-3 py-2 text-textdim font-semibold">{s ? fmt(s.throughput_mbps) : '—'}</td>
                  <td className={`px-3 py-2 font-semibold ${drC}`}>{dr != null ? `${fmt(dr, 1)}%` : '—'}</td>
                  <td className="px-3 py-2" style={{ color: rtt < 500 ? '#00ddb0' : rtt > 3000 ? '#ef4444' : '#c8daea' }}>
                    {s ? fmt(s.avg_rtt_us, 0) : '—'}
                  </td>
                  <td className="px-3 py-2 text-muted">{s ? fmt(s.min_rtt_us, 0) : '—'}</td>
                  <td className="px-3 py-2 text-muted">{s ? fmt(s.max_rtt_us, 0) : '—'}</td>
                  <td className="px-3 py-2 text-muted">{s ? fmt(s.rtt_std_us, 0) : '—'}</td>
                  <td className={`px-3 py-2 ${s && s.retransmits > 0 ? 'text-yellow-400' : 'text-muted'}`}>{s ? fmtK(s.retransmits) : '—'}</td>
                  <td className="px-3 py-2 text-muted">{s ? fmt(s.cpu_host_total) : '—'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────
export default function ModePage() {
  const { id, qosType } = useParams<{ id: string; qosType: string }>();
  const router = useRouter();
  const [data,      setData]      = useState<ModeData | null>(null);
  const [error,     setError]     = useState('');
  const [exporting, setExporting] = useState(false);

  const meta = QOS_META[qosType as QosType];

  useEffect(() => {
    if (!meta) { setError(`Unknown QoS type: ${qosType}`); return; }
    api.getModeData(parseInt(id), qosType as QosType).then(setData).catch(e => setError(e.message));
  }, [id, qosType, meta]);

  async function handleExport() {
    if (!data || exporting) return;
    setExporting(true);
    try { await api.downloadModeReport(data.dataset_id, qosType as QosType); }
    catch (e: unknown) { alert('Export failed: ' + (e instanceof Error ? e.message : String(e))); }
    finally { setExporting(false); }
  }

  if (error) return <div className="text-red-400 font-mono text-sm bg-red-400/10 border border-red-400/20 rounded p-4">{error}</div>;
  if (!data) return <div className="text-muted font-mono text-sm text-center py-20">กำลังโหลด...</div>;

  const accentColor = meta.accent;

  // ── Derived ─────────────────────────────────────────────────────────────────
  const protos = Object.keys(data.iperfByProtocol ?? {}).filter(p => {
    const pr = (data.iperfByProtocol ?? {})[p];
    return pr && TC_KEYS.some(tc => pr[tc]?.summary);
  });
  const hasTcpIperf = protos.includes('tcp');
  const hasUdpIperf = protos.includes('udp');

  // Fallback: primary protocol from data.iperf
  const primaryIperf = data.iperf;
  const primaryHasData = TC_KEYS.some(tc => primaryIperf[tc]?.summary);

  // CPU
  const cpuSnapshots = data.cpu.snapshots;
  const cpuAvgTotal = cpuSnapshots.length
    ? cpuSnapshots.reduce((s, r) => s + (r.usr_pct || 0) + (r.sys_pct || 0) + (r.soft_pct || 0), 0) / cpuSnapshots.length
    : null;
  const cpuTimelineData = cpuSnapshots.map((s, i) => ({
    i,
    time:  s.snapshot_time,
    total: (s.usr_pct || 0) + (s.sys_pct || 0) + (s.soft_pct || 0),
    usr:   s.usr_pct,
    sys:   s.sys_pct,
    soft:  s.soft_pct,
  }));

  // EF KPIs (TCP preferentially)
  const efSource = hasTcpIperf
    ? (data.iperfByProtocol?.tcp?.ef?.summary ?? null)
    : (primaryIperf.ef?.summary ?? null);

  // Protocols in header
  const headerProtos = protos.length ? protos : (primaryHasData ? ['primary'] : []);

  return (
    <div>
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-start gap-3 mb-8">
        <button onClick={() => router.back()} className="mt-0.5 p-1.5 rounded hover:bg-surface transition-colors text-muted hover:text-textdim">
          <ArrowLeft size={16} />
        </button>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-xs text-muted">{data.dataset_name}</span>
            <span className="text-border">/</span>
            <span className={`font-mono text-xs font-bold uppercase tracking-wider ${meta.color}`}>Mode Analysis</span>
            {protos.map(p => (
              <span key={p} className="font-mono text-xs px-1.5 py-0.5 rounded bg-surface border border-border text-muted uppercase">{p}</span>
            ))}
          </div>
          <h1 className={`font-mono text-2xl font-bold mt-1 ${meta.color}`}>{meta.label}</h1>
          <p className="font-mono text-xs text-muted mt-0.5">{meta.desc}</p>
        </div>
        <button onClick={handleExport} disabled={exporting}
          className="flex items-center gap-2 px-3 py-1.5 rounded border border-border bg-surface hover:bg-surface2 transition-colors font-mono text-xs text-textdim disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap">
          {exporting ? <Loader2 size={13} className="animate-spin" /> : <FileDown size={13} />}
          {exporting ? 'Exporting…' : 'Export .md'}
        </button>
      </div>

      {/* ── Overview tiles ──────────────────────────────────────────────── */}
      <SECTION icon={Info} title="Overview">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3">
          <StatTile label="EF Received"
            value={efSource ? `${fmt(efSource.throughput_mbps)} Mbps` : '—'}
            sub={efSource?.sent_throughput_mbps != null ? `sent ${fmt(efSource.sent_throughput_mbps)} Mbps` : 'server-side goodput'} />
          <StatTile label="EF Delivery Ratio"
            value={efSource?.delivery_ratio != null ? `${fmt(efSource.delivery_ratio, 1)}%` : '—'}
            sub="rcv / sent bytes" />
          <StatTile label="EF Avg RTT"
            value={efSource ? `${fmt(efSource.avg_rtt_us, 0)} µs` : '—'}
            sub="TCP ACK round-trip" />
          <StatTile label="CPU Active"
            value={cpuAvgTotal != null ? `${cpuAvgTotal.toFixed(2)}%` : '—'}
            sub={`${cpuSnapshots.length} sar samples`}
            color={cpuAvgTotal != null && cpuAvgTotal > 40 ? 'text-yellow-400' : undefined} />
        </div>
        {(() => {
          const insights: string[] = [];
          const tcpEf = data.iperfByProtocol?.tcp?.ef?.summary;
          const tcpBe = data.iperfByProtocol?.tcp?.be?.summary;
          if (tcpEf && tcpBe) {
            const rttDiff = tcpBe.avg_rtt_us - tcpEf.avg_rtt_us;
            insights.push(rttDiff > 100
              ? `TCP EF vs BE RTT gap: ${rttDiff.toFixed(0)} µs — priority differentiation confirmed.`
              : `TCP EF and BE RTT gap: ${Math.abs(rttDiff).toFixed(0)} µs — minimal priority differentiation.`);
          }
          if (qosType === 'ebpf') {
            const totalEcn = data.ebpfClasses.reduce((s, c) => s + (c.ecn_marked || 0), 0);
            if (totalEcn > 0) insights.push(`${fmtK(totalEcn)} ECN marks — eBPF congestion management active.`);
            const udpEf = data.iperfByProtocol?.udp?.ef?.summary;
            const udpBe = data.iperfByProtocol?.udp?.be?.summary;
            if (udpEf && udpBe && udpEf.delivery_ratio != null && udpBe.delivery_ratio != null && udpEf.delivery_ratio < udpBe.delivery_ratio) {
              insights.push(`UDP priority inversion: EF delivery ${udpEf.delivery_ratio.toFixed(1)}% < BE ${udpBe.delivery_ratio.toFixed(1)}% — check EF token-bucket config.`);
            }
          }
          if (qosType === 'htb') {
            const dropped = data.htbClasses.reduce((s, c) => s + (c.dropped || 0), 0);
            if (dropped > 0) insights.push(`${fmtK(dropped)} HTB drops — rate limits enforced.`);
            const overlimits = data.htbClasses.reduce((s, c) => s + (c.overlimits || 0), 0);
            if (overlimits > 0) insights.push(`${fmtK(overlimits)} overlimits — token-bucket enforcement active (no drops).`);
          }
          return insights.length > 0 ? (
            <div className="border border-border rounded px-4 py-3 bg-surface font-mono text-xs text-muted space-y-1">
              {insights.map((t, i) => <p key={i}><span className={meta.color}>›</span> {t}</p>)}
            </div>
          ) : null;
        })()}
      </SECTION>

      {/* ── TCP Analysis ────────────────────────────────────────────────── */}
      {hasTcpIperf && (
        <SECTION icon={BarChart2} title="TCP Analysis" tag="· iperf3 TCP · 30 s · CUBIC">
          <ProtocolSection
            proto="tcp"
            iperf={data.iperfByProtocol?.tcp ?? {}}
            accentColor={accentColor}
            qosType={qosType}
          />
          {/* TCP time series */}
          {TC_KEYS.some(tc => (data.iperfByProtocol?.tcp?.[tc]?.intervals?.length ?? 0) > 0) && (
            <div className="mt-4">
              <p className="font-mono text-xs text-muted uppercase tracking-wider mb-3">TCP Throughput Time Series</p>
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {TC_KEYS.map(tc => {
                  const intervals = data.iperfByProtocol?.tcp?.[tc]?.intervals ?? [];
                  if (!intervals.length) return null;
                  const chartData = intervals.map(iv => ({ t: iv.interval_start, mbps: iv.bits_per_second / 1e6, rtt: iv.rtt_us }));
                  const avg = chartData.reduce((s, d) => s + d.mbps, 0) / chartData.length;
                  return (
                    <div key={tc} className="card p-3">
                      <p className="font-mono text-xs font-bold mb-1" style={{ color: TC_COLOR[tc] }}>{TC_LABEL[tc]} — avg {avg.toFixed(1)} Mbps</p>
                      <ResponsiveContainer width="100%" height={110}>
                        <LineChart data={chartData} margin={{ top: 2, right: 4, left: 0, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                          <XAxis dataKey="t" tick={{ fontSize: 9, fill: 'var(--color-muted)' }} tickFormatter={v => `${v}s`} />
                          <YAxis tick={{ fontSize: 9, fill: 'var(--color-muted)' }} width={38} tickFormatter={v => v.toFixed(0)} />
                          <Tooltip contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 4, fontSize: 10 }}
                            formatter={(v: number) => [`${v.toFixed(2)} Mbps`, 'Throughput']} labelFormatter={v => `t=${v}s`} />
                          <ReferenceLine y={avg} stroke="var(--color-muted)" strokeDasharray="3 3" />
                          <Line type="monotone" dataKey="mbps" stroke={TC_COLOR[tc]} dot={false} strokeWidth={1.5} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </SECTION>
      )}

      {/* ── UDP Analysis ────────────────────────────────────────────────── */}
      {hasUdpIperf && (
        <SECTION icon={Wifi} title="UDP Analysis" tag="· iperf3 UDP · 30 s · no congestion control">
          <ProtocolSection
            proto="udp"
            iperf={data.iperfByProtocol?.udp ?? {}}
            accentColor={accentColor}
            qosType={qosType}
          />
        </SECTION>
      )}

      {/* ── Fallback: primary protocol (no per-protocol data) ───────────── */}
      {!hasTcpIperf && !hasUdpIperf && primaryHasData && (
        <SECTION icon={BarChart2} title="Throughput — Traffic Class Comparison">
          <ProtocolSection
            proto="primary"
            iperf={primaryIperf}
            accentColor={accentColor}
            qosType={qosType}
          />
        </SECTION>
      )}

      {/* ── CPU ─────────────────────────────────────────────────────────── */}
      {cpuSnapshots.length > 0 && (
        <SECTION icon={Cpu} title="CPU Utilization (sar)">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
            {(() => {
              const avg = (key: 'usr_pct' | 'sys_pct' | 'soft_pct' | 'idle_pct') =>
                cpuSnapshots.reduce((s, r) => s + (r[key] || 0), 0) / cpuSnapshots.length;
              const totals = cpuSnapshots.map(s => (s.usr_pct || 0) + (s.sys_pct || 0) + (s.soft_pct || 0));
              const totAvg = totals.reduce((a, b) => a + b, 0) / totals.length;
              return [
                { l: 'User %',       v: avg('usr_pct').toFixed(2)  + '%', hi: avg('usr_pct') > 20 },
                { l: 'System %',     v: avg('sys_pct').toFixed(2)  + '%', hi: false },
                { l: 'Softirq %',    v: avg('soft_pct').toFixed(2) + '%', hi: false },
                { l: 'Total Active', v: totAvg.toFixed(2)          + '%', hi: totAvg > 50 },
              ].map(({ l, v, hi }) => (
                <StatTile key={l} label={l} value={v} color={hi ? 'text-yellow-400' : undefined} />
              ));
            })()}
          </div>
          {cpuTimelineData.length > 0 && (
            <div className="card p-4">
              <p className="font-mono text-xs text-muted mb-3">CPU timeline — {cpuSnapshots.length} sar snapshots</p>
              <ResponsiveContainer width="100%" height={160}>
                <LineChart data={cpuTimelineData} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                  <XAxis dataKey="time" tick={{ fontSize: 9, fill: 'var(--color-muted)' }} interval="preserveStartEnd" />
                  <YAxis tick={{ fontSize: 10, fill: 'var(--color-muted)' }} unit="%" domain={[0, 100]} width={38} />
                  <Tooltip contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 4, fontSize: 11 }} />
                  <Line type="monotone" dataKey="total" name="Active %" stroke={accentColor} dot={false} strokeWidth={2} />
                  <Line type="monotone" dataKey="usr"   name="User %"    stroke="#60a5fa" dot={false} strokeWidth={1} strokeDasharray="4 2" />
                  <Line type="monotone" dataKey="sys"   name="System %"  stroke="#f59e0b" dot={false} strokeWidth={1} strokeDasharray="4 2" />
                  <Line type="monotone" dataKey="soft"  name="Softirq %" stroke="#a78bfa" dot={false} strokeWidth={1} strokeDasharray="2 2" />
                </LineChart>
              </ResponsiveContainer>
              <div className="flex gap-4 mt-2 font-mono text-xs text-muted">
                <span><span style={{ color: accentColor }}>—</span> Active</span>
                <span><span className="text-blue-400">- -</span> User</span>
                <span><span className="text-yellow-400">- -</span> System</span>
                <span><span className="text-violet-400">··</span> Softirq</span>
              </div>
            </div>
          )}
        </SECTION>
      )}

      {/* ── HTB TC classes ──────────────────────────────────────────────── */}
      {qosType === 'htb' && (data.htbClasses.length > 0 || Object.keys(data.htbClassesByProtocol ?? {}).length > 0) && (
        <SECTION icon={TrendingUp} title="HTB TC Class Stats">
          {Object.keys(data.htbClassesByProtocol ?? {}).length > 0
            ? Object.entries(data.htbClassesByProtocol ?? {}).map(([proto, classes]) => classes ? (
                <div key={proto} className="mb-4">
                  <p className="font-mono text-xs font-bold uppercase tracking-wider text-muted mb-2">{proto.toUpperCase()}</p>
                  <HtbTable classes={classes} />
                </div>
              ) : null)
            : <HtbTable classes={data.htbClasses} />
          }
        </SECTION>
      )}

      {/* ── eBPF Map Stats ──────────────────────────────────────────────── */}
      {qosType === 'ebpf' && (data.ebpfClasses.length > 0 || Object.keys(data.ebpfClassesByProtocol ?? {}).length > 0) && (
        <SECTION icon={AlertTriangle} title="eBPF Map Statistics (XDP counters)">
          {Object.keys(data.ebpfClassesByProtocol ?? {}).length > 0
            ? Object.entries(data.ebpfClassesByProtocol ?? {}).map(([proto, classes]) => classes ? (
                <div key={proto} className="mb-6">
                  <p className="font-mono text-xs font-bold uppercase tracking-wider text-muted mb-2">{proto.toUpperCase()}</p>
                  <EbpfCards classes={classes} />
                </div>
              ) : null)
            : <EbpfCards classes={data.ebpfClasses} />
          }
        </SECTION>
      )}
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────
function HtbTable({ classes }: { classes: import('@/types').HtbClass[] }) {
  return (
    <div className="card overflow-x-auto">
      <table className="w-full text-left border-collapse font-mono text-xs">
        <thead>
          <tr className="bg-surface border-b border-border">
            {['Class ID', 'Rate', 'Bytes Sent', 'Packets', 'Dropped', 'Overlimits', 'Calc. Mbps'].map(h => (
              <th key={h} className="px-3 py-2 text-muted uppercase tracking-wider font-bold whitespace-nowrap">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {classes.map(c => {
            const mbps = (c.bytes_sent * 8) / 30 / 1e6;
            return (
              <tr key={c.id} className="border-b border-border hover:bg-surface2">
                <td className="px-3 py-2 text-htb font-bold">{c.class_id}</td>
                <td className="px-3 py-2 text-textdim">{c.rate}</td>
                <td className="px-3 py-2 text-muted">{Number(c.bytes_sent).toLocaleString()}</td>
                <td className="px-3 py-2 text-muted">{Number(c.packets).toLocaleString()}</td>
                <td className={`px-3 py-2 ${c.dropped > 0 ? 'text-red-400 font-semibold' : 'text-muted'}`}>{Number(c.dropped).toLocaleString()}</td>
                <td className="px-3 py-2 text-muted">{Number(c.overlimits).toLocaleString()}</td>
                <td className="px-3 py-2 text-textdim font-semibold">{mbps.toFixed(2)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function EbpfCards({ classes }: { classes: import('@/types').EbpfClass[] }) {
  const totalEcn = classes.reduce((s, c) => s + (c.ecn_marked || 0), 0);
  const totalDly = classes.reduce((s, c) => s + (c.delayed || 0), 0);
  const totalBor = classes.reduce((s, c) => s + (c.borrowed || 0), 0);
  return (
    <>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
        {classes.map(c => {
          const mbps = (c.bytes * 8) / 30 / 1e6;
          return (
            <div key={c.id} className="card p-4">
              <div className="font-mono text-xs font-bold uppercase tracking-widest text-accent mb-3 pb-2 border-b border-border">
                {c.class_name} (key {c.class_key})
              </div>
              {([
                ['packets',    Number(c.packets).toLocaleString(),    false],
                ['throughput', `${mbps.toFixed(2)} Mbps`,             false],
                ['bytes',      Number(c.bytes).toLocaleString(),      false],
                ['borrowed',   Number(c.borrowed).toLocaleString(),   c.borrowed > 0],
                ['ECN marked', Number(c.ecn_marked).toLocaleString(), c.ecn_marked > 0],
                ['delayed',    Number(c.delayed).toLocaleString(),    c.delayed > 0],
              ] as [string, string, boolean][]).map(([k, v, hi]) => (
                <div key={k} className="flex justify-between items-baseline py-1.5 border-b border-border last:border-0 font-mono text-xs">
                  <span className="text-muted">{k}</span>
                  <span className={hi ? 'text-yellow-400 font-semibold' : 'text-textdim'}>{v}</span>
                </div>
              ))}
            </div>
          );
        })}
      </div>
      <div className="grid grid-cols-3 gap-3">
        {([
          ['Total ECN Marks',  totalEcn, 'Active congestion signalling'],
          ['Total Delayed',    totalDly, 'Packet shaping events'],
          ['Total Borrowed',   totalBor, 'Bandwidth borrowing events'],
        ] as [string, number, string][]).map(([label, val, note]) => (
          <div key={label} className="card p-3 text-center">
            <p className="font-mono text-xs text-muted uppercase tracking-wider mb-1">{label}</p>
            <p className={`font-mono text-xl font-bold ${val > 0 ? 'text-yellow-400' : 'text-textdim'}`}>
              {val.toLocaleString()}
            </p>
            <p className="font-mono text-xs text-muted mt-0.5">{note}</p>
          </div>
        ))}
      </div>
    </>
  );
}
