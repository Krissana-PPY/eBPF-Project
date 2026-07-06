'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft, FileDown, Loader2, Activity, Cpu, BarChart2,
  Zap, Clock, AlertTriangle, Database, TrendingUp, Info
} from 'lucide-react';
import {
  BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend, ReferenceLine, Cell
} from 'recharts';
import { api } from '@/lib/api';
import type { ModeData, QosType } from '@/types';

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

const SECTION = ({ icon: Icon, title, children }: { icon: React.ElementType; title: string; children: React.ReactNode }) => (
  <section className="mb-8">
    <div className="flex items-center gap-2 mb-3">
      <Icon size={13} className="text-muted" />
      <h2 className="font-mono text-xs font-semibold text-textdim tracking-wide uppercase">{title}</h2>
      <div className="flex-1 h-px bg-border" />
    </div>
    {children}
  </section>
);

const StatTile = ({ label, value, sub }: { label: string; value: string; sub?: string }) => (
  <div className="card p-3">
    <p className="font-mono text-xs text-muted uppercase tracking-wider mb-1">{label}</p>
    <p className="font-mono text-lg font-bold text-textdim leading-none">{value}</p>
    {sub && <p className="font-mono text-xs text-muted mt-1">{sub}</p>}
  </div>
);

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
    api.getModeData(parseInt(id), qosType as QosType)
      .then(setData)
      .catch(e => setError(e.message));
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

  // Derived data
  const throughputChartData = TC_KEYS.map(tc => ({
    tc:      TC_LABEL[tc],
    full:    TC_FULL[tc],
    sent:    data.iperf[tc]?.summary?.sent_throughput_mbps ?? 0,
    rcv:     data.iperf[tc]?.summary?.throughput_mbps ?? 0,
    dr:      data.iperf[tc]?.summary?.delivery_ratio ?? null,
    rtt:     data.iperf[tc]?.summary?.avg_rtt_us ?? 0,
  }));

  const cpuAvgTotal = data.cpu.snapshots.length
    ? data.cpu.snapshots.reduce((s, r) => s + (r.usr_pct || 0) + (r.sys_pct || 0) + (r.soft_pct || 0), 0) / data.cpu.snapshots.length
    : null;

  const cpuTimelineData = data.cpu.snapshots.map((s, i) => ({
    i,
    time:  s.snapshot_time,
    total: (s.usr_pct || 0) + (s.sys_pct || 0) + (s.soft_pct || 0),
    usr:   s.usr_pct,
    sys:   s.sys_pct,
    soft:  s.soft_pct,
  }));

  // Best traffic class: lowest RTT
  const bestRtt = TC_KEYS.reduce<{ tc: string; rtt: number } | null>((best, tc) => {
    const rtt = data.iperf[tc]?.summary?.avg_rtt_us;
    if (rtt == null) return best;
    return (!best || rtt < best.rtt) ? { tc, rtt } : best;
  }, null);

  return (
    <div>
      {/* Header */}
      <div className="flex items-start gap-3 mb-8">
        <button onClick={() => router.back()} className="mt-0.5 p-1.5 rounded hover:bg-surface transition-colors text-muted hover:text-textdim">
          <ArrowLeft size={16} />
        </button>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-xs text-muted">{data.dataset_name}</span>
            <span className="text-border">/</span>
            <span className={`font-mono text-xs font-bold uppercase tracking-wider ${meta.color}`}>Mode Analysis</span>
          </div>
          <h1 className={`font-mono text-2xl font-bold mt-1 ${meta.color}`}>{meta.label}</h1>
          <p className="font-mono text-xs text-muted mt-0.5">{meta.desc}</p>
        </div>
        <button
          onClick={handleExport}
          disabled={exporting}
          className="flex items-center gap-2 px-3 py-1.5 rounded border border-border bg-surface hover:bg-surface2 transition-colors font-mono text-xs text-textdim disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
        >
          {exporting ? <Loader2 size={13} className="animate-spin" /> : <FileDown size={13} />}
          {exporting ? 'Exporting…' : 'Export .md'}
        </button>
      </div>

      {/* ── Overview tiles ───────────────────────────────────── */}
      <SECTION icon={Info} title="Overview">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3">
          <StatTile label="EF Received"
            value={data.iperf.ef?.summary ? `${fmt(data.iperf.ef.summary.throughput_mbps)} Mbps` : '—'}
            sub={data.iperf.ef?.summary?.sent_throughput_mbps != null
              ? `sent ${fmt(data.iperf.ef.summary.sent_throughput_mbps)} Mbps`
              : 'server-side goodput'} />
          <StatTile label="EF Delivery Ratio"
            value={data.iperf.ef?.summary?.delivery_ratio != null
              ? `${fmt(data.iperf.ef.summary.delivery_ratio, 1)}%`
              : '—'}
            sub="rcv / sent bytes" />
          <StatTile label="EF Avg RTT"
            value={data.iperf.ef?.summary ? `${fmt(data.iperf.ef.summary.avg_rtt_us, 0)} µs` : '—'}
            sub={bestRtt?.tc === 'ef' ? 'lowest RTT class' : undefined} />
          <StatTile label="CPU Active"
            value={cpuAvgTotal != null ? `${cpuAvgTotal.toFixed(2)}%` : '—'}
            sub={`${data.cpu.snapshots.length} sar samples`} />
        </div>

        {/* analysis callout */}
        {(() => {
          const insights: string[] = [];
          const ef = data.iperf.ef?.summary;
          const be = data.iperf.be?.summary;
          if (ef && be) {
            const rttDiff = be.avg_rtt_us - ef.avg_rtt_us;
            if (rttDiff > 100) insights.push(`EF vs BE RTT gap: ${rttDiff.toFixed(0)} µs — priority differentiation is working.`);
            else insights.push(`EF and BE RTT are similar (${Math.abs(rttDiff).toFixed(0)} µs gap) — minimal priority differentiation.`);
          }
          if (qosType === 'ebpf') {
            const totalEcn = data.ebpfClasses.reduce((s, c) => s + (c.ecn_marked || 0), 0);
            if (totalEcn > 0) insights.push(`${fmtK(totalEcn)} ECN marks detected — eBPF congestion management is active.`);
          }
          if (qosType === 'htb') {
            const dropped = data.htbClasses.reduce((s, c) => s + (c.dropped || 0), 0);
            if (dropped > 0) insights.push(`${fmtK(dropped)} packets dropped — HTB rate limits are being enforced.`);
          }
          return insights.length > 0 ? (
            <div className="border border-border rounded px-4 py-3 bg-surface font-mono text-xs text-muted space-y-1">
              {insights.map((t, i) => <p key={i}><span className={meta.color}>›</span> {t}</p>)}
            </div>
          ) : null;
        })()}
      </SECTION>

      {/* ── Throughput by traffic class ──────────────────────── */}
      <SECTION icon={BarChart2} title="Throughput by Traffic Class — Sent vs Received (Mbps)">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="card p-4">
            <p className="font-mono text-xs text-muted mb-1">Sent (client) vs Received (server) — Mbps</p>
            <p className="font-mono text-xs text-muted mb-3 opacity-60">Gap = bytes absorbed by shaping</p>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={throughputChartData} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                <XAxis dataKey="tc" tick={{ fontSize: 11, fill: 'var(--color-muted)' }} />
                <YAxis tick={{ fontSize: 10, fill: 'var(--color-muted)' }} unit=" Mbps" width={60} />
                <Tooltip
                  contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 4, fontSize: 11 }}
                  formatter={(v: number, name: string) => [`${Number(v).toFixed(2)} Mbps`, name === 'sent' ? 'Sent (client)' : 'Received (server)']}
                />
                <Legend iconSize={10} wrapperStyle={{ fontSize: 11 }} formatter={n => n === 'sent' ? 'Sent (client)' : 'Received (server)'} />
                <Bar dataKey="sent" fill="var(--color-muted)" opacity={0.45} radius={[2, 2, 0, 0]} />
                <Bar dataKey="rcv" radius={[3, 3, 0, 0]}>
                  {throughputChartData.map(entry => (
                    <Cell key={entry.tc} fill={TC_COLOR[entry.tc.toLowerCase()] ?? accentColor} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="card p-4">
            <p className="font-mono text-xs text-muted mb-1">Delivery Ratio — % of sent bytes received</p>
            <p className="font-mono text-xs text-muted mb-3 opacity-60">100% = no packet loss from shaping</p>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={throughputChartData} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                <XAxis dataKey="tc" tick={{ fontSize: 11, fill: 'var(--color-muted)' }} />
                <YAxis tick={{ fontSize: 10, fill: 'var(--color-muted)' }} unit="%" domain={[0, 100]} width={44} />
                <Tooltip
                  contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 4, fontSize: 11 }}
                  formatter={(v: number) => [`${Number(v).toFixed(1)}%`, 'Delivery Ratio']}
                />
                <Bar dataKey="dr" radius={[3, 3, 0, 0]}>
                  {throughputChartData.map(entry => (
                    <Cell key={entry.tc} fill={TC_COLOR[entry.tc.toLowerCase()] ?? accentColor} opacity={0.85} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </SECTION>

      {/* ── Detailed metrics table ───────────────────────────── */}
      <SECTION icon={Database} title="Traffic Class Detail">
        <div className="card overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="bg-surface border-b border-border">
                {['Traffic Class', 'Sent Mbps', 'Rcv Mbps', 'Delivery Ratio', 'Avg RTT (µs)', 'Min RTT', 'Max RTT', 'RTT σ', 'Retransmits', 'CPU Host %'].map(h => (
                  <th key={h} className="px-3 py-2 text-muted uppercase tracking-wider font-bold whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {TC_KEYS.map(tc => {
                const s = data.iperf[tc]?.summary;
                const dr = s?.delivery_ratio;
                const drColor = dr == null ? 'text-muted' : dr >= 99 ? 'text-green-400' : dr >= 95 ? 'text-yellow-400' : 'text-red-400';
                return (
                  <tr key={tc} className="border-b border-border hover:bg-surface2">
                    <td className="px-3 py-2 font-bold" style={{ color: TC_COLOR[tc] }}>
                      {TC_LABEL[tc]} <span className="font-normal text-muted">— {TC_FULL[tc]}</span>
                    </td>
                    <td className="px-3 py-2 text-muted">{s ? fmt(s.sent_throughput_mbps) : '—'}</td>
                    <td className="px-3 py-2 text-textdim font-semibold">{s ? fmt(s.throughput_mbps) : '—'}</td>
                    <td className={`px-3 py-2 font-semibold ${drColor}`}>
                      {dr != null ? `${fmt(dr, 1)}%` : '—'}
                    </td>
                    <td className="px-3 py-2 text-textdim">{s ? fmt(s.avg_rtt_us, 0) : '—'}</td>
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
      </SECTION>

      {/* ── Time series per traffic class ────────────────────── */}
      {TC_KEYS.some(tc => data.iperf[tc]?.intervals.length) && (
        <SECTION icon={Activity} title="Throughput Time Series — per Second">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {TC_KEYS.map(tc => {
              const intervals = data.iperf[tc]?.intervals ?? [];
              if (!intervals.length) return null;
              const chartData = intervals.map(iv => ({
                t:    iv.interval_start,
                mbps: iv.bits_per_second / 1e6,
                rtt:  iv.rtt_us,
              }));
              const avgMbps = chartData.reduce((s, d) => s + d.mbps, 0) / chartData.length;
              return (
                <div key={tc} className="card p-3">
                  <p className="font-mono text-xs font-bold mb-2" style={{ color: TC_COLOR[tc] }}>
                    {TC_LABEL[tc]} — {TC_FULL[tc]}
                  </p>
                  <p className="font-mono text-xs text-muted mb-2">avg {avgMbps.toFixed(1)} Mbps</p>
                  <ResponsiveContainer width="100%" height={120}>
                    <LineChart data={chartData} margin={{ top: 2, right: 4, left: 0, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                      <XAxis dataKey="t" tick={{ fontSize: 9, fill: 'var(--color-muted)' }} tickFormatter={v => `${v}s`} />
                      <YAxis tick={{ fontSize: 9, fill: 'var(--color-muted)' }} width={40} tickFormatter={v => v.toFixed(0)} />
                      <Tooltip contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 4, fontSize: 10 }}
                        formatter={(v: number) => [`${v.toFixed(2)} Mbps`, 'Throughput']}
                        labelFormatter={v => `t=${v}s`} />
                      <ReferenceLine y={avgMbps} stroke="var(--color-muted)" strokeDasharray="3 3" />
                      <Line type="monotone" dataKey="mbps" stroke={TC_COLOR[tc]} dot={false} strokeWidth={1.5} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              );
            })}
          </div>
        </SECTION>
      )}

      {/* ── RTT time series ──────────────────────────────────── */}
      {TC_KEYS.some(tc => data.iperf[tc]?.intervals.some(iv => iv.rtt_us)) && (
        <SECTION icon={Clock} title="RTT Time Series — per Second">
          <div className="card p-4">
            <ResponsiveContainer width="100%" height={180}>
              <LineChart margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                <XAxis dataKey="t" type="number" tick={{ fontSize: 10, fill: 'var(--color-muted)' }} tickFormatter={v => `${v}s`} />
                <YAxis tick={{ fontSize: 10, fill: 'var(--color-muted)' }} unit=" µs" width={58} />
                <Tooltip contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 4, fontSize: 11 }}
                  formatter={(v: number, name: string) => [`${v.toFixed(0)} µs`, name]} labelFormatter={v => `t=${v}s`} />
                <Legend wrapperStyle={{ fontSize: 11, fontFamily: 'monospace' }} />
                {TC_KEYS.map(tc => {
                  const intervals = data.iperf[tc]?.intervals.filter(iv => iv.rtt_us) ?? [];
                  if (!intervals.length) return null;
                  const chartData = intervals.map(iv => ({ t: iv.interval_start, rtt: iv.rtt_us }));
                  return (
                    <Line key={tc} data={chartData} type="monotone" dataKey="rtt" name={TC_LABEL[tc]}
                      stroke={TC_COLOR[tc]} dot={false} strokeWidth={1.5} connectNulls />
                  );
                })}
              </LineChart>
            </ResponsiveContainer>
          </div>
        </SECTION>
      )}

      {/* ── CPU ──────────────────────────────────────────────── */}
      {data.cpu.snapshots.length > 0 && (
        <SECTION icon={Cpu} title="CPU Utilization (sar)">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
            {(() => {
              const snaps = data.cpu.snapshots;
              const avg = (key: 'usr_pct' | 'sys_pct' | 'soft_pct' | 'idle_pct') =>
                snaps.reduce((s, r) => s + (r[key] || 0), 0) / snaps.length;
              const totals = snaps.map(s => (s.usr_pct || 0) + (s.sys_pct || 0) + (s.soft_pct || 0));
              return [
                ['User %',      avg('usr_pct').toFixed(2)  + '%'],
                ['System %',    avg('sys_pct').toFixed(2)  + '%'],
                ['Softirq %',   avg('soft_pct').toFixed(2) + '%'],
                ['Total Active', (totals.reduce((a, b) => a + b, 0) / totals.length).toFixed(2) + '%'],
              ].map(([label, value]) => <StatTile key={String(label)} label={String(label)} value={String(value)} />);
            })()}
          </div>
          {cpuTimelineData.length > 0 && (
            <div className="card p-4">
              <p className="font-mono text-xs text-muted mb-3">CPU timeline — {data.cpu.snapshots.length} sar snapshots</p>
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

      {/* ── HTB TC classes (HTB only) ────────────────────────── */}
      {qosType === 'htb' && data.htbClasses.length > 0 && (
        <SECTION icon={TrendingUp} title="HTB TC Class Configuration">
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
                {data.htbClasses.map(c => {
                  const mbps = (c.bytes_sent * 8) / 30 / 1e6;
                  return (
                    <tr key={c.id} className="border-b border-border hover:bg-surface2">
                      <td className="px-3 py-2 text-htb font-bold">{c.class_id}</td>
                      <td className="px-3 py-2 text-textdim">{c.rate}</td>
                      <td className="px-3 py-2 text-muted">{fmtK(c.bytes_sent)}</td>
                      <td className="px-3 py-2 text-muted">{fmtK(c.packets)}</td>
                      <td className={`px-3 py-2 ${c.dropped > 0 ? 'text-red-400 font-semibold' : 'text-muted'}`}>{fmtK(c.dropped)}</td>
                      <td className="px-3 py-2 text-muted">{fmtK(c.overlimits)}</td>
                      <td className="px-3 py-2 text-textdim font-semibold">{mbps.toFixed(2)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </SECTION>
      )}

      {/* ── eBPF Map Stats (eBPF only) ───────────────────────── */}
      {qosType === 'ebpf' && data.ebpfClasses.length > 0 && (() => {
        const totalEcn = data.ebpfClasses.reduce((s, c) => s + (c.ecn_marked || 0), 0);
        const totalDly = data.ebpfClasses.reduce((s, c) => s + (c.delayed || 0), 0);
        const totalBor = data.ebpfClasses.reduce((s, c) => s + (c.borrowed || 0), 0);
        return (
          <SECTION icon={AlertTriangle} title="eBPF Map Statistics (XDP counters)">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
              {data.ebpfClasses.map(c => {
                const mbps = (c.bytes * 8) / 30 / 1e6;
                return (
                  <div key={c.id} className="card p-4">
                    <div className="font-mono text-xs font-bold uppercase tracking-widest text-accent mb-3 pb-2 border-b border-border">
                      {c.class_name} (key {c.class_key})
                    </div>
                    {[
                      ['packets',    fmtK(c.packets),    false],
                      ['throughput', `${mbps.toFixed(2)} Mbps`, false],
                      ['bytes',      fmtK(c.bytes),      false],
                      ['borrowed',   fmtK(c.borrowed),   c.borrowed > 0],
                      ['ECN marked', fmtK(c.ecn_marked), c.ecn_marked > 0],
                      ['delayed',    fmtK(c.delayed),    c.delayed > 0],
                    ].map(([k, v, hi]) => (
                      <div key={String(k)} className="flex justify-between items-baseline py-1.5 border-b border-border last:border-0 font-mono text-xs">
                        <span className="text-muted">{k}</span>
                        <span className={hi ? 'text-yellow-400 font-semibold' : 'text-textdim'}>{String(v)}</span>
                      </div>
                    ))}
                  </div>
                );
              })}
            </div>
            <div className="grid grid-cols-3 gap-3">
              {[
                ['Total ECN Marks',  totalEcn, 'Active congestion signalling'],
                ['Total Delayed',    totalDly, 'Packet shaping events'],
                ['Total Borrowed',   totalBor, 'Bandwidth borrowing events'],
              ].map(([label, val, note]) => (
                <div key={String(label)} className="card p-3 text-center">
                  <p className="font-mono text-xs text-muted uppercase tracking-wider mb-1">{label}</p>
                  <p className={`font-mono text-xl font-bold ${Number(val) > 0 ? 'text-yellow-400' : 'text-textdim'}`}>
                    {fmtK(Number(val))}
                  </p>
                  <p className="font-mono text-xs text-muted mt-0.5">{note}</p>
                </div>
              ))}
            </div>
          </SECTION>
        );
      })()}
    </div>
  );
}
