'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft, FileDown, Loader2, Activity, Cpu, BarChart2,
  Zap, Clock, AlertTriangle, Database
} from 'lucide-react';
import { api } from '@/lib/api';
import type { ExperimentDetail } from '@/types';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine
} from 'recharts';

// ── helpers ──────────────────────────────────────────────────────────────────
const QOS_LABEL: Record<string, string> = { no_qos: 'No QoS', htb: 'HTB', ebpf: 'eBPF' };
const QOS_COLOR: Record<string, string> = { no_qos: 'var(--color-noqos)', htb: 'var(--color-htb)', ebpf: 'var(--color-accent)' };
const TC_LABEL:  Record<string, string> = { ef: 'EF — Expedited Forwarding', af: 'AF — Assured Forwarding', be: 'BE — Best Effort' };
const EXP_LABEL: Record<string, string> = { iperf: 'iperf3 TCP Throughput', cpu: 'CPU Utilization (sar)', htb_tc: 'HTB TC Classes', ebpf_map: 'eBPF Map Stats' };

function fmt(n: number | null | undefined, d = 2) {
  if (n == null || isNaN(Number(n))) return '—';
  return Number(n).toFixed(d);
}
function fmtK(n: number | null | undefined) {
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

const StatRow = ({ label, value, hi }: { label: string; value: string; hi?: boolean }) => (
  <div className="flex justify-between items-baseline py-1.5 border-b border-border last:border-0 font-mono text-xs">
    <span className="text-muted">{label}</span>
    <span className={hi ? 'text-yellow-400 font-semibold' : 'text-textdim'}>{value}</span>
  </div>
);

// ── Page ─────────────────────────────────────────────────────────────────────
export default function ExperimentPage() {
  const { id, expId } = useParams<{ id: string; expId: string }>();
  const router = useRouter();
  const [exp,       setExp]       = useState<ExperimentDetail | null>(null);
  const [error,     setError]     = useState('');
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    api.getExperiment(parseInt(expId))
      .then(setExp)
      .catch(e => setError(e.message));
  }, [expId]);

  async function handleExport() {
    if (!exp || exporting) return;
    setExporting(true);
    try {
      const slug = `${exp.qos_type}-${exp.experiment_type}${exp.traffic_class ? '-' + exp.traffic_class : ''}-exp${exp.id}`;
      await api.downloadExperimentReport(exp.id, slug);
    } catch (e: unknown) {
      alert('Export failed: ' + (e instanceof Error ? e.message : String(e)));
    } finally {
      setExporting(false);
    }
  }

  if (error) return (
    <div className="text-red-400 font-mono text-sm bg-red-400/10 border border-red-400/20 rounded p-4">{error}</div>
  );
  if (!exp) return (
    <div className="text-muted font-mono text-sm text-center py-20">กำลังโหลด...</div>
  );

  const accentColor = QOS_COLOR[exp.qos_type] || '#888';

  return (
    <div>
      {/* Header */}
      <div className="flex items-start gap-3 mb-8">
        <button onClick={() => router.back()} className="mt-0.5 p-1.5 rounded hover:bg-surface transition-colors text-muted hover:text-textdim">
          <ArrowLeft size={16} />
        </button>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-xs text-muted">{exp.dataset_name}</span>
            <span className="text-border">/</span>
            <span className="font-mono text-xs px-1.5 py-0.5 rounded bg-surface border border-border text-textdim">
              Exp #{exp.id}
            </span>
          </div>
          <h1 className="font-mono text-lg font-bold text-textdim mt-1">
            {QOS_LABEL[exp.qos_type] || exp.qos_type}
            {exp.traffic_class && <span className="text-muted"> / {exp.traffic_class.toUpperCase()}</span>}
            <span className="ml-2 text-sm font-normal text-muted">— {EXP_LABEL[exp.experiment_type] || exp.experiment_type}</span>
          </h1>
          {exp.source_filename && (
            <p className="font-mono text-xs text-muted mt-0.5">{exp.source_filename}</p>
          )}
          {exp.traffic_class && (
            <p className="text-xs text-muted mt-0.5">{TC_LABEL[exp.traffic_class]}</p>
          )}
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

      {/* ── iperf ─────────────────────────────────────────────── */}
      {exp.experiment_type === 'iperf' && exp.summary && (() => {
        const s = exp.summary;
        return (
          <>
            <SECTION icon={Zap} title="Summary Statistics">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                {/* throughput */}
                <div className="card p-4">
                  <p className="font-mono text-xs text-muted uppercase tracking-wider mb-2">Throughput</p>
                  <p className="font-mono text-2xl font-bold text-textdim">{fmt(s.throughput_mbps)} <span className="text-sm font-normal text-muted">Mbps</span></p>
                </div>
                {/* avg RTT */}
                <div className="card p-4">
                  <p className="font-mono text-xs text-muted uppercase tracking-wider mb-2">Avg RTT</p>
                  <p className="font-mono text-2xl font-bold" style={{ color: accentColor }}>
                    {fmt(s.avg_rtt_us, 0)} <span className="text-sm font-normal text-muted">µs</span>
                  </p>
                  <p className="font-mono text-xs text-muted mt-1">min {fmt(s.min_rtt_us, 0)} · max {fmt(s.max_rtt_us, 0)} · σ {fmt(s.rtt_std_us, 0)}</p>
                </div>
                {/* retransmits */}
                <div className="card p-4">
                  <p className="font-mono text-xs text-muted uppercase tracking-wider mb-2">Retransmits</p>
                  <p className={`font-mono text-2xl font-bold ${s.retransmits > 0 ? 'text-yellow-400' : 'text-textdim'}`}>
                    {fmtK(s.retransmits)}
                  </p>
                  <p className="font-mono text-xs text-muted mt-1">Duration {fmt(s.duration_s, 0)} s</p>
                </div>
                {/* CPU */}
                <div className="card p-4 sm:col-span-2 lg:col-span-3">
                  <p className="font-mono text-xs text-muted uppercase tracking-wider mb-3">CPU (iperf3 measurement)</p>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-x-6">
                    <StatRow label="Host Total"   value={`${fmt(s.cpu_host_total)}%`} />
                    <StatRow label="Host User"    value={`${fmt(s.cpu_host_user)}%`} />
                    <StatRow label="Host System"  value={`${fmt(s.cpu_host_system)}%`} />
                    <StatRow label="Remote Total" value={`${fmt(s.cpu_remote_total)}%`} />
                  </div>
                </div>
              </div>
            </SECTION>

            {/* Time series charts */}
            {exp.intervals.length > 0 && (() => {
              const data = exp.intervals.map(iv => ({
                t:    iv.interval_start,
                mbps: iv.bits_per_second / 1e6,
                rtt:  iv.rtt_us,
                retx: iv.retransmits,
              }));
              const avgMbps = data.reduce((s, d) => s + d.mbps, 0) / data.length;
              const avgRtt  = data.filter(d => d.rtt).reduce((s, d) => s + (d.rtt ?? 0), 0) / data.filter(d => d.rtt).length;

              return (
                <>
                  <SECTION icon={Activity} title="Throughput per Second">
                    <div className="card p-4">
                      <ResponsiveContainer width="100%" height={180}>
                        <LineChart data={data} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                          <XAxis dataKey="t" tick={{ fontSize: 10, fill: 'var(--color-muted)' }} tickFormatter={v => `${v}s`} />
                          <YAxis tick={{ fontSize: 10, fill: 'var(--color-muted)' }} tickFormatter={v => `${v.toFixed(0)}`} unit=" Mbps" width={62} />
                          <Tooltip
                            contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 4, fontSize: 11 }}
                            formatter={(v: number) => [`${v.toFixed(2)} Mbps`, 'Throughput']}
                            labelFormatter={v => `t = ${v}s`}
                          />
                          <ReferenceLine y={avgMbps} stroke="var(--color-muted)" strokeDasharray="4 4" label={{ value: 'avg', fill: 'var(--color-muted)', fontSize: 10 }} />
                          <Line type="monotone" dataKey="mbps" stroke={accentColor} dot={false} strokeWidth={1.5} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  </SECTION>

                  <SECTION icon={Clock} title="RTT per Second">
                    <div className="card p-4">
                      <ResponsiveContainer width="100%" height={160}>
                        <LineChart data={data} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                          <XAxis dataKey="t" tick={{ fontSize: 10, fill: 'var(--color-muted)' }} tickFormatter={v => `${v}s`} />
                          <YAxis tick={{ fontSize: 10, fill: 'var(--color-muted)' }} tickFormatter={v => v.toFixed(0)} unit=" µs" width={58} />
                          <Tooltip
                            contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 4, fontSize: 11 }}
                            formatter={(v: number) => [`${v.toFixed(0)} µs`, 'RTT']}
                            labelFormatter={v => `t = ${v}s`}
                          />
                          <ReferenceLine y={avgRtt} stroke="var(--color-muted)" strokeDasharray="4 4" label={{ value: 'avg', fill: 'var(--color-muted)', fontSize: 10 }} />
                          <Line type="monotone" dataKey="rtt" stroke="#f59e0b" dot={false} strokeWidth={1.5} connectNulls />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  </SECTION>

                  <SECTION icon={Database} title="Interval Data">
                    <div className="card overflow-x-auto">
                      <table className="w-full text-left border-collapse font-mono text-xs">
                        <thead>
                          <tr className="bg-surface border-b border-border">
                            {['#', 'Start (s)', 'End (s)', 'Mbps', 'RTT (µs)', 'Retx'].map(h => (
                              <th key={h} className="px-3 py-2 text-muted uppercase tracking-wider font-bold whitespace-nowrap">{h}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {exp.intervals.map((iv, i) => (
                            <tr key={iv.id} className="border-b border-border hover:bg-surface2">
                              <td className="px-3 py-1.5 text-muted">{i + 1}</td>
                              <td className="px-3 py-1.5 text-muted">{iv.interval_start.toFixed(1)}</td>
                              <td className="px-3 py-1.5 text-muted">{iv.interval_end.toFixed(1)}</td>
                              <td className="px-3 py-1.5 text-textdim font-semibold">{(iv.bits_per_second / 1e6).toFixed(2)}</td>
                              <td className="px-3 py-1.5 text-textdim">{iv.rtt_us != null ? iv.rtt_us.toFixed(0) : '—'}</td>
                              <td className={`px-3 py-1.5 ${iv.retransmits > 0 ? 'text-yellow-400' : 'text-muted'}`}>{iv.retransmits}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </SECTION>
                </>
              );
            })()}
          </>
        );
      })()}

      {/* ── cpu ───────────────────────────────────────────────── */}
      {exp.experiment_type === 'cpu' && exp.cpuSnapshots.length > 0 && (() => {
        const snaps = exp.cpuSnapshots;
        const avg = (key: keyof typeof snaps[0]) => snaps.reduce((s, r) => s + ((r[key] as number) || 0), 0) / snaps.length;
        const totals = snaps.map(s => (s.usr_pct || 0) + (s.sys_pct || 0) + (s.soft_pct || 0));
        const data = snaps.map((s, i) => ({
          i,
          time:  s.snapshot_time,
          total: (s.usr_pct || 0) + (s.sys_pct || 0) + (s.soft_pct || 0),
          usr:   s.usr_pct,
          sys:   s.sys_pct,
          soft:  s.soft_pct,
          idle:  s.idle_pct,
        }));

        return (
          <>
            <SECTION icon={Cpu} title="CPU Summary">
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
                {[
                  ['Avg User', `${avg('usr_pct').toFixed(2)}%`],
                  ['Avg System', `${avg('sys_pct').toFixed(2)}%`],
                  ['Avg Softirq', `${avg('soft_pct').toFixed(2)}%`],
                  ['Avg Idle', `${avg('idle_pct').toFixed(2)}%`],
                  ['Avg Active', `${(totals.reduce((a, b) => a + b, 0) / totals.length).toFixed(2)}%`],
                ].map(([label, value]) => (
                  <div key={String(label)} className="card p-3">
                    <p className="font-mono text-xs text-muted uppercase tracking-wider mb-1">{label}</p>
                    <p className="font-mono text-lg font-bold text-textdim">{value}</p>
                  </div>
                ))}
              </div>
            </SECTION>

            <SECTION icon={Activity} title="CPU Timeline">
              <div className="card p-4">
                <ResponsiveContainer width="100%" height={180}>
                  <LineChart data={data} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                    <XAxis dataKey="time" tick={{ fontSize: 9, fill: 'var(--color-muted)' }} interval="preserveStartEnd" />
                    <YAxis tick={{ fontSize: 10, fill: 'var(--color-muted)' }} unit="%" domain={[0, 100]} width={38} />
                    <Tooltip contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 4, fontSize: 11 }} />
                    <Line type="monotone" dataKey="total" name="Active %" stroke={accentColor}   dot={false} strokeWidth={2} />
                    <Line type="monotone" dataKey="usr"   name="User %"   stroke="#60a5fa" dot={false} strokeWidth={1} strokeDasharray="4 2" />
                    <Line type="monotone" dataKey="sys"   name="System %" stroke="#f59e0b" dot={false} strokeWidth={1} strokeDasharray="4 2" />
                    <Line type="monotone" dataKey="soft"  name="Softirq %" stroke="#a78bfa" dot={false} strokeWidth={1} strokeDasharray="2 2" />
                  </LineChart>
                </ResponsiveContainer>
                <div className="flex gap-4 mt-2 font-mono text-xs text-muted">
                  <span className="flex items-center gap-1"><span className="inline-block w-4 h-0.5" style={{ background: accentColor }} /> Active</span>
                  <span className="flex items-center gap-1"><span className="inline-block w-4 h-0.5 bg-blue-400" /> User</span>
                  <span className="flex items-center gap-1"><span className="inline-block w-4 h-0.5 bg-yellow-400" /> System</span>
                  <span className="flex items-center gap-1"><span className="inline-block w-4 h-0.5 bg-violet-400" /> Softirq</span>
                </div>
              </div>
            </SECTION>

            <SECTION icon={Database} title="Raw Snapshots">
              <div className="card overflow-x-auto">
                <table className="w-full text-left border-collapse font-mono text-xs">
                  <thead>
                    <tr className="bg-surface border-b border-border">
                      {['Time', 'CPU', 'User %', 'System %', 'Softirq %', 'Idle %', 'Active %'].map(h => (
                        <th key={h} className="px-3 py-2 text-muted uppercase tracking-wider font-bold whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {snaps.map(s => {
                      const total = (s.usr_pct || 0) + (s.sys_pct || 0) + (s.soft_pct || 0);
                      return (
                        <tr key={s.id} className="border-b border-border hover:bg-surface2">
                          <td className="px-3 py-1.5 text-muted">{s.snapshot_time}</td>
                          <td className="px-3 py-1.5 text-muted">{s.cpu_core}</td>
                          <td className="px-3 py-1.5 text-textdim">{fmt(s.usr_pct)}</td>
                          <td className="px-3 py-1.5 text-textdim">{fmt(s.sys_pct)}</td>
                          <td className="px-3 py-1.5 text-textdim">{fmt(s.soft_pct)}</td>
                          <td className="px-3 py-1.5 text-muted">{fmt(s.idle_pct)}</td>
                          <td className="px-3 py-1.5 text-textdim font-semibold">{fmt(total)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </SECTION>
          </>
        );
      })()}

      {/* ── htb_tc ────────────────────────────────────────────── */}
      {exp.experiment_type === 'htb_tc' && exp.htbClasses.length > 0 && (
        <SECTION icon={BarChart2} title="HTB TC Class Statistics">
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
                {exp.htbClasses.map(c => {
                  const mbps = (c.bytes_sent * 8) / 30 / 1e6;
                  return (
                    <tr key={c.id} className="border-b border-border hover:bg-surface2">
                      <td className="px-3 py-2 text-htb font-bold">{c.class_id}</td>
                      <td className="px-3 py-2 text-textdim">{c.rate}</td>
                      <td className="px-3 py-2 text-muted">{fmtK(c.bytes_sent)}</td>
                      <td className="px-3 py-2 text-muted">{fmtK(c.packets)}</td>
                      <td className={`px-3 py-2 ${c.dropped > 0 ? 'text-red-400' : 'text-muted'}`}>{fmtK(c.dropped)}</td>
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

      {/* ── ebpf_map ──────────────────────────────────────────── */}
      {exp.experiment_type === 'ebpf_map' && exp.ebpfClasses.length > 0 && (() => {
        const totalEcn = exp.ebpfClasses.reduce((s, c) => s + (c.ecn_marked || 0), 0);
        const totalDly = exp.ebpfClasses.reduce((s, c) => s + (c.delayed    || 0), 0);
        const totalBor = exp.ebpfClasses.reduce((s, c) => s + (c.borrowed   || 0), 0);
        return (
          <>
            <SECTION icon={AlertTriangle} title="eBPF Map Statistics">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
                {exp.ebpfClasses.map(c => {
                  const mbps = (c.bytes * 8) / 30 / 1e6;
                  return (
                    <div key={c.id} className="card p-4">
                      <div className="font-mono text-xs font-bold uppercase tracking-widest text-accent mb-3 pb-2 border-b border-border">
                        {c.class_name} (key {c.class_key})
                      </div>
                      <StatRow label="Packets"    value={fmtK(c.packets)} />
                      <StatRow label="Throughput" value={`${mbps.toFixed(2)} Mbps`} />
                      <StatRow label="Bytes"      value={fmtK(c.bytes)} />
                      <StatRow label="Borrowed"   value={fmtK(c.borrowed)}   hi={c.borrowed > 0} />
                      <StatRow label="ECN Marked" value={fmtK(c.ecn_marked)} hi={c.ecn_marked > 0} />
                      <StatRow label="Delayed"    value={fmtK(c.delayed)}    hi={c.delayed > 0} />
                    </div>
                  );
                })}
              </div>
              <div className="grid grid-cols-3 gap-3">
                {[
                  ['Total ECN Marks',  totalEcn, totalEcn > 0 ? 'Active congestion signalling' : 'No congestion marks'],
                  ['Total Delayed',    totalDly, totalDly > 0 ? 'Active shaping observed'      : 'No delays'],
                  ['Total Borrowed',   totalBor, totalBor > 0 ? 'Bandwidth borrowing occurred'  : 'No borrowing'],
                ].map(([label, val, note]) => (
                  <div key={String(label)} className="card p-3">
                    <p className="font-mono text-xs text-muted uppercase tracking-wider mb-1">{label}</p>
                    <p className={`font-mono text-lg font-bold ${Number(val) > 0 ? 'text-yellow-400' : 'text-textdim'}`}>
                      {fmtK(Number(val))}
                    </p>
                    <p className="font-mono text-xs text-muted mt-0.5">{note}</p>
                  </div>
                ))}
              </div>
            </SECTION>
          </>
        );
      })()}
    </div>
  );
}
