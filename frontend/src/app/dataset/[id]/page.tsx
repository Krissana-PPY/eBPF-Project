'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, Zap, Clock, Cpu, BarChart2, Activity, AlertTriangle, FileDown, Loader2, FlaskConical, ExternalLink, Layers } from 'lucide-react';
import Link from 'next/link';
import { api } from '@/lib/api';
import type { Dataset, ExperimentSummary, QosType } from '@/types';
import MetricCard       from '@/components/MetricCard';
import ThroughputChart  from '@/components/ThroughputChart';
import RTTChart         from '@/components/RTTChart';
import AccuracyTable    from '@/components/AccuracyTable';
import CPUCards         from '@/components/CPUCards';
import TimeSeriesChart  from '@/components/TimeSeriesChart';

const SECTION = ({ icon: Icon, title, children }: { icon: React.ElementType; title: string; children: React.ReactNode }) => (
  <section className="mb-10">
    <div className="flex items-center gap-2 mb-4">
      <Icon size={14} className="text-muted" />
      <h2 className="font-mono text-sm font-semibold text-textdim tracking-wide">{title}</h2>
      <div className="flex-1 h-px bg-border" />
    </div>
    {children}
  </section>
);

export default function DatasetPage() {
  const { id }  = useParams<{ id: string }>();
  const router  = useRouter();
  const [ds,         setDs]         = useState<Dataset | null>(null);
  const [exps,       setExps]       = useState<ExperimentSummary[]>([]);
  const [error,      setError]      = useState('');
  const [exporting,  setExporting]  = useState(false);
  const [expExporting,  setExpExporting]  = useState<number | null>(null);
  const [modeExporting, setModeExporting] = useState<QosType | null>(null);

  useEffect(() => {
    const numId = parseInt(id);
    api.getDataset(numId).then(setDs).catch(e => setError(e.message));
    api.listExperiments(numId).then(setExps).catch(() => {});
  }, [id]);

  async function handleModeExport(qosType: QosType) {
    if (!ds || modeExporting) return;
    setModeExporting(qosType);
    try {
      await api.downloadModeReport(ds.id, qosType);
    } catch (e: unknown) {
      alert('Export failed: ' + (e instanceof Error ? e.message : String(e)));
    } finally {
      setModeExporting(null);
    }
  }

  async function handleExpExport(exp: ExperimentSummary) {
    if (expExporting === exp.id) return;
    setExpExporting(exp.id);
    try {
      const slug = `${exp.qos_type}-${exp.experiment_type}${exp.traffic_class ? '-' + exp.traffic_class : ''}-exp${exp.id}`;
      await api.downloadExperimentReport(exp.id, slug);
    } catch (e: unknown) {
      alert('Export failed: ' + (e instanceof Error ? e.message : String(e)));
    } finally {
      setExpExporting(null);
    }
  }

  async function handleExport() {
    if (!ds || exporting) return;
    setExporting(true);
    try {
      const res = await fetch(`/api/datasets/${ds.id}/report`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      const slug = ds.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      a.href     = url;
      a.download = `ebpf-report-${slug}.md`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e: unknown) {
      alert('Export failed: ' + (e instanceof Error ? e.message : String(e)));
    } finally {
      setExporting(false);
    }
  }

  if (error) return (
    <div className="text-red-400 font-mono text-sm bg-red-400/10 border border-red-400/20 rounded p-4">{error}</div>
  );
  if (!ds) return (
    <div className="text-muted font-mono text-sm text-center py-20">กำลังโหลด...</div>
  );

  const m = ds.metrics;

  // Hero RTT values (EF class)
  const rttNoQos = m.no_qos?.ef?.avgRttUs;
  const rttHtb   = m.htb?.ef?.avgRttUs;
  const rttEbpf  = m.ebpf?.ef?.avgRttUs;
  const rttRatio = rttNoQos && rttEbpf ? (rttNoQos / rttEbpf).toFixed(1) : null;

  // eBPF map totals
  const ebpfMap   = m.ebpf?.mapStats;
  const totalEcn  = ebpfMap ? Object.values(ebpfMap).reduce((s, c) => s + (c.ecnMarked || 0), 0) : 0;
  const totalDelay= ebpfMap ? Object.values(ebpfMap).reduce((s, c) => s + (c.delayed   || 0), 0) : 0;

  return (
    <div>
      {/* Header */}
      <div className="flex items-start gap-3 mb-8">
        <button onClick={() => router.back()} className="mt-0.5 p-1.5 rounded hover:bg-surface transition-colors text-muted hover:text-textdim">
          <ArrowLeft size={16} />
        </button>
        <div className="flex-1 min-w-0">
          <h1 className="font-mono text-xl font-bold text-textdim">{ds.name}</h1>
          {ds.description && <p className="text-muted text-sm mt-0.5">{ds.description}</p>}
          <p className="font-mono text-xs text-muted mt-1">{new Date(ds.created_at).toLocaleString('th-TH')}</p>
        </div>
        <button
          onClick={handleExport}
          disabled={exporting}
          className="flex items-center gap-2 px-3 py-1.5 rounded border border-border bg-surface hover:bg-surface2 transition-colors font-mono text-xs text-textdim disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
          title="Export Markdown report (.md)"
        >
          {exporting
            ? <Loader2 size={13} className="animate-spin" />
            : <FileDown size={13} />}
          {exporting ? 'Exporting…' : 'Export .md'}
        </button>
      </div>

      {/* ── MODE ANALYSIS CARDS ─────────────────────────────── */}
      {(() => {
        const modes: { key: QosType; label: string; desc: string; color: string; borderColor: string }[] = [
          { key: 'no_qos', label: 'No QoS',  desc: 'Baseline — no traffic classification', color: 'text-noqos', borderColor: 'border-l-noqos' },
          { key: 'htb',    label: 'HTB',      desc: 'Hierarchical Token Bucket (tc qdisc)', color: 'text-htb',   borderColor: 'border-l-htb'   },
          { key: 'ebpf',   label: 'eBPF',     desc: 'XDP-based kernel classification',      color: 'text-accent',borderColor: 'border-l-accent' },
        ];
        return (
          <SECTION icon={Layers} title="Per-Mode Analysis">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {modes.map(({ key, label, desc, color, borderColor }) => {
                const mq = m[key];
                const efRtt   = mq?.ef?.avgRttUs;
                const efMbps  = mq?.ef?.throughputMbps;
                const cpuUsed = mq?.cpu?.avgTotal;
                const isExp   = modeExporting === key;
                return (
                  <div key={key} className={`card border-l-2 ${borderColor} p-4 flex flex-col gap-3`}>
                    <div>
                      <p className={`font-mono text-sm font-bold ${color} uppercase tracking-wider`}>{label}</p>
                      <p className="font-mono text-xs text-muted mt-0.5">{desc}</p>
                    </div>
                    <div className="grid grid-cols-3 gap-2 font-mono text-xs">
                      <div>
                        <p className="text-muted mb-0.5">EF RTT</p>
                        <p className="text-textdim font-semibold">{efRtt != null ? `${efRtt.toFixed(0)} µs` : '—'}</p>
                      </div>
                      <div>
                        <p className="text-muted mb-0.5">EF Mbps</p>
                        <p className="text-textdim font-semibold">{efMbps != null ? `${efMbps.toFixed(0)}` : '—'}</p>
                      </div>
                      <div>
                        <p className="text-muted mb-0.5">CPU</p>
                        <p className="text-textdim font-semibold">{cpuUsed != null ? `${cpuUsed.toFixed(1)}%` : '—'}</p>
                      </div>
                    </div>
                    <div className="flex gap-2 mt-auto pt-2 border-t border-border">
                      <Link
                        href={`/dataset/${id}/mode/${key}`}
                        className={`flex-1 text-center font-mono text-xs py-1.5 rounded border border-border hover:bg-surface2 transition-colors ${color}`}
                      >
                        Full Analysis
                      </Link>
                      <button
                        onClick={() => handleModeExport(key)}
                        disabled={isExp}
                        className="flex items-center gap-1 px-2 py-1.5 rounded border border-border hover:bg-surface2 transition-colors font-mono text-xs text-muted disabled:opacity-40"
                        title={`Export ${label} report`}
                      >
                        {isExp ? <Loader2 size={12} className="animate-spin" /> : <FileDown size={12} />}
                        .md
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </SECTION>
        );
      })()}

      {/* ── SECTION 1: RTT Hero ─────────────────────────────── */}
      <SECTION icon={Zap} title="Latency — EF Traffic Class (avg RTT)">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-1 mb-3">
          <MetricCard variant="noqos" label="No QoS"
            value={rttNoQos?.toFixed(0) ?? '—'} unit="µs avg RTT"
            sub="No traffic classification" />
          <MetricCard variant="htb" label="HTB"
            value={rttHtb?.toFixed(0) ?? '—'} unit="µs avg RTT"
            sub="Hierarchical Token Bucket" />
          <MetricCard variant="accent" label="eBPF"
            value={rttEbpf?.toFixed(0) ?? '—'} unit="µs avg RTT"
            sub="XDP-based classification"
            badge={rttRatio ? `${rttRatio}× lower than No QoS` : undefined} />
        </div>
        {rttRatio && (
          <div className="border border-border border-l-2 border-l-accent rounded px-4 py-3 bg-surface font-mono text-xs text-muted">
            eBPF EF average RTT: <span className="text-accent font-bold">{rttEbpf?.toFixed(0)} µs</span>
            {' '}vs No QoS: <span className="text-noqos">{rttNoQos?.toFixed(0)} µs</span>
            {' '}— latency improvement of <span className="text-accent font-bold">{rttRatio}×</span>
          </div>
        )}
      </SECTION>

      {/* ── SECTION 2: Throughput ───────────────────────────── */}
      <SECTION icon={BarChart2} title="Throughput by Traffic Class (Mbps)">
        <div className="card p-4">
          <ThroughputChart metrics={m} />
        </div>
      </SECTION>

      {/* ── SECTION 3: QoS Accuracy ─────────────────────────── */}
      <SECTION icon={Activity} title="QoS Accuracy — Actual vs Target Rate">
        <div className="card overflow-hidden">
          <AccuracyTable metrics={m} />
        </div>
      </SECTION>

      {/* ── SECTION 4: RTT Chart ────────────────────────────── */}
      <SECTION icon={Clock} title="RTT Comparison (avg µs)">
        <div className="card p-4">
          <RTTChart metrics={m} />
        </div>
      </SECTION>

      {/* ── SECTION 5: Time Series ──────────────────────────── */}
      {Object.keys(ds.timeSeries).length > 0 && (
        <SECTION icon={Activity} title="Time Series — Throughput per Second">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {(['ef', 'af', 'be'] as const).map(tc => (
              <div key={tc} className="card p-3">
                <p className="font-mono text-xs text-muted uppercase tracking-wider mb-2">{tc.toUpperCase()} class</p>
                <TimeSeriesChart timeSeries={ds.timeSeries} metric="bitsPerSecond" trafficClass={tc} />
              </div>
            ))}
          </div>
        </SECTION>
      )}

      {/* ── SECTION 6: CPU ──────────────────────────────────── */}
      <SECTION icon={Cpu} title="CPU Utilization (sar avg)">
        <CPUCards metrics={m} />
      </SECTION>

      {/* ── SECTION 7: eBPF Internals ───────────────────────── */}
      {ebpfMap && Object.keys(ebpfMap).length > 0 && (
        <SECTION icon={AlertTriangle} title="eBPF Map Statistics — Per-Class Detail">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {Object.entries(ebpfMap).map(([cls, stats]) => (
              <div key={cls} className="card p-4">
                <div className="font-mono text-xs font-bold uppercase tracking-widest text-accent mb-3 pb-2 border-b border-border">
                  {cls}
                </div>
                {[
                  ['packets',       stats.packets?.toLocaleString(), false],
                  ['throughput',    `${stats.throughputMbps?.toFixed(2)} Mbps`, false],
                  ['bytes',         stats.bytes?.toLocaleString(), false],
                  ['borrowed',      stats.borrowed?.toLocaleString(), stats.borrowed > 0],
                  ['ECN marked',    stats.ecnMarked?.toLocaleString(), stats.ecnMarked > 0],
                  ['delayed',       stats.delayed?.toLocaleString(), stats.delayed > 0],
                ].map(([k, v, hi]) => (
                  <div key={String(k)} className="flex justify-between items-baseline py-1.5 border-b border-border last:border-0 font-mono text-xs">
                    <span className="text-muted">{k}</span>
                    <span className={hi ? 'text-yellow-400 font-semibold' : 'text-textdim'}>{v}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
          {(totalEcn > 0 || totalDelay > 0) && (
            <div className="mt-3 font-mono text-xs text-muted border border-border rounded px-3 py-2">
              Total: ECN marked <span className="text-yellow-400">{totalEcn.toLocaleString()}</span> packets ·
              delayed <span className="text-yellow-400">{totalDelay.toLocaleString()}</span> events
              — indicates active congestion management in AF/BE classes
            </div>
          )}
        </SECTION>
      )}

      {/* ── SECTION 8: HTB TC classes ───────────────────────── */}
      {m.htb?.tcClasses && Object.keys(m.htb.tcClasses).length > 0 && (
        <SECTION icon={BarChart2} title="HTB TC Class Statistics">
          <div className="card overflow-x-auto">
            <table className="w-full text-left border-collapse font-mono text-xs">
              <thead>
                <tr className="bg-surface border-b border-border">
                  {['Class', 'Rate', 'Bytes Sent', 'Packets', 'Dropped', 'Overlimits', 'Mbps (calc)'].map(h => (
                    <th key={h} className="px-3 py-2 text-muted uppercase tracking-wider text-xs font-bold whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {Object.entries(m.htb.tcClasses).sort().map(([cid, s]) => (
                  <tr key={cid} className="border-b border-border hover:bg-surface2">
                    <td className="px-3 py-2 text-htb font-bold">{cid}</td>
                    <td className="px-3 py-2 text-textdim">{s.rate}</td>
                    <td className="px-3 py-2 text-muted">{s.bytesSent?.toLocaleString()}</td>
                    <td className="px-3 py-2 text-muted">{s.packets?.toLocaleString()}</td>
                    <td className={`px-3 py-2 ${s.dropped > 0 ? 'text-red-400' : 'text-muted'}`}>{s.dropped?.toLocaleString()}</td>
                    <td className="px-3 py-2 text-muted">{s.overlimits?.toLocaleString()}</td>
                    <td className="px-3 py-2 text-textdim font-semibold">{s.throughputMbps?.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SECTION>
      )}

      {/* ── SECTION 9: Individual Experiments ──────────────── */}
      {exps.length > 0 && (
        <SECTION icon={FlaskConical} title={`Individual Experiments (${exps.length} files)`}>
          <div className="card overflow-x-auto">
            <table className="w-full text-left border-collapse font-mono text-xs">
              <thead>
                <tr className="bg-surface border-b border-border">
                  {['#', 'QoS', 'Class', 'Type', 'Source File', 'Throughput', 'Avg RTT', 'Retransmits', ''].map(h => (
                    <th key={h} className="px-3 py-2 text-muted uppercase tracking-wider text-xs font-bold whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {exps.map(exp => {
                  const qosColor: Record<string, string> = { no_qos: 'text-noqos', htb: 'text-htb', ebpf: 'text-accent' };
                  const typeColor: Record<string, string> = { iperf: 'text-blue-400', cpu: 'text-yellow-400', htb_tc: 'text-htb', ebpf_map: 'text-accent' };
                  const expSlug = `${exp.qos_type}-${exp.experiment_type}${exp.traffic_class ? '-' + exp.traffic_class : ''}-exp${exp.id}`;
                  return (
                    <tr key={exp.id} className="border-b border-border hover:bg-surface2">
                      <td className="px-3 py-2 text-muted">{exp.id}</td>
                      <td className={`px-3 py-2 font-semibold ${qosColor[exp.qos_type] || 'text-textdim'}`}>
                        {exp.qos_type === 'no_qos' ? 'No QoS' : exp.qos_type.toUpperCase()}
                      </td>
                      <td className="px-3 py-2 text-textdim">{exp.traffic_class?.toUpperCase() ?? '—'}</td>
                      <td className={`px-3 py-2 ${typeColor[exp.experiment_type] || 'text-muted'}`}>
                        {exp.experiment_type}
                      </td>
                      <td className="px-3 py-2 text-muted max-w-[200px] truncate" title={exp.source_filename ?? ''}>
                        {exp.source_filename ?? '—'}
                      </td>
                      <td className="px-3 py-2 text-textdim">
                        {exp.throughput_mbps != null ? `${exp.throughput_mbps.toFixed(1)} Mbps` : '—'}
                      </td>
                      <td className="px-3 py-2 text-textdim">
                        {exp.avg_rtt_us != null ? `${exp.avg_rtt_us.toFixed(0)} µs` : '—'}
                      </td>
                      <td className="px-3 py-2 text-muted">
                        {exp.retransmits != null ? exp.retransmits.toLocaleString() : '—'}
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-1">
                          <Link
                            href={`/dataset/${id}/experiment/${exp.id}`}
                            className="p-1.5 rounded hover:bg-surface2 text-muted hover:text-textdim transition-colors"
                            title="View experiment detail"
                          >
                            <ExternalLink size={12} />
                          </Link>
                          <button
                            onClick={() => handleExpExport(exp)}
                            disabled={expExporting === exp.id}
                            className="p-1.5 rounded hover:bg-surface2 text-muted hover:text-textdim transition-colors disabled:opacity-40"
                            title="Export experiment .md report"
                          >
                            {expExporting === exp.id
                              ? <Loader2 size={12} className="animate-spin" />
                              : <FileDown size={12} />}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </SECTION>
      )}
    </div>
  );
}
