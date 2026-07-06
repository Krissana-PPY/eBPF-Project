'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft, FileDown, Loader2, Activity, Cpu, BarChart2,
  Zap, AlertTriangle, FlaskConical, ExternalLink, Layers, Info, TrendingUp,
} from 'lucide-react';
import Link from 'next/link';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend, ReferenceLine, LineChart, Line,
} from 'recharts';
import { api } from '@/lib/api';
import type { Dataset, ExperimentSummary, QosType, QosMetrics } from '@/types';

// ── Constants ────────────────────────────────────────────────────────────────
const C = { ebpf: '#00ddb0', htb: '#f59e0b', noqos: '#5b7fa6', ef: '#22d3ee', af: '#a78bfa', be: '#fb923c' };
const MODE_LABEL: Record<string, string> = { ebpf: 'eBPF', htb: 'HTB', no_qos: 'No QoS' };
const TC_LABEL: Record<string, string>   = { ef: 'EF', af: 'AF', be: 'BE' };
const TC_FULL: Record<string, string>    = { ef: 'Expedited Forwarding', af: 'Assured Forwarding', be: 'Best Effort' };
const MODE_KEYS = ['no_qos', 'htb', 'ebpf'] as const;
const TC_KEYS   = ['ef', 'af', 'be'] as const;

function fmt(n: number | null | undefined, d = 1) {
  if (n == null || isNaN(Number(n))) return '—';
  return Number(n).toFixed(d);
}
function fmtK(n: number | null | undefined) {
  if (n == null) return '—';
  return Number(n).toLocaleString('en-US');
}

// ── Shared components ────────────────────────────────────────────────────────
const SECTION = ({
  id, icon: Icon, title, tag, children,
}: { id?: string; icon: React.ElementType; title: string; tag?: string; children: React.ReactNode }) => (
  <section id={id} className="mb-10">
    <div className="flex items-center gap-2 mb-4">
      <Icon size={13} className="text-muted" />
      <h2 className="font-mono text-xs font-semibold text-textdim tracking-widest uppercase">{title}</h2>
      {tag && <span className="font-mono text-xs text-muted">{tag}</span>}
      <div className="flex-1 h-px bg-border" />
    </div>
    {children}
  </section>
);

const ChartTip = ({ active, payload, label, unit = '' }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-surface border border-border rounded p-2 font-mono text-xs shadow-lg">
      <p className="text-textdim mb-1">{label}</p>
      {payload.map((p: any) => (
        <p key={p.name} style={{ color: p.fill || p.color }}>
          {p.name}: {typeof p.value === 'number' ? p.value.toLocaleString() : p.value}{unit}
        </p>
      ))}
    </div>
  );
};

function GroupedBars({
  title, data, bars, unit = '', height = 220,
}: {
  title: string;
  data: Record<string, any>[];
  bars: { key: string; label: string; color: string }[];
  unit?: string;
  height?: number;
}) {
  return (
    <div className="card p-3">
      <p className="font-mono text-xs text-muted uppercase tracking-wider mb-3">{title}</p>
      <ResponsiveContainer width="100%" height={height}>
        <BarChart data={data} margin={{ top: 4, right: 8, left: 0, bottom: 4 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1a2b40" vertical={false} />
          <XAxis dataKey="name" tick={{ fontFamily: 'monospace', fontSize: 11, fill: '#4d6880' }} />
          <YAxis tick={{ fontFamily: 'monospace', fontSize: 10, fill: '#4d6880' }} width={50}
            tickFormatter={(v) => v >= 1000 ? `${(v/1000).toFixed(v>=1000000?1:0)}${v>=1000000?'M':'K'}` : v} />
          <Tooltip content={<ChartTip unit={unit} />} />
          <Legend iconType="square" iconSize={8}
            wrapperStyle={{ fontFamily: 'monospace', fontSize: 11, paddingTop: '8px' }} />
          {bars.map(b => (
            <Bar key={b.key} dataKey={b.key} name={b.label} fill={b.color}
              radius={[2, 2, 0, 0]} maxBarSize={26} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function CpuStack({ data }: { data: { name: string; usr: number; sys: number; soft: number; idle: number }[] }) {
  return (
    <div className="card p-3">
      <p className="font-mono text-xs text-muted uppercase tracking-wider mb-3">CPU Breakdown — usr / sys / softirq / idle</p>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} margin={{ top: 4, right: 8, left: 0, bottom: 24 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1a2b40" vertical={false} />
          <XAxis dataKey="name" tick={{ fontFamily: 'monospace', fontSize: 9, fill: '#4d6880' }}
            interval={0} angle={-20} textAnchor="end" height={44} />
          <YAxis tick={{ fontFamily: 'monospace', fontSize: 10, fill: '#4d6880' }} width={34} domain={[0, 100]} />
          <Tooltip content={<ChartTip unit="%" />} />
          <Legend iconType="square" iconSize={8}
            wrapperStyle={{ fontFamily: 'monospace', fontSize: 11, paddingTop: '8px' }} />
          <Bar dataKey="usr"  name="usr"  stackId="a" fill="#22d3ee" maxBarSize={36} />
          <Bar dataKey="sys"  name="sys"  stackId="a" fill="#f59e0b" maxBarSize={36} />
          <Bar dataKey="soft" name="soft" stackId="a" fill="#a78bfa" maxBarSize={36} />
          <Bar dataKey="idle" name="idle" stackId="a" fill="#1a2b40" maxBarSize={36} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── Auto-generate findings ────────────────────────────────────────────────────
function genFindings(tcp: Record<string, QosMetrics> | undefined, udp: Record<string, QosMetrics> | undefined) {
  const out: { color: string; text: string }[] = [];
  if (!tcp) return out;

  const efRttE = (tcp.ebpf?.ef as any)?.avgRttUs;
  const efRttH = (tcp.htb?.ef  as any)?.avgRttUs;
  const efRttN = (tcp.no_qos?.ef as any)?.avgRttUs;
  if (efRttE && efRttN) out.push({
    color: C.ebpf,
    text: `eBPF EF TCP RTT: ${efRttE.toFixed(0)} µs — ${(efRttN/efRttE).toFixed(1)}× lower than No QoS (${efRttN.toFixed(0)} µs)` +
          (efRttH ? ` and ${(efRttH/efRttE).toFixed(1)}× lower than HTB (${efRttH.toFixed(0)} µs)` : '') +
          '. XDP scheduling eliminates qdisc queuing latency.',
  });

  const efE = (tcp.ebpf?.ef as any)?.throughputMbps;
  const afE = (tcp.ebpf?.af as any)?.throughputMbps;
  const beE = (tcp.ebpf?.be as any)?.throughputMbps;
  const afRetx = (tcp.ebpf?.af as any)?.retransmits;
  const beRetx = (tcp.ebpf?.be as any)?.retransmits;
  if (efE != null && afE != null && beE != null) {
    const tot = efE + afE + beE;
    out.push({
      color: C.ebpf,
      text: `eBPF TCP strict priority: EF=${efE.toFixed(0)} Mbps (${((efE/tot)*100).toFixed(0)}%), AF=${afE.toFixed(0)}, BE=${beE.toFixed(0)} Mbps. ` +
            `Total ${tot.toFixed(0)} Mbps (${((tot/1000)*100).toFixed(0)}% of 1 Gbps link). AF/BE retransmits: ${(afRetx||0).toLocaleString()}/${(beRetx||0).toLocaleString()}.`,
    });
  }

  const efH = (tcp.htb?.ef as any)?.throughputMbps;
  const afH = (tcp.htb?.af as any)?.throughputMbps;
  const beH = (tcp.htb?.be as any)?.throughputMbps;
  if (efH != null && afH != null && beH != null) {
    const tot = efH + afH + beH;
    out.push({
      color: C.htb,
      text: `HTB proportional allocation: EF=${efH.toFixed(0)}, AF=${afH.toFixed(0)}, BE=${beH.toFixed(0)} Mbps — total ${tot.toFixed(0)} Mbps (${((tot/1000)*100).toFixed(0)}% link utilization). Zero retransmits — enforcement via overlimits only.`,
    });
  }

  const cpuE = (tcp.ebpf?.cpu as any)?.avgTotal;
  const cpuH = (tcp.htb?.cpu  as any)?.avgTotal;
  const usrE = (tcp.ebpf?.cpu as any)?.avgUsr;
  if (cpuE != null && cpuH != null) out.push({
    color: '#f59e0b',
    text: `eBPF TCP CPU: ${cpuE.toFixed(1)}% active (${(usrE||0).toFixed(1)}% usr) vs HTB ${cpuH.toFixed(1)}% — ${(cpuE/cpuH).toFixed(0)}× higher. High user-space CPU suggests a user-space token-bucket control plane.`,
  });

  if (udp) {
    const efDr = (udp.ebpf?.ef as any)?.deliveryRatio;
    const beDr = (udp.ebpf?.be as any)?.deliveryRatio;
    if (efDr != null && beDr != null && efDr < beDr) out.push({
      color: '#ef4444',
      text: `eBPF UDP anomaly: EF delivery ratio ${efDr.toFixed(1)}% < BE ${beDr.toFixed(1)}% — priority is inverted. eBPF map: 0 delayed events for EF vs 800K+ for AF/BE, indicating EF uses drop-based (no delay queue) while AF/BE use delay-based enforcement.`,
    });
  }

  const noqosEf = (tcp.no_qos?.ef as any)?.throughputMbps;
  const noqosAf = (tcp.no_qos?.af as any)?.throughputMbps;
  const noqosBe = (tcp.no_qos?.be as any)?.throughputMbps;
  if (noqosEf != null && noqosAf != null && noqosBe != null) out.push({
    color: C.noqos,
    text: `No QoS baseline: TCP CUBIC fair-shares equally — EF=${noqosEf.toFixed(0)}, AF=${noqosAf.toFixed(0)}, BE=${noqosBe.toFixed(0)} Mbps, RTT ~${(tcp.no_qos?.ef as any)?.avgRttUs?.toFixed(0)||'—'} µs. Any QoS benefit must exceed this reference.`,
  });

  return out;
}

// ── Page ─────────────────────────────────────────────────────────────────────
export default function DatasetPage() {
  const { id }  = useParams<{ id: string }>();
  const router  = useRouter();
  const [ds,           setDs]           = useState<Dataset | null>(null);
  const [exps,         setExps]         = useState<ExperimentSummary[]>([]);
  const [error,        setError]        = useState('');
  const [exporting,    setExporting]    = useState(false);
  const [expExporting, setExpExporting] = useState<number | null>(null);
  const [modeExp,      setModeExp]      = useState<QosType | null>(null);

  useEffect(() => {
    const n = parseInt(id);
    api.getDataset(n).then(setDs).catch(e => setError(e.message));
    api.listExperiments(n).then(setExps).catch(() => {});
  }, [id]);

  async function doExport() {
    if (!ds || exporting) return;
    setExporting(true);
    try {
      const r = await fetch(`/api/datasets/${ds.id}/report`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const blob = await r.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href = url;
      a.download = `ebpf-report-${ds.name.toLowerCase().replace(/[^a-z0-9]+/g,'-')}.md`;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    } catch (e: unknown) { alert('Export failed: ' + (e instanceof Error ? e.message : String(e))); }
    finally { setExporting(false); }
  }

  async function doModeExport(q: QosType) {
    if (!ds || modeExp) return;
    setModeExp(q);
    try { await api.downloadModeReport(ds.id, q); }
    catch (e: unknown) { alert('Export failed: ' + (e instanceof Error ? e.message : String(e))); }
    finally { setModeExp(null); }
  }

  async function doExpExport(exp: ExperimentSummary) {
    if (expExporting === exp.id) return;
    setExpExporting(exp.id);
    try {
      const slug = `${exp.qos_type}-${exp.experiment_type}${exp.traffic_class?'-'+exp.traffic_class:''}-exp${exp.id}`;
      await api.downloadExperimentReport(exp.id, slug);
    } catch (e: unknown) { alert('Export failed: ' + (e instanceof Error ? e.message : String(e))); }
    finally { setExpExporting(null); }
  }

  if (error) return <div className="text-red-400 font-mono text-sm bg-red-400/10 border border-red-400/20 rounded p-4">{error}</div>;
  if (!ds)   return <div className="text-muted font-mono text-sm text-center py-20">กำลังโหลด...</div>;

  // ── Data extraction ────────────────────────────────────────────────────────
  const mbp  = ds.metricsByProtocol;
  const tcp  = mbp?.tcp as Record<string, QosMetrics> | undefined;
  const udp  = mbp?.udp as Record<string, QosMetrics> | undefined;
  const m    = ds.metrics;
  const findings = genFindings(tcp, udp);

  // helpers
  const tcpVal = (q: string, tc: string, key: string): number =>
    ((tcp?.[q]?.[tc as keyof QosMetrics] as any)?.[key] ?? 0) as number;
  const udpVal = (q: string, tc: string, key: string): number =>
    ((udp?.[q]?.[tc as keyof QosMetrics] as any)?.[key] ?? 0) as number;
  const cpuVal = (proto: 'tcp'|'udp', q: string, key: string): number =>
    (((proto === 'tcp' ? tcp : udp)?.[q]?.cpu as any)?.[key] ?? 0) as number;

  // TCP charts
  const tcpTputData = TC_KEYS.map(tc => ({
    name: TC_LABEL[tc],
    'No QoS': +tcpVal('no_qos', tc, 'throughputMbps').toFixed(1),
    'HTB':    +tcpVal('htb',    tc, 'throughputMbps').toFixed(1),
    'eBPF':   +tcpVal('ebpf',   tc, 'throughputMbps').toFixed(1),
  }));
  const tcpRttData = TC_KEYS.map(tc => ({
    name: TC_LABEL[tc],
    'No QoS': Math.round(tcpVal('no_qos', tc, 'avgRttUs')),
    'HTB':    Math.round(tcpVal('htb',    tc, 'avgRttUs')),
    'eBPF':   Math.round(tcpVal('ebpf',   tc, 'avgRttUs')),
  }));

  // UDP charts
  const udpTputData = TC_KEYS.map(tc => ({
    name: TC_LABEL[tc],
    'No QoS': +udpVal('no_qos', tc, 'throughputMbps').toFixed(1),
    'HTB':    +udpVal('htb',    tc, 'throughputMbps').toFixed(1),
    'eBPF':   +udpVal('ebpf',   tc, 'throughputMbps').toFixed(1),
  }));
  const udpDrData = TC_KEYS.map(tc => ({
    name: TC_LABEL[tc],
    'No QoS': +udpVal('no_qos', tc, 'deliveryRatio').toFixed(1),
    'HTB':    +udpVal('htb',    tc, 'deliveryRatio').toFixed(1),
    'eBPF':   +udpVal('ebpf',   tc, 'deliveryRatio').toFixed(1),
  }));

  // CPU charts
  const cpuProtos = [tcp ? 'tcp' : null, udp ? 'udp' : null].filter(Boolean) as ('tcp'|'udp')[];
  const cpuTotalData = cpuProtos.flatMap(p =>
    MODE_KEYS.map(q => ({
      name: `${q === 'no_qos' ? 'NoQoS' : q.toUpperCase()} ${p.toUpperCase()}`,
      Total: +cpuVal(p, q, 'avgTotal').toFixed(1),
    }))
  );
  const cpuStackData = cpuProtos.flatMap(p =>
    MODE_KEYS.map(q => ({
      name: `${q === 'no_qos' ? 'NoQoS' : q.toUpperCase()} ${p.toUpperCase()}`,
      usr:  +cpuVal(p, q, 'avgUsr').toFixed(1),
      sys:  +cpuVal(p, q, 'avgSys').toFixed(1),
      soft: +cpuVal(p, q, 'avgSoft').toFixed(1),
      idle: +cpuVal(p, q, 'avgIdle').toFixed(1),
    }))
  );

  // HTB overlimits (TCP vs UDP)
  const htbTcp = m.htb?.tcClasses;
  const htbUdp = mbp?.udp?.htb?.tcClasses as Record<string,any> | undefined;
  const overlimData = htbTcp
    ? Object.entries(htbTcp).sort().map(([cls, s]) => ({
        name: cls,
        TCP:  s.overlimits,
        UDP:  htbUdp?.[cls]?.overlimits ?? 0,
      }))
    : [];

  // ── KPIs ──────────────────────────────────────────────────────────────────
  const kpiEbpfRtt  = (tcp?.ebpf?.ef   as any)?.avgRttUs   as number | undefined;
  const kpiNoqosRtt = (tcp?.no_qos?.ef as any)?.avgRttUs   as number | undefined;
  const kpiEbpfTput = (tcp?.ebpf?.ef   as any)?.throughputMbps as number | undefined;
  const kpiHtbTput  = (tcp?.htb?.ef    as any)?.throughputMbps as number | undefined;
  const kpiCpuEbpf  = (tcp?.ebpf?.cpu  as any)?.avgTotal   as number | undefined;
  const kpiCpuHtb   = (tcp?.htb?.cpu   as any)?.avgTotal   as number | undefined;

  return (
    <div>
      {/* ── HEADER ──────────────────────────────────────────────────────── */}
      <div className="flex items-start gap-3 mb-6">
        <button onClick={() => router.back()}
          className="mt-1 p-1.5 rounded hover:bg-surface text-muted hover:text-textdim">
          <ArrowLeft size={16} />
        </button>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="font-mono text-xl font-bold text-textdim">{ds.name}</h1>
            {ds.protocols?.map(p => (
              <span key={p} className="font-mono text-xs px-1.5 py-0.5 rounded bg-surface border border-border text-muted uppercase">{p}</span>
            ))}
          </div>
          {ds.description && <p className="text-muted text-sm mt-0.5">{ds.description}</p>}
          <p className="font-mono text-xs text-muted mt-1">{new Date(ds.created_at).toLocaleString('th-TH')}</p>
        </div>
        <button onClick={doExport} disabled={exporting}
          className="flex items-center gap-2 px-3 py-1.5 rounded border border-border bg-surface hover:bg-surface2 font-mono text-xs text-textdim disabled:opacity-50 whitespace-nowrap">
          {exporting ? <Loader2 size={13} className="animate-spin" /> : <FileDown size={13} />}
          Export .md
        </button>
      </div>

      {/* ── KPI CARDS ───────────────────────────────────────────────────── */}
      {kpiEbpfRtt != null && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-8">
          {[
            {
              label: 'eBPF EF RTT (TCP)',
              value: `${kpiEbpfRtt.toFixed(0)} µs`,
              sub:   kpiNoqosRtt ? `vs No QoS ${kpiNoqosRtt.toFixed(0)} µs — ${(kpiNoqosRtt/kpiEbpfRtt).toFixed(1)}× lower` : 'avg RTT',
              color: 'text-accent', border: 'border-l-accent',
            },
            {
              label: 'eBPF EF Throughput',
              value: kpiEbpfTput ? `${kpiEbpfTput.toFixed(0)} Mbps` : '—',
              sub:   'TCP received — post-shaping',
              color: 'text-accent', border: 'border-l-accent',
            },
            {
              label: 'HTB EF Throughput',
              value: kpiHtbTput ? `${kpiHtbTput.toFixed(0)} Mbps` : '—',
              sub:   'TCP proportional allocation',
              color: 'text-htb', border: 'border-l-htb',
            },
            {
              label: 'eBPF CPU Overhead',
              value: kpiCpuEbpf ? `${kpiCpuEbpf.toFixed(1)}%` : '—',
              sub:   kpiCpuEbpf && kpiCpuHtb ? `vs HTB ${kpiCpuHtb.toFixed(1)}% — ${(kpiCpuEbpf/kpiCpuHtb).toFixed(0)}× higher` : 'active CPU (TCP)',
              color: kpiCpuEbpf && kpiCpuEbpf > 40 ? 'text-yellow-400' : 'text-textdim',
              border: 'border-l-yellow-500',
            },
          ].map((k, i) => (
            <div key={i} className={`card border-l-2 ${k.border} p-3`}>
              <p className="font-mono text-xs text-muted uppercase tracking-wider mb-1">{k.label}</p>
              <p className={`font-mono text-2xl font-bold leading-none ${k.color}`}>{k.value}</p>
              <p className="font-mono text-xs text-muted mt-1">{k.sub}</p>
            </div>
          ))}
        </div>
      )}

      {/* ── EXECUTIVE SUMMARY ───────────────────────────────────────────── */}
      {findings.length > 0 && (
        <SECTION icon={Info} title="Executive Summary">
          <div className="flex flex-col gap-2">
            {findings.map((f, i) => (
              <div key={i} className="card p-3 flex gap-3 items-start">
                <span className="mt-1.5 w-2 h-2 rounded-full flex-shrink-0" style={{ background: f.color }} />
                <p className="font-mono text-xs text-muted leading-relaxed">{f.text}</p>
              </div>
            ))}
          </div>
        </SECTION>
      )}

      {/* ── PER-MODE OVERVIEW ───────────────────────────────────────────── */}
      <SECTION icon={Layers} title="Per-Mode Analysis">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {([
            { key: 'no_qos' as QosType, label: 'No QoS',  desc: 'Baseline — no traffic classification', color: 'text-noqos', border: 'border-l-noqos' },
            { key: 'htb'    as QosType, label: 'HTB',      desc: 'Hierarchical Token Bucket (tc qdisc)', color: 'text-htb',   border: 'border-l-htb'   },
            { key: 'ebpf'   as QosType, label: 'eBPF',     desc: 'XDP-based kernel classification',      color: 'text-accent',border: 'border-l-accent' },
          ] as const).map(({ key, label, desc, color, border }) => {
            const mq = tcp?.[key] as any ?? (m as any)[key];
            const isExp = modeExp === key;
            return (
              <div key={key} className={`card border-l-2 ${border} p-4 flex flex-col gap-2`}>
                <div>
                  <p className={`font-mono text-sm font-bold ${color} uppercase tracking-wider`}>{label}</p>
                  <p className="font-mono text-xs text-muted">{desc}</p>
                </div>
                <div className="grid grid-cols-3 gap-1 font-mono text-xs">
                  {[
                    ['EF RTT',  mq?.ef?.avgRttUs      != null ? `${(mq.ef.avgRttUs as number).toFixed(0)} µs`  : '—'],
                    ['EF Mbps', mq?.ef?.throughputMbps != null ? (mq.ef.throughputMbps as number).toFixed(0) : '—'],
                    ['CPU',     mq?.cpu?.avgTotal      != null ? `${(mq.cpu.avgTotal as number).toFixed(1)}%`   : '—'],
                  ].map(([lbl, val]) => (
                    <div key={lbl}><p className="text-muted">{lbl}</p><p className="text-textdim font-semibold">{val}</p></div>
                  ))}
                </div>
                <div className="flex gap-2 mt-1 pt-2 border-t border-border">
                  <Link href={`/dataset/${id}/mode/${key}`}
                    className={`flex-1 text-center font-mono text-xs py-1.5 rounded border border-border hover:bg-surface2 ${color}`}>
                    Full Analysis
                  </Link>
                  <button onClick={() => doModeExport(key)} disabled={!!isExp}
                    className="flex items-center gap-1 px-2 py-1.5 rounded border border-border hover:bg-surface2 font-mono text-xs text-muted disabled:opacity-40">
                    {isExp ? <Loader2 size={12} className="animate-spin" /> : <FileDown size={12} />} .md
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </SECTION>

      {/* ── TCP ANALYSIS ────────────────────────────────────────────────── */}
      {tcp && (
        <SECTION icon={BarChart2} title="TCP Analysis" tag="· iperf3 TCP · 30 s · CUBIC congestion control">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <GroupedBars title="Received Throughput (Mbps) — server-side goodput" data={tcpTputData}
              bars={[{ key:'No QoS',label:'No QoS',color:C.noqos },{ key:'HTB',label:'HTB',color:C.htb },{ key:'eBPF',label:'eBPF',color:C.ebpf }]}
              unit=" Mbps" />
            <GroupedBars title="Avg RTT (µs) — TCP ACK round-trip" data={tcpRttData}
              bars={[{ key:'No QoS',label:'No QoS',color:C.noqos },{ key:'HTB',label:'HTB',color:C.htb },{ key:'eBPF',label:'eBPF',color:C.ebpf }]}
              unit=" µs" />
          </div>
          <div className="overflow-x-auto card">
            <table className="w-full border-collapse font-mono text-xs">
              <thead>
                <tr className="bg-surface border-b border-border">
                  {['Mode','Class','Sent Mbps','Rcv Mbps','DR%','RTT min','RTT avg','RTT max','Retx','CPU Host'].map(h => (
                    <th key={h} className="px-2 py-2 text-muted uppercase tracking-wider text-xs font-bold whitespace-nowrap first:pl-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {MODE_KEYS.flatMap(q => TC_KEYS.map(tc => {
                  const d = tcp[q]?.[tc] as any;
                  if (!d) return null;
                  const rtt = d.avgRttUs ?? 0;
                  return (
                    <tr key={`${q}${tc}`} className="border-b border-border hover:bg-surface">
                      <td className="pl-3 pr-2 py-1.5"><span className={`tag tag-${q==='no_qos'?'noqos':q}`}>{MODE_LABEL[q]}</span></td>
                      <td className="px-2 py-1.5 font-bold" style={{ color: C[tc as keyof typeof C] }}>{TC_LABEL[tc]}</td>
                      <td className="px-2 py-1.5 text-muted">{fmt(d.sentThroughputMbps)}</td>
                      <td className="px-2 py-1.5 text-textdim font-semibold">{fmt(d.throughputMbps)}</td>
                      <td className="px-2 py-1.5 text-textdim">{fmt(d.deliveryRatio,1)}%</td>
                      <td className="px-2 py-1.5 text-muted">{fmtK(d.minRttUs)} µs</td>
                      <td className="px-2 py-1.5 font-semibold" style={{ color: rtt<500?C.ebpf:rtt>3000?'#ef4444':'#c8daea' }}>{fmtK(d.avgRttUs)} µs</td>
                      <td className="px-2 py-1.5 text-muted">{fmtK(d.maxRttUs)} µs</td>
                      <td className="px-2 py-1.5" style={{ color: (d.retransmits||0)>0?'#ef4444':'#4d6880' }}>{fmtK(d.retransmits)}</td>
                      <td className="px-2 py-1.5 text-muted">{fmt(d.cpuHostTotal)}%</td>
                    </tr>
                  );
                }))}
              </tbody>
            </table>
          </div>
        </SECTION>
      )}

      {/* ── UDP ANALYSIS ────────────────────────────────────────────────── */}
      {udp && (
        <SECTION icon={Activity} title="UDP Analysis" tag="· iperf3 UDP · 30 s · no congestion control">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <GroupedBars title="Received Throughput (Mbps) — post-shaping goodput" data={udpTputData}
              bars={[{ key:'No QoS',label:'No QoS',color:C.noqos },{ key:'HTB',label:'HTB',color:C.htb },{ key:'eBPF',label:'eBPF',color:C.ebpf }]}
              unit=" Mbps" />
            <GroupedBars title="Delivery Ratio (%) — rcv bytes / sent bytes × 100" data={udpDrData}
              bars={[{ key:'No QoS',label:'No QoS',color:C.noqos },{ key:'HTB',label:'HTB',color:C.htb },{ key:'eBPF',label:'eBPF',color:C.ebpf }]}
              unit="%" />
          </div>

          {/* eBPF anomaly callout */}
          {(() => {
            const efDr = (udp.ebpf?.ef as any)?.deliveryRatio;
            const beDr = (udp.ebpf?.be as any)?.deliveryRatio;
            if (efDr != null && beDr != null && efDr < beDr) return (
              <div className="card border-l-2 border-l-red-500 p-3 mb-4 flex gap-2 items-start">
                <AlertTriangle size={13} className="text-red-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="font-mono text-xs font-bold text-red-400 uppercase tracking-wider mb-1">eBPF UDP Priority Anomaly</p>
                  <p className="font-mono text-xs text-muted leading-relaxed">
                    EF delivery ratio ({efDr.toFixed(1)}%) is lower than BE ({beDr.toFixed(1)}%) — priority ordering is inverted for UDP.
                    eBPF map shows 0 delayed events for EF but 800K+ for AF/BE: EF uses drop-based enforcement (no delay queue) while
                    AF/BE use delay-based shaping. Verify the eBPF EF UDP token-bucket rate configuration.
                  </p>
                </div>
              </div>
            );
            return null;
          })()}

          <div className="overflow-x-auto card">
            <table className="w-full border-collapse font-mono text-xs">
              <thead>
                <tr className="bg-surface border-b border-border">
                  {['Mode','Class','Sent Mbps','Rcv Mbps','Delivery Ratio','CPU Host'].map(h => (
                    <th key={h} className="px-2 py-2 text-muted uppercase tracking-wider text-xs font-bold whitespace-nowrap first:pl-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {MODE_KEYS.flatMap(q => TC_KEYS.map(tc => {
                  const d = udp[q]?.[tc] as any;
                  if (!d) return null;
                  const dr = d.deliveryRatio ?? 0;
                  const drC = dr>=90?C.ebpf:dr>=70?C.htb:'#ef4444';
                  return (
                    <tr key={`${q}${tc}`} className="border-b border-border hover:bg-surface">
                      <td className="pl-3 pr-2 py-1.5"><span className={`tag tag-${q==='no_qos'?'noqos':q}`}>{MODE_LABEL[q]}</span></td>
                      <td className="px-2 py-1.5 font-bold" style={{ color: C[tc as keyof typeof C] }}>{TC_LABEL[tc]}</td>
                      <td className="px-2 py-1.5 text-muted">{fmt(d.sentThroughputMbps)}</td>
                      <td className="px-2 py-1.5 text-textdim font-semibold">{fmt(d.throughputMbps)}</td>
                      <td className="px-2 py-1.5 font-semibold" style={{ color: drC }}>{fmt(dr,1)}%</td>
                      <td className="px-2 py-1.5 text-muted">{fmt(d.cpuHostTotal)}%</td>
                    </tr>
                  );
                }))}
              </tbody>
            </table>
          </div>
        </SECTION>
      )}

      {/* ── CPU UTILIZATION ─────────────────────────────────────────────── */}
      {(tcp || udp) && cpuStackData.some(r => r.usr+r.sys+r.soft > 0) && (
        <SECTION icon={Cpu} title="CPU Utilization" tag="· SAR measurement · all-CPU aggregate">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <GroupedBars title="Total Active CPU % (usr + sys + soft)" data={cpuTotalData}
              bars={[{ key:'Total',label:'Active %',color:'#a78bfa' }]} unit="%" />
            <CpuStack data={cpuStackData} />
          </div>
          <div className="overflow-x-auto card">
            <table className="w-full border-collapse font-mono text-xs">
              <thead>
                <tr className="bg-surface border-b border-border">
                  {['Mode','Proto','usr %','sys %','softirq %','idle %','Active Total'].map(h => (
                    <th key={h} className="px-2 py-2 text-muted uppercase tracking-wider text-xs font-bold first:pl-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {cpuProtos.flatMap(p =>
                  MODE_KEYS.map(q => {
                    const cpu = ((p === 'tcp' ? tcp : udp)?.[q] as any)?.cpu;
                    if (!cpu) return null;
                    const tot = cpu.avgTotal ?? 0;
                    return (
                      <tr key={`${p}${q}`} className="border-b border-border hover:bg-surface">
                        <td className="pl-3 pr-2 py-1.5"><span className={`tag tag-${q==='no_qos'?'noqos':q}`}>{MODE_LABEL[q]}</span></td>
                        <td className="px-2 py-1.5 text-muted font-bold uppercase">{p}</td>
                        <td className="px-2 py-1.5" style={{ color: cpu.avgUsr>20?'#ef4444':'#c8daea' }}>{fmt(cpu.avgUsr,2)}</td>
                        <td className="px-2 py-1.5 text-textdim">{fmt(cpu.avgSys,2)}</td>
                        <td className="px-2 py-1.5 text-textdim">{fmt(cpu.avgSoft,2)}</td>
                        <td className="px-2 py-1.5 text-muted">{fmt(cpu.avgIdle,2)}</td>
                        <td className="px-2 py-1.5 font-semibold" style={{ color: tot>80?'#ef4444':tot>50?'#f59e0b':C.ebpf }}>{fmt(tot,2)}%</td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </SECTION>
      )}

      {/* ── QoS INTERNALS ───────────────────────────────────────────────── */}
      {(m.htb?.tcClasses || m.ebpf?.mapStats || (mbp?.udp as any)?.ebpf?.mapStats) && (
        <SECTION icon={AlertTriangle} title="QoS Internals — HTB & eBPF" tag="· tc qdisc counters · eBPF map dump">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            {m.htb?.tcClasses && (
              <div>
                <p className="font-mono text-xs text-muted uppercase tracking-wider mb-2">HTB TC Class Stats (TCP)</p>
                <div className="overflow-x-auto card">
                  <table className="w-full border-collapse font-mono text-xs">
                    <thead>
                      <tr className="bg-surface border-b border-border">
                        {['Class','Rate','Bytes','Packets','Dropped','Overlimits'].map(h => (
                          <th key={h} className="px-2 py-2 text-muted uppercase text-xs font-bold first:pl-3">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(m.htb.tcClasses).sort().map(([cid, s]) => (
                        <tr key={cid} className="border-b border-border hover:bg-surface">
                          <td className="pl-3 pr-2 py-1.5 text-htb font-bold">{cid}</td>
                          <td className="px-2 py-1.5 text-textdim">{s.rate}</td>
                          <td className="px-2 py-1.5 text-muted">{fmtK(s.bytesSent)}</td>
                          <td className="px-2 py-1.5 text-muted">{fmtK(s.packets)}</td>
                          <td className="px-2 py-1.5" style={{ color: s.dropped>0?'#ef4444':C.ebpf }}>{fmtK(s.dropped)}</td>
                          <td className="px-2 py-1.5" style={{ color: s.overlimits>100000?'#ef4444':s.overlimits>10000?'#f59e0b':'#4d6880' }}>{fmtK(s.overlimits)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
            {m.ebpf?.mapStats && (
              <div>
                <p className="font-mono text-xs text-muted uppercase tracking-wider mb-2">eBPF Map Stats (TCP)</p>
                <div className="overflow-x-auto card">
                  <table className="w-full border-collapse font-mono text-xs">
                    <thead>
                      <tr className="bg-surface border-b border-border">
                        {['Class','Packets','Bytes','Borrowed','ECN','Delayed'].map(h => (
                          <th key={h} className="px-2 py-2 text-muted uppercase text-xs font-bold first:pl-3">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(m.ebpf.mapStats).map(([cls, s]) => (
                        <tr key={cls} className="border-b border-border hover:bg-surface">
                          <td className="pl-3 pr-2 py-1.5 text-accent font-bold">{cls}</td>
                          <td className="px-2 py-1.5 text-muted">{fmtK(s.packets)}</td>
                          <td className="px-2 py-1.5 text-muted">{fmtK(s.bytes)}</td>
                          <td className="px-2 py-1.5" style={{ color: s.borrowed>0?'#f59e0b':'#4d6880' }}>{fmtK(s.borrowed)}</td>
                          <td className="px-2 py-1.5" style={{ color: s.ecnMarked>0?'#f59e0b':'#4d6880' }}>{fmtK(s.ecnMarked)}</td>
                          <td className="px-2 py-1.5" style={{ color: s.delayed>100000?'#ef4444':s.delayed>0?'#f59e0b':C.ebpf }}>{fmtK(s.delayed)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>

          {overlimData.length > 0 && (
            <GroupedBars title="HTB Overlimits — TCP vs UDP per class"
              data={overlimData}
              bars={[{ key:'TCP',label:'TCP',color:C.htb },{ key:'UDP',label:'UDP',color:C.noqos }]}
              height={180} />
          )}

          {/* eBPF UDP map */}
          {(() => {
            const udpMap = (mbp?.udp as any)?.ebpf?.mapStats as Record<string,any> | undefined;
            if (!udpMap || !Object.keys(udpMap).length) return null;
            return (
              <div className="mt-4">
                <p className="font-mono text-xs text-muted uppercase tracking-wider mb-2">eBPF Map Stats (UDP)</p>
                <div className="overflow-x-auto card">
                  <table className="w-full border-collapse font-mono text-xs">
                    <thead>
                      <tr className="bg-surface border-b border-border">
                        {['Class','Packets','Bytes','Borrowed','ECN','Delayed'].map(h => (
                          <th key={h} className="px-2 py-2 text-muted uppercase text-xs font-bold first:pl-3">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(udpMap).map(([cls, s]: [string, any]) => (
                        <tr key={cls} className="border-b border-border hover:bg-surface">
                          <td className="pl-3 pr-2 py-1.5 text-accent font-bold">{cls}</td>
                          <td className="px-2 py-1.5 text-muted">{fmtK(s.packets)}</td>
                          <td className="px-2 py-1.5 text-muted">{fmtK(s.bytes)}</td>
                          <td className="px-2 py-1.5" style={{ color: s.borrowed>0?'#f59e0b':'#4d6880' }}>{fmtK(s.borrowed)}</td>
                          <td className="px-2 py-1.5" style={{ color: s.ecnMarked>0?'#f59e0b':'#4d6880' }}>{fmtK(s.ecnMarked)}</td>
                          <td className="px-2 py-1.5" style={{ color: s.delayed>100000?'#ef4444':s.delayed>0?'#f59e0b':C.ebpf }}>{fmtK(s.delayed)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            );
          })()}
        </SECTION>
      )}

      {/* ── FULL COMPARISON TABLE ───────────────────────────────────────── */}
      {(tcp || udp) && (
        <SECTION icon={BarChart2} title="Full Comparison Table" tag="· all measurements · mode × protocol × class">
          <div className="overflow-x-auto card">
            <table className="w-full border-collapse font-mono text-xs">
              <thead>
                <tr className="bg-surface border-b border-border">
                  {['Mode','Proto','Class','Sent Mbps','Rcv Mbps','DR%','RTT avg','RTT min','RTT max','Retx','CPU Host'].map(h => (
                    <th key={h} className="px-2 py-2 text-muted uppercase tracking-wider text-xs font-bold whitespace-nowrap first:pl-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {cpuProtos.flatMap(p =>
                  MODE_KEYS.flatMap(q =>
                    TC_KEYS.map(tc => {
                      const d = ((p === 'tcp' ? tcp : udp)?.[q]?.[tc]) as any;
                      if (!d) return null;
                      const dr = d.deliveryRatio ?? (d.sentBytes > 0 ? d.rcvBytes/d.sentBytes*100 : null);
                      const drC = dr==null?'#4d6880':dr>=99?C.ebpf:dr>=85?'#c8daea':dr>=65?'#f59e0b':'#ef4444';
                      const rtt = d.avgRttUs ?? 0;
                      return (
                        <tr key={`${p}${q}${tc}`} className="border-b border-border hover:bg-surface">
                          <td className="pl-3 pr-2 py-1.5"><span className={`tag tag-${q==='no_qos'?'noqos':q}`}>{MODE_LABEL[q]}</span></td>
                          <td className="px-2 py-1.5 font-bold uppercase text-muted">{p}</td>
                          <td className="px-2 py-1.5 font-bold" style={{ color: C[tc as keyof typeof C] }}>{TC_LABEL[tc]}</td>
                          <td className="px-2 py-1.5 text-muted">{fmt(d.sentThroughputMbps)}</td>
                          <td className="px-2 py-1.5 text-textdim font-semibold">{fmt(d.throughputMbps)}</td>
                          <td className="px-2 py-1.5 font-semibold" style={{ color: drC }}>{dr!=null?fmt(dr,1)+'%':'—'}</td>
                          <td className="px-2 py-1.5" style={{ color: rtt<500?C.ebpf:rtt>3000?'#ef4444':'#c8daea' }}>{d.avgRttUs?fmtK(d.avgRttUs)+' µs':'—'}</td>
                          <td className="px-2 py-1.5 text-muted">{d.minRttUs?fmtK(d.minRttUs)+' µs':'—'}</td>
                          <td className="px-2 py-1.5 text-muted">{d.maxRttUs?fmtK(d.maxRttUs)+' µs':'—'}</td>
                          <td className="px-2 py-1.5" style={{ color: (d.retransmits||0)>0?'#ef4444':'#4d6880' }}>{fmtK(d.retransmits)}</td>
                          <td className="px-2 py-1.5 text-muted">{fmt(d.cpuHostTotal)}%</td>
                        </tr>
                      );
                    })
                  )
                )}
              </tbody>
            </table>
          </div>
        </SECTION>
      )}

      {/* ── RESEARCH CONCLUSIONS ────────────────────────────────────────── */}
      {tcp && (
        <SECTION icon={TrendingUp} title="Research Conclusions">
          {[
            {
              color: C.ebpf,
              title: '1 · eBPF XDP achieves superior latency for EF traffic',
              text: (() => {
                const e = kpiEbpfRtt, n = kpiNoqosRtt, h = (tcp.htb?.ef as any)?.avgRttUs, bh = (tcp.htb?.be as any)?.avgRttUs;
                return [
                  e && n ? `eBPF EF RTT ${e.toFixed(0)} µs — ${(n/e).toFixed(1)}× lower than No QoS (${n.toFixed(0)} µs).` : null,
                  h ? `HTB qdisc queuing: EF ${h.toFixed(0)} µs → BE ${bh?.toFixed(0)||'—'} µs (increasing by class depth).` : null,
                  'XDP classification removes inter-class queuing delay — all classes see sub-ms RTT regardless of bandwidth allocation.',
                ].filter(Boolean).join(' ');
              })(),
            },
            {
              color: C.ebpf,
              title: '2 · eBPF enforces strict priority at the cost of link utilisation',
              text: (() => {
                const tot = ((tcp.ebpf?.ef as any)?.throughputMbps||0)+((tcp.ebpf?.af as any)?.throughputMbps||0)+((tcp.ebpf?.be as any)?.throughputMbps||0);
                const totH = ((tcp.htb?.ef as any)?.throughputMbps||0)+((tcp.htb?.af as any)?.throughputMbps||0)+((tcp.htb?.be as any)?.throughputMbps||0);
                return tot>0 ? `eBPF total TCP ${tot.toFixed(0)} Mbps (${((tot/1000)*100).toFixed(0)}% of 1 Gbps) vs HTB ${totH.toFixed(0)} Mbps (${((totH/1000)*100).toFixed(0)}%). EF receives ${((tcp.ebpf?.ef as any)?.throughputMbps||0).toFixed(0)} Mbps while AF/BE are throttled with significant retransmits. Consider increasing AF/BE rate limits if the unused capacity is wasteful.` : '';
              })(),
            },
            {
              color: C.htb,
              title: '3 · HTB provides clean proportional allocation with zero loss',
              text: `EF:AF:BE = ${((tcp.htb?.ef as any)?.throughputMbps||0).toFixed(0)}:${((tcp.htb?.af as any)?.throughputMbps||0).toFixed(0)}:${((tcp.htb?.be as any)?.throughputMbps||0).toFixed(0)} Mbps. Zero retransmits, zero drops — enforcement via token-bucket overlimits only. Correct choice when near-line-rate utilization and predictable proportional allocation are required.`,
            },
            {
              color: '#f59e0b',
              title: '4 · eBPF CPU overhead requires production evaluation',
              text: kpiCpuEbpf && kpiCpuHtb
                ? `eBPF TCP ${kpiCpuEbpf.toFixed(1)}% active CPU (${((tcp.ebpf?.cpu as any)?.avgUsr||0).toFixed(1)}% usr) vs HTB ${kpiCpuHtb.toFixed(1)}%. High user-space CPU likely reflects a user-space token-bucket controller. Profile before production deployment — a kernel-side rate calculation could reduce overhead substantially.`
                : '',
            },
            udp ? {
              color: '#ef4444',
              title: '5 · eBPF UDP priority inversion requires investigation',
              text: (() => {
                const efDr = (udp.ebpf?.ef as any)?.deliveryRatio, beDr = (udp.ebpf?.be as any)?.deliveryRatio;
                return `eBPF UDP EF delivery ${efDr?.toFixed(1)||'—'}% < BE ${beDr?.toFixed(1)||'—'}%. eBPF map: 0 delayed events for EF but 800K+ for AF/BE. EF uses drop-based enforcement (no delay queue) causing high loss above the rate limit. Verify the eBPF program's EF UDP code path.`;
              })(),
            } : null,
            {
              color: C.noqos,
              title: '6 · Recommended next experiments',
              text: 'Concurrent multi-class TCP/UDP tests to observe real QoS interaction; eBPF UDP with corrected EF rate config; CPU profiling to separate XDP hook time from user-space control plane; ECN behavior analysis for TCP AF/BE under heavy load.',
            },
          ].filter(Boolean).map((c: any, i) => (
            <div key={i} className="card border-l-2 p-4 mb-3" style={{ borderLeftColor: c.color }}>
              <p className="font-mono text-xs font-bold uppercase tracking-wider mb-1" style={{ color: c.color }}>{c.title}</p>
              <p className="font-mono text-xs text-muted leading-relaxed">{c.text}</p>
            </div>
          ))}
        </SECTION>
      )}

      {/* ── TIME SERIES ─────────────────────────────────────────────────── */}
      {Object.keys(ds.timeSeries).length > 0 && (
        <SECTION icon={Activity} title="Time Series — Throughput per Second">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {TC_KEYS.map(tc => {
              const series = MODE_KEYS.map(q => ({
                key: `${q}_${tc}`, color: C[q === 'no_qos' ? 'noqos' : q as keyof typeof C],
                data: ds.timeSeries[`${q}_${tc}`] ?? [],
              })).filter(s => s.data.length);
              if (!series.length) return null;
              const allPts = series.flatMap(s => s.data);
              const chartData = [...new Set(allPts.map(p => p.t))].sort((a,b)=>a-b).map(t => {
                const row: Record<string, any> = { t };
                series.forEach(s => { const p = s.data.find(d => d.t === t); if (p) row[s.key] = +(p.bitsPerSecond/1e6).toFixed(1); });
                return row;
              });
              return (
                <div key={tc} className="card p-3">
                  <p className="font-mono text-xs font-bold mb-2" style={{ color: C[tc as keyof typeof C] }}>
                    {TC_LABEL[tc]} — {TC_FULL[tc]}
                  </p>
                  <ResponsiveContainer width="100%" height={120}>
                    <LineChart data={chartData} margin={{ top: 2, right: 4, left: 0, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1a2b40" />
                      <XAxis dataKey="t" tick={{ fontSize: 9, fill: '#4d6880' }} tickFormatter={v=>`${v}s`} />
                      <YAxis tick={{ fontSize: 9, fill: '#4d6880' }} width={38} tickFormatter={v=>v.toFixed(0)} />
                      <Tooltip contentStyle={{ background:'#0c1420',border:'1px solid #1a2b40',borderRadius:4,fontSize:10 }}
                        formatter={(v:number)=>[`${v.toFixed(1)} Mbps`,'Mbps']} labelFormatter={v=>`t=${v}s`} />
                      {series.map(s => (
                        <Line key={s.key} type="monotone" dataKey={s.key} stroke={s.color} dot={false} strokeWidth={1.5} name={MODE_LABEL[s.key.replace(`_${tc}`,'')]} />
                      ))}
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              );
            })}
          </div>
        </SECTION>
      )}

      {/* ── INDIVIDUAL EXPERIMENTS ──────────────────────────────────────── */}
      {exps.length > 0 && (
        <SECTION icon={FlaskConical} title={`Individual Experiments — ${exps.length} files`}>
          <div className="card overflow-x-auto">
            <table className="w-full text-left border-collapse font-mono text-xs">
              <thead>
                <tr className="bg-surface border-b border-border">
                  {['#','QoS','Proto','Class','Type','Source','Mbps','RTT avg','Retx',''].map(h => (
                    <th key={h} className="px-2 py-2 text-muted uppercase tracking-wider text-xs font-bold whitespace-nowrap first:pl-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {exps.map(exp => {
                  const qC: Record<string,string> = { no_qos:'text-noqos', htb:'text-htb', ebpf:'text-accent' };
                  return (
                    <tr key={exp.id} className="border-b border-border hover:bg-surface">
                      <td className="pl-3 pr-2 py-1.5 text-muted">{exp.id}</td>
                      <td className={`px-2 py-1.5 font-semibold ${qC[exp.qos_type]||'text-textdim'}`}>
                        {exp.qos_type==='no_qos'?'No QoS':exp.qos_type.toUpperCase()}
                      </td>
                      <td className="px-2 py-1.5 text-muted uppercase">{exp.protocol??'—'}</td>
                      <td className="px-2 py-1.5 text-textdim">{exp.traffic_class?.toUpperCase()??'—'}</td>
                      <td className="px-2 py-1.5 text-muted">{exp.experiment_type}</td>
                      <td className="px-2 py-1.5 text-muted max-w-[130px] truncate" title={exp.source_filename??''}>{exp.source_filename??'—'}</td>
                      <td className="px-2 py-1.5 text-textdim">{exp.throughput_mbps!=null?`${exp.throughput_mbps.toFixed(1)}`:'—'}</td>
                      <td className="px-2 py-1.5 text-textdim">{exp.avg_rtt_us!=null?`${exp.avg_rtt_us.toFixed(0)} µs`:'—'}</td>
                      <td className="px-2 py-1.5 text-muted">{exp.retransmits!=null?exp.retransmits.toLocaleString():'—'}</td>
                      <td className="px-2 py-1.5">
                        <div className="flex gap-1">
                          <Link href={`/dataset/${id}/experiment/${exp.id}`}
                            className="p-1.5 rounded hover:bg-surface2 text-muted hover:text-textdim"><ExternalLink size={12}/></Link>
                          <button onClick={() => doExpExport(exp)} disabled={expExporting===exp.id}
                            className="p-1.5 rounded hover:bg-surface2 text-muted hover:text-textdim disabled:opacity-40">
                            {expExporting===exp.id?<Loader2 size={12} className="animate-spin"/>:<FileDown size={12}/>}
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
