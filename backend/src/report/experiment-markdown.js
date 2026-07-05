'use strict';

const QOS_LABELS = { no_qos: 'No QoS', htb: 'HTB', ebpf: 'eBPF' };
const TC_LABELS  = { ef: 'EF — Expedited Forwarding', af: 'AF — Assured Forwarding', be: 'BE — Best Effort' };
const EXP_LABELS = { iperf: 'iperf3 TCP Throughput Test', cpu: 'CPU Utilization (sar)', htb_tc: 'HTB TC Class Statistics', ebpf_map: 'eBPF Map Statistics' };

function fmt(n, d = 2) { return (n == null || isNaN(n)) ? '—' : Number(n).toFixed(d); }
function fmtK(n) { return (n == null || isNaN(n)) ? '—' : Number(n).toLocaleString('en-US'); }
function row(cells) { return '| ' + cells.join(' | ') + ' |'; }
function sep(n) { return '|' + Array(n).fill('---').join('|') + '|'; }

function buildExpMarkdown(exp) {
  const now  = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  const tc   = exp.traffic_class;
  const q    = exp.qos_type;
  const type = exp.experiment_type;

  const lines = [];

  // Front matter
  lines.push('---');
  lines.push(`title: "Experiment #${exp.id} — ${QOS_LABELS[q] || q}${tc ? ' / ' + tc.toUpperCase() : ''} (${EXP_LABELS[type] || type})"`);
  lines.push(`generated: "${now}"`);
  lines.push(`experiment_id: ${exp.id}`);
  lines.push(`dataset: "${exp.dataset_name}"`);
  lines.push(`qos_type: ${q}`);
  if (tc) lines.push(`traffic_class: ${tc}`);
  lines.push(`experiment_type: ${type}`);
  if (exp.source_filename) lines.push(`source_file: "${exp.source_filename}"`);
  lines.push('---');
  lines.push('');

  // Title
  const title = `${QOS_LABELS[q] || q}${tc ? ' / ' + tc.toUpperCase() : ''} — ${EXP_LABELS[type] || type}`;
  lines.push(`# Experiment Report: ${title}`);
  lines.push('');
  lines.push(`| Field | Value |`);
  lines.push(`|---|---|`);
  lines.push(`| Experiment ID | ${exp.id} |`);
  lines.push(`| Dataset | ${exp.dataset_name} |`);
  lines.push(`| QoS Method | ${QOS_LABELS[q] || q} |`);
  if (tc) lines.push(`| Traffic Class | ${TC_LABELS[tc] || tc.toUpperCase()} |`);
  lines.push(`| Experiment Type | ${EXP_LABELS[type] || type} |`);
  if (exp.source_filename) lines.push(`| Source File | \`${exp.source_filename}\` |`);
  lines.push(`| Generated | ${now} |`);
  lines.push('');

  // ── iperf ────────────────────────────────────────────────────────────────
  if (type === 'iperf' && exp.summary) {
    const s = exp.summary;

    lines.push('## Summary Statistics');
    lines.push('');
    lines.push(row(['Metric', 'Value']));
    lines.push(sep(2));
    lines.push(row(['Throughput', `${fmt(s.throughput_mbps)} Mbps`]));
    lines.push(row(['Average RTT', `${fmt(s.avg_rtt_us, 0)} µs`]));
    lines.push(row(['Minimum RTT', `${fmt(s.min_rtt_us, 0)} µs`]));
    lines.push(row(['Maximum RTT', `${fmt(s.max_rtt_us, 0)} µs`]));
    lines.push(row(['RTT Std Dev', `${fmt(s.rtt_std_us, 0)} µs`]));
    lines.push(row(['Retransmits', fmtK(s.retransmits)]));
    lines.push(row(['Duration', `${fmt(s.duration_s, 0)} s`]));
    lines.push('');

    lines.push('### CPU Utilization (iperf3 measurement)');
    lines.push('');
    lines.push(row(['Side', 'Total %', 'User %', 'System %']));
    lines.push(sep(4));
    lines.push(row(['Host (sender)', fmt(s.cpu_host_total), fmt(s.cpu_host_user), fmt(s.cpu_host_system)]));
    lines.push(row(['Remote (receiver)', fmt(s.cpu_remote_total), '—', '—']));
    lines.push('');

    // RTT analysis
    if (exp.intervals?.length) {
      const rtts = exp.intervals.map(i => i.rtt_us).filter(Boolean);
      const bpss = exp.intervals.map(i => i.bits_per_second / 1e6).filter(Boolean);
      if (rtts.length) {
        lines.push('### RTT Distribution');
        lines.push('');
        const buckets = [0, 500, 1000, 2000, 5000, 10000, Infinity];
        const labels  = ['< 500 µs', '500–1000 µs', '1–2 ms', '2–5 ms', '5–10 ms', '> 10 ms'];
        lines.push(row(['RTT Range', 'Interval Count', '% of Test']));
        lines.push(sep(3));
        for (let i = 0; i < labels.length; i++) {
          const cnt = rtts.filter(r => r >= buckets[i] && r < buckets[i + 1]).length;
          if (cnt > 0) lines.push(row([labels[i], cnt, `${(cnt / rtts.length * 100).toFixed(1)}%`]));
        }
        lines.push('');

        lines.push('### Throughput Distribution');
        lines.push('');
        const sorted = [...bpss].sort((a, b) => a - b);
        const p = pct => sorted[Math.floor(sorted.length * pct / 100)] ?? 0;
        lines.push(row(['Percentile', 'Mbps']));
        lines.push(sep(2));
        [10, 25, 50, 75, 90, 95, 99].forEach(pc => lines.push(row([`P${pc}`, fmt(p(pc))])));
        lines.push('');
      }
    }

    // Full interval table
    if (exp.intervals?.length) {
      lines.push('## Per-Second Intervals');
      lines.push('');
      lines.push(`_${exp.intervals.length} intervals recorded during ${fmt(s.duration_s, 0)}-second test_`);
      lines.push('');
      lines.push(row(['#', 'Start (s)', 'End (s)', 'Mbps', 'RTT (µs)', 'Retransmits']));
      lines.push(sep(6));
      for (const iv of exp.intervals) {
        lines.push(row([
          iv.id,
          fmt(iv.interval_start, 1),
          fmt(iv.interval_end, 1),
          fmt(iv.bits_per_second / 1e6),
          fmt(iv.rtt_us, 0),
          iv.retransmits ?? 0,
        ]));
      }
      lines.push('');
    }
  }

  // ── cpu ──────────────────────────────────────────────────────────────────
  if (type === 'cpu' && exp.cpuSnapshots?.length) {
    const snaps = exp.cpuSnapshots;

    // aggregate
    const avg = key => snaps.reduce((s, r) => s + (r[key] || 0), 0) / snaps.length;
    lines.push('## CPU Utilization Summary');
    lines.push('');
    lines.push(row(['Metric', 'Average', 'Min', 'Max']));
    lines.push(sep(4));
    const keys = [['usr_pct', 'User %'], ['sys_pct', 'System %'], ['soft_pct', 'Softirq %'], ['idle_pct', 'Idle %']];
    for (const [k, label] of keys) {
      const vals = snaps.map(s => s[k]).filter(v => v != null);
      lines.push(row([label, fmt(avg(k)), fmt(Math.min(...vals)), fmt(Math.max(...vals))]));
    }
    const totals = snaps.map(s => (s.usr_pct || 0) + (s.sys_pct || 0) + (s.soft_pct || 0));
    lines.push(row(['Total Active %',
      fmt(totals.reduce((a, b) => a + b, 0) / totals.length),
      fmt(Math.min(...totals)),
      fmt(Math.max(...totals)),
    ]));
    lines.push('');

    lines.push('## CPU Snapshot Timeline');
    lines.push('');
    lines.push(`_${snaps.length} snapshots from \`sar\` measurement_`);
    lines.push('');
    lines.push(row(['Time', 'CPU', 'User %', 'System %', 'Softirq %', 'Idle %', 'Active %']));
    lines.push(sep(7));
    for (const s of snaps) {
      const total = (s.usr_pct || 0) + (s.sys_pct || 0) + (s.soft_pct || 0);
      lines.push(row([s.snapshot_time ?? '—', s.cpu_core ?? 'all', fmt(s.usr_pct), fmt(s.sys_pct), fmt(s.soft_pct), fmt(s.idle_pct), fmt(total)]));
    }
    lines.push('');
  }

  // ── htb_tc ───────────────────────────────────────────────────────────────
  if (type === 'htb_tc' && exp.htbClasses?.length) {
    lines.push('## HTB TC Class Statistics');
    lines.push('');
    lines.push('Traffic classes as reported by `tc -s class show dev <iface>`.');
    lines.push('');
    lines.push(row(['Class ID', 'Rate', 'Bytes Sent', 'Packets', 'Dropped', 'Overlimits', 'Calc. Mbps']));
    lines.push(sep(7));
    for (const c of exp.htbClasses) {
      const mbps = (c.bytes_sent * 8) / 30 / 1e6;
      lines.push(row([c.class_id, c.rate, fmtK(c.bytes_sent), fmtK(c.packets), fmtK(c.dropped), fmtK(c.overlimits), fmt(mbps)]));
    }
    lines.push('');
    const totalDropped = exp.htbClasses.reduce((s, c) => s + (c.dropped || 0), 0);
    if (totalDropped > 0) lines.push(`> **Warning**: ${fmtK(totalDropped)} packets dropped across all classes — indicates congestion or misconfigured rates.`);
    else lines.push(`> All classes: zero dropped packets.`);
    lines.push('');
  }

  // ── ebpf_map ─────────────────────────────────────────────────────────────
  if (type === 'ebpf_map' && exp.ebpfClasses?.length) {
    lines.push('## eBPF Map Statistics');
    lines.push('');
    lines.push('Per-class counters from XDP eBPF map dump.');
    lines.push('');
    lines.push(row(['Class', 'Key', 'Packets', 'Bytes', 'Calc. Mbps', 'Borrowed', 'ECN Marked', 'Delayed']));
    lines.push(sep(8));
    for (const c of exp.ebpfClasses) {
      const mbps = (c.bytes * 8) / 30 / 1e6;
      lines.push(row([c.class_name, c.class_key, fmtK(c.packets), fmtK(c.bytes), fmt(mbps), fmtK(c.borrowed), fmtK(c.ecn_marked), fmtK(c.delayed)]));
    }
    lines.push('');
    const totalEcn = exp.ebpfClasses.reduce((s, c) => s + (c.ecn_marked || 0), 0);
    const totalDly = exp.ebpfClasses.reduce((s, c) => s + (c.delayed    || 0), 0);
    const totalBor = exp.ebpfClasses.reduce((s, c) => s + (c.borrowed   || 0), 0);
    lines.push('**Totals:**');
    lines.push('');
    lines.push(row(['Metric', 'Total', 'Interpretation']));
    lines.push(sep(3));
    lines.push(row(['ECN Marked', fmtK(totalEcn), totalEcn > 0 ? 'Active congestion signalling observed' : 'No congestion marks']));
    lines.push(row(['Delayed',    fmtK(totalDly), totalDly > 0 ? 'Scheduler held packets — shaping active' : 'No delays recorded']));
    lines.push(row(['Borrowed',   fmtK(totalBor), totalBor > 0 ? 'Bandwidth borrowing between classes occurred' : 'No borrowing']));
    lines.push('');
  }

  // Footer
  lines.push('---');
  lines.push('');
  lines.push(`*Generated by eBPF QoS Research Platform · Experiment #${exp.id} · ${now}*`);
  lines.push('');

  return lines.join('\n');
}

// percentile helper (closed over — not exported)
function pct(arr, p) {
  const sorted = [...arr].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length * p / 100)] ?? 0;
}

module.exports = { buildExpMarkdown };
