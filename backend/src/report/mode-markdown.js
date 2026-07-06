'use strict';

const QOS_LABELS = { no_qos: 'No QoS (Baseline)', htb: 'HTB (Hierarchical Token Bucket)', ebpf: 'eBPF (XDP-based Classification)' };
const TC_LABELS  = { ef: 'EF — Expedited Forwarding', af: 'AF — Assured Forwarding', be: 'BE — Best Effort' };
const TC_TARGET  = { ef: 500, af: 300, be: 100 }; // Mbps targets (adjust per experiment config)

function fmt(n, d = 2) { return (n == null || isNaN(n)) ? '—' : Number(n).toFixed(d); }
function fmtK(n) { return (n == null || isNaN(n)) ? '—' : Number(n).toLocaleString('en-US'); }
function row(cells) { return '| ' + cells.join(' | ') + ' |'; }
function sep(n) { return '|' + Array(n).fill('---').join('|') + '|'; }

function buildModeMarkdown(mode) {
  const { qos_type: q, dataset_name, iperf = {}, cpu = {}, htbClasses = [], ebpfClasses = [], timeSeries = {} } = mode;
  const now  = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  const label = QOS_LABELS[q] || q;
  const TC    = ['ef', 'af', 'be'];

  const lines = [];

  // ── Front matter ──────────────────────────────────────────────────────────
  lines.push('---');
  lines.push(`title: "${label} — Mode Analysis Report"`);
  lines.push(`generated: "${now}"`);
  lines.push(`dataset: "${dataset_name}"`);
  lines.push(`qos_type: ${q}`);
  lines.push('---');
  lines.push('');

  lines.push(`# ${label}`);
  lines.push(`## Mode Analysis — ${dataset_name}`);
  lines.push('');
  lines.push(`> Generated: ${now}`);
  lines.push('');

  // ── 1. Mode Overview ──────────────────────────────────────────────────────
  lines.push('## 1. Mode Overview');
  lines.push('');
  const descriptions = {
    no_qos: 'No traffic classification or shaping. All traffic classes share bandwidth equally. Serves as the performance baseline.',
    htb:    'Hierarchical Token Bucket: kernel-level qdisc with rate limits and burst settings per class. Configured via `tc` tool.',
    ebpf:   'XDP-based eBPF program classifies packets by DSCP/TOS field at kernel ingress. Uses custom token-bucket scheduler in eBPF maps.',
  };
  lines.push(descriptions[q] || '');
  lines.push('');

  // ── 2. Traffic Class Results ──────────────────────────────────────────────
  lines.push('## 2. Traffic Class Performance');
  lines.push('');
  lines.push('> **Sent** = client application rate (before shaping). **Received** = server goodput (after shaping). **Delivery Ratio** = Rcv/Sent ×100%.');
  lines.push('');
  lines.push(row(['Traffic Class', 'Sent (Mbps)', 'Received (Mbps)', 'Delivery Ratio', 'Avg RTT (µs)', 'Min RTT', 'Max RTT', 'RTT σ', 'Retransmits']));
  lines.push(sep(9));
  for (const tc of TC) {
    const s = iperf[tc]?.summary;
    if (!s) { lines.push(row([TC_LABELS[tc], '—', '—', '—', '—', '—', '—', '—', '—'])); continue; }
    const drLabel = s.delivery_ratio != null ? `${fmt(s.delivery_ratio, 1)}%` : '—';
    lines.push(row([
      TC_LABELS[tc],
      fmt(s.sent_throughput_mbps),
      fmt(s.throughput_mbps),
      drLabel,
      fmt(s.avg_rtt_us, 0),
      fmt(s.min_rtt_us, 0),
      fmt(s.max_rtt_us, 0),
      fmt(s.rtt_std_us, 0),
      fmtK(s.retransmits),
    ]));
  }
  lines.push('');

  // ── 3. Throughput Analysis ────────────────────────────────────────────────
  lines.push('## 3. Throughput Analysis');
  lines.push('');
  lines.push('Per-second interval statistics are sender-side (iperf3 client measurements).');
  lines.push('');
  lines.push(row(['Traffic Class', 'Sent (Mbps)', 'Received (Mbps)', 'Delivery Ratio', 'P10', 'P50 (median)', 'P90', 'Stability (σ/avg)']));
  lines.push(sep(8));
  for (const tc of TC) {
    const intervals = iperf[tc]?.intervals || [];
    const s = iperf[tc]?.summary;
    if (!intervals.length) { lines.push(row([TC_LABELS[tc], '—', '—', '—', '—', '—', '—', '—'])); continue; }
    const mbps   = intervals.map(iv => iv.bits_per_second / 1e6).filter(Boolean).sort((a, b) => a - b);
    const avg    = mbps.reduce((a, b) => a + b, 0) / mbps.length;
    const stdv   = Math.sqrt(mbps.reduce((sv, v) => sv + (v - avg) ** 2, 0) / mbps.length);
    const p      = pct => mbps[Math.floor(mbps.length * pct / 100)] ?? 0;
    const drLabel = s?.delivery_ratio != null ? `${fmt(s.delivery_ratio, 1)}%` : '—';
    lines.push(row([
      TC_LABELS[tc],
      fmt(s?.sent_throughput_mbps),
      fmt(s?.throughput_mbps),
      drLabel,
      fmt(p(10)),
      fmt(p(50)),
      fmt(p(90)),
      avg > 0 ? `${(stdv / avg * 100).toFixed(1)}%` : '—',
    ]));
  }
  lines.push('');
  lines.push('_Stability = coefficient of variation (lower = more stable throughput)_');
  lines.push('');

  // ── 4. Latency Analysis ───────────────────────────────────────────────────
  lines.push('## 4. Latency Analysis');
  lines.push('');

  for (const tc of TC) {
    const intervals = iperf[tc]?.intervals || [];
    const rtts = intervals.map(iv => iv.rtt_us).filter(Boolean).sort((a, b) => a - b);
    if (!rtts.length) continue;
    lines.push(`### ${TC_LABELS[tc]}`);
    lines.push('');
    const p = pct => rtts[Math.floor(rtts.length * pct / 100)] ?? 0;
    lines.push(row(['Percentile', 'RTT (µs)']));
    lines.push(sep(2));
    [10, 25, 50, 75, 90, 95, 99].forEach(pc => lines.push(row([`P${pc}`, fmt(p(pc), 0)])));
    lines.push('');

    // RTT bucket distribution
    const buckets = [0, 500, 1000, 2000, 5000, 10000, Infinity];
    const bLabels = ['< 500 µs', '500–1000 µs', '1–2 ms', '2–5 ms', '5–10 ms', '> 10 ms'];
    lines.push(row(['RTT Range', 'Count', '% of Intervals']));
    lines.push(sep(3));
    for (let i = 0; i < bLabels.length; i++) {
      const cnt = rtts.filter(r => r >= buckets[i] && r < buckets[i + 1]).length;
      if (cnt > 0) lines.push(row([bLabels[i], cnt, `${(cnt / rtts.length * 100).toFixed(1)}%`]));
    }
    lines.push('');
  }

  // ── 5. CPU Utilization ────────────────────────────────────────────────────
  lines.push('## 5. CPU Utilization');
  lines.push('');
  if (cpu.snapshots?.length) {
    const snaps = cpu.snapshots;
    const avg   = key => snaps.reduce((s, r) => s + (r[key] || 0), 0) / snaps.length;
    const totals = snaps.map(s => (s.usr_pct || 0) + (s.sys_pct || 0) + (s.soft_pct || 0));
    lines.push(row(['Metric', 'Average', 'Min', 'Max']));
    lines.push(sep(4));
    const fields = [['usr_pct', 'User %'], ['sys_pct', 'System %'], ['soft_pct', 'Softirq %'], ['idle_pct', 'Idle %']];
    for (const [k, label] of fields) {
      const vals = snaps.map(s => s[k]).filter(v => v != null);
      lines.push(row([label, fmt(avg(k)), fmt(Math.min(...vals)), fmt(Math.max(...vals))]));
    }
    lines.push(row([
      'Total Active %',
      fmt(totals.reduce((a, b) => a + b, 0) / totals.length),
      fmt(Math.min(...totals)),
      fmt(Math.max(...totals)),
    ]));
    lines.push('');
    lines.push(`_Based on ${snaps.length} \`sar\` snapshots_`);
    lines.push('');

    // iperf-reported CPU per class
    const hasIperfCpu = TC.some(tc => iperf[tc]?.summary?.cpu_host_total != null);
    if (hasIperfCpu) {
      lines.push('### iperf3 CPU (per traffic class, host-side)');
      lines.push('');
      lines.push(row(['Traffic Class', 'Host Total %', 'Host User %', 'Host System %', 'Remote Total %']));
      lines.push(sep(5));
      for (const tc of TC) {
        const s = iperf[tc]?.summary;
        if (!s || s.cpu_host_total == null) continue;
        lines.push(row([TC_LABELS[tc], fmt(s.cpu_host_total), fmt(s.cpu_host_user), fmt(s.cpu_host_system), fmt(s.cpu_remote_total)]));
      }
      lines.push('');
    }
  } else {
    lines.push('_No CPU sar data available for this mode._');
    lines.push('');
  }

  // ── 6. Mode-specific ──────────────────────────────────────────────────────
  if (q === 'htb' && htbClasses.length) {
    lines.push('## 6. HTB TC Class Configuration & Stats');
    lines.push('');
    lines.push('Traffic class rules configured via `tc htb` qdisc:');
    lines.push('');
    lines.push(row(['Class ID', 'Rate', 'Bytes Sent', 'Packets', 'Dropped', 'Overlimits', 'Calc. Mbps']));
    lines.push(sep(7));
    for (const c of htbClasses) {
      const mbps = (c.bytes_sent * 8) / 30 / 1e6;
      lines.push(row([c.class_id, c.rate, fmtK(c.bytes_sent), fmtK(c.packets), fmtK(c.dropped), fmtK(c.overlimits), fmt(mbps)]));
    }
    lines.push('');
    const totalDropped = htbClasses.reduce((s, c) => s + (c.dropped || 0), 0);
    if (totalDropped > 0) lines.push(`> **${fmtK(totalDropped)} packets dropped** — classes hitting rate limit.`);
    else lines.push('> Zero dropped packets — all classes within rate limits.');
    lines.push('');
  }

  if (q === 'ebpf' && ebpfClasses.length) {
    lines.push('## 6. eBPF Map Statistics (XDP Counters)');
    lines.push('');
    lines.push(row(['Class', 'Packets', 'Bytes', 'Throughput (Mbps)', 'Borrowed', 'ECN Marked', 'Delayed']));
    lines.push(sep(7));
    for (const c of ebpfClasses) {
      const mbps = (c.bytes * 8) / 30 / 1e6;
      lines.push(row([c.class_name, fmtK(c.packets), fmtK(c.bytes), fmt(mbps), fmtK(c.borrowed), fmtK(c.ecn_marked), fmtK(c.delayed)]));
    }
    lines.push('');
    const totalEcn = ebpfClasses.reduce((s, c) => s + (Number(c.ecn_marked) || 0), 0);
    const totalDly = ebpfClasses.reduce((s, c) => s + (Number(c.delayed)    || 0), 0);
    const totalBor = ebpfClasses.reduce((s, c) => s + (Number(c.borrowed)   || 0), 0);
    lines.push(row(['Counter', 'Total', 'Meaning']));
    lines.push(sep(3));
    lines.push(row(['ECN Marked', fmtK(totalEcn), totalEcn > 0 ? 'Active congestion signalling' : 'No marks']));
    lines.push(row(['Delayed',    fmtK(totalDly), totalDly > 0 ? 'Active packet shaping'        : 'No delays']));
    lines.push(row(['Borrowed',   fmtK(totalBor), totalBor > 0 ? 'Cross-class bandwidth sharing' : 'No borrowing']));
    lines.push('');
  }

  // ── 7. Time Series Summary ────────────────────────────────────────────────
  const tsKeys = Object.keys(timeSeries).filter(k => k.startsWith(q + '_'));
  if (tsKeys.length) {
    lines.push('## 7. Time Series Summary (per-second intervals)');
    lines.push('');
    lines.push(row(['Traffic Class', 'Samples', 'Avg Mbps', 'Min Mbps', 'Max Mbps', 'Avg RTT (µs)']));
    lines.push(sep(6));
    for (const key of tsKeys.sort()) {
      const pts  = timeSeries[key];
      if (!pts?.length) continue;
      const bps  = pts.map(p => p.bitsPerSecond / 1e6).filter(Boolean);
      const rtts = pts.map(p => p.rttUs).filter(Boolean);
      const avg  = arr => arr.length ? (arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(2) : '—';
      const tc   = key.replace(q + '_', '').toUpperCase();
      lines.push(row([tc, pts.length, avg(bps), bps.length ? Math.min(...bps).toFixed(2) : '—', bps.length ? Math.max(...bps).toFixed(2) : '—', avg(rtts)]));
    }
    lines.push('');
  }

  // ── 8. Analysis & Conclusions ─────────────────────────────────────────────
  lines.push('## 8. Analysis & Conclusions');
  lines.push('');

  const conclusions = [];

  if (q === 'no_qos') {
    const rtts = TC.map(tc => iperf[tc]?.summary?.avg_rtt_us).filter(Boolean);
    if (rtts.length > 1) {
      const spread = (Math.max(...rtts) - Math.min(...rtts)).toFixed(0);
      conclusions.push(`**RTT uniformity**: Without QoS, all traffic classes share the same queue. RTT spread across classes: ${spread} µs (expected near-zero with no differentiation).`);
    }
    // Delivery ratio baseline — expect ~100% with no shaping
    const drs = TC.map(tc => iperf[tc]?.summary?.delivery_ratio).filter(v => v != null);
    if (drs.length) {
      const avgDr = (drs.reduce((a, b) => a + b, 0) / drs.length).toFixed(1);
      conclusions.push(`**Delivery baseline**: Average delivery ratio ${avgDr}% — this is the reference packet delivery without any shaping overhead.`);
    }
    conclusions.push(`**Baseline reference**: No QoS values serve as the control group. Any improvement in RTT or fairness in other modes should be measured against these numbers.`);
    const cpuTotal = cpu.snapshots?.length
      ? (cpu.snapshots.reduce((s, r) => s + (r.usr_pct || 0) + (r.sys_pct || 0) + (r.soft_pct || 0), 0) / cpu.snapshots.length).toFixed(2)
      : null;
    if (cpuTotal) conclusions.push(`**Baseline CPU**: ${cpuTotal}% active CPU with no QoS overhead — minimum forwarding cost.`);
  }

  if (q === 'htb') {
    const efRtt = iperf.ef?.summary?.avg_rtt_us;
    const beRtt = iperf.be?.summary?.avg_rtt_us;
    if (efRtt && beRtt)
      conclusions.push(`**Priority differentiation**: EF RTT (${fmt(efRtt, 0)} µs) vs BE RTT (${fmt(beRtt, 0)} µs) — spread of ${(beRtt - efRtt).toFixed(0)} µs shows HTB priority queue working.`);
    const dropped = htbClasses.reduce((s, c) => s + (c.dropped || 0), 0);
    if (dropped > 0)
      conclusions.push(`**Rate enforcement (drop-based)**: ${fmtK(dropped)} packets dropped — classes hitting configured rate limits. Delivery ratio degraded accordingly.`);
    else
      conclusions.push(`**Rate enforcement**: Zero drops — all traffic stayed within configured HTB limits during the test window.`);
    // HTB delivery ratio per class
    TC.forEach(tc => {
      const s = iperf[tc]?.summary;
      if (s?.delivery_ratio != null && s.delivery_ratio < 99)
        conclusions.push(`**${TC_LABELS[tc]} delivery**: ${fmt(s.delivery_ratio, 1)}% — ${(100 - s.delivery_ratio).toFixed(1)}% of sent bytes were dropped/lost.`);
    });
  }

  if (q === 'ebpf') {
    const efRtt  = iperf.ef?.summary?.avg_rtt_us;
    const beRtt  = iperf.be?.summary?.avg_rtt_us;
    const efMbps = iperf.ef?.summary?.throughput_mbps;
    const efDr   = iperf.ef?.summary?.delivery_ratio;
    const beDr   = iperf.be?.summary?.delivery_ratio;
    if (efRtt && beRtt)
      conclusions.push(`**Latency priority**: EF RTT ${fmt(efRtt, 0)} µs, BE RTT ${fmt(beRtt, 0)} µs — eBPF XDP scheduler providing priority queuing at kernel level.`);
    if (efMbps > 400)
      conclusions.push(`**High-priority throughput**: EF class achieved ${fmt(efMbps)} Mbps (server-received) — near line-rate for latency-sensitive traffic.`);
    if (efDr != null)
      conclusions.push(`**EF delivery ratio**: ${fmt(efDr, 1)}% — ${efDr >= 99 ? 'eBPF delivered EF traffic with near-zero packet loss (delay-based shaping)' : `${(100 - efDr).toFixed(1)}% packet overhead from shaping`}.`);
    if (beDr != null && efDr != null && beDr < efDr)
      conclusions.push(`**Traffic class fairness**: EF delivery ${fmt(efDr, 1)}% vs BE ${fmt(beDr, 1)}% — eBPF is correctly prioritising EF over BE at the expense of BE delivery.`);
    const totalEcn = ebpfClasses.reduce((s, c) => s + (Number(c.ecn_marked) || 0), 0);
    if (totalEcn > 0)
      conclusions.push(`**Congestion management**: ${fmtK(totalEcn)} ECN marks — eBPF signals congestion without dropping packets, preserving delivery ratio.`);
    const cpuTotal = cpu.snapshots?.length
      ? (cpu.snapshots.reduce((s, r) => s + (r.usr_pct || 0) + (r.sys_pct || 0) + (r.soft_pct || 0), 0) / cpu.snapshots.length).toFixed(2)
      : null;
    if (cpuTotal)
      conclusions.push(`**CPU overhead**: ${cpuTotal}% active CPU — XDP runs in kernel context; softirq load reflects per-packet eBPF program execution.`);
  }

  if (conclusions.length) {
    conclusions.forEach((c, i) => lines.push(`${i + 1}. ${c}`));
  } else {
    lines.push('_Upload complete experiment files to generate automated conclusions._');
  }
  lines.push('');

  // Footer
  lines.push('---');
  lines.push('');
  lines.push(`*Generated by eBPF QoS Research Platform · ${label} · ${now}*`);
  lines.push('');

  return lines.join('\n');
}

module.exports = { buildModeMarkdown };
