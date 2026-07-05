'use strict';

// Converts raw dataset object (same shape as GET /datasets/:id) into Markdown

function fmt(n, decimals = 2) {
  if (n == null || isNaN(n)) return '—';
  return Number(n).toFixed(decimals);
}

function fmtK(n) {
  if (n == null || isNaN(n)) return '—';
  return Number(n).toLocaleString('en-US');
}

function tableRow(cells) {
  return '| ' + cells.join(' | ') + ' |';
}

function tableSep(n) {
  return '|' + Array(n).fill('---').join('|') + '|';
}

function pct(val, base) {
  if (!base || !val) return '';
  return ` (${((val / base - 1) * 100).toFixed(1)}%)`;
}

// ── Main builder ────────────────────────────────────────────────────────────
function buildMarkdown(ds) {
  const m   = ds.metrics || {};
  const ts  = ds.timeSeries || {};
  const now = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

  const QOS_LABELS = { no_qos: 'No QoS', htb: 'HTB', ebpf: 'eBPF' };
  const TC_LABELS  = { ef: 'EF (Expedited)', af: 'AF (Assured)', be: 'BE (Best Effort)' };
  const QOS_KEYS   = ['no_qos', 'htb', 'ebpf'];
  const TC_KEYS    = ['ef', 'af', 'be'];

  const lines = [];

  // ── Front matter ──────────────────────────────────────────────────────────
  lines.push('---');
  lines.push(`title: "${ds.name}"`);
  lines.push(`generated: "${now}"`);
  lines.push(`dataset_id: ${ds.id}`);
  if (ds.description) lines.push(`description: "${ds.description}"`);
  lines.push('---');
  lines.push('');

  // ── Title ─────────────────────────────────────────────────────────────────
  lines.push(`# eBPF QoS Research Report — ${ds.name}`);
  lines.push('');
  lines.push(`> Generated: ${now}`);
  if (ds.description) lines.push(`> ${ds.description}`);
  lines.push('');

  // ── 1. Executive Summary ──────────────────────────────────────────────────
  lines.push('## 1. Executive Summary');
  lines.push('');

  const efNoQos = m.no_qos?.ef;
  const efHtb   = m.htb?.ef;
  const efEbpf  = m.ebpf?.ef;

  const findings = [];
  if (efNoQos && efEbpf && efEbpf.avgRttUs) {
    const ratio = (efNoQos.avgRttUs / efEbpf.avgRttUs).toFixed(1);
    findings.push(`eBPF reduces EF avg RTT by **${ratio}×** compared to No QoS (${fmt(efEbpf.avgRttUs, 0)} µs vs ${fmt(efNoQos.avgRttUs, 0)} µs).`);
  }
  if (efNoQos && efHtb && efHtb.avgRttUs) {
    const ratio = (efNoQos.avgRttUs / efHtb.avgRttUs).toFixed(1);
    findings.push(`HTB reduces EF avg RTT by **${ratio}×** compared to No QoS (${fmt(efHtb.avgRttUs, 0)} µs).`);
  }

  const ebpfCpu = m.ebpf?.cpu?.avgTotal;
  const noqosCpu = m.no_qos?.cpu?.avgTotal;
  if (ebpfCpu != null && noqosCpu != null) {
    const overhead = (ebpfCpu - noqosCpu).toFixed(2);
    findings.push(`eBPF CPU overhead: **+${overhead}%** vs No QoS (${fmt(ebpfCpu)}% vs ${fmt(noqosCpu)}% total CPU).`);
  }

  const ebpfMap = m.ebpf?.mapStats;
  if (ebpfMap) {
    const totalEcn = Object.values(ebpfMap).reduce((s, c) => s + (Number(c.ecnMarked) || 0), 0);
    if (totalEcn > 0) findings.push(`eBPF performed **${fmtK(totalEcn)} ECN marks** for active congestion management.`);
  }

  if (findings.length) {
    findings.forEach(f => lines.push(`- ${f}`));
  } else {
    lines.push('_No data available for summary._');
  }
  lines.push('');

  // ── 2. RTT / Latency ─────────────────────────────────────────────────────
  lines.push('## 2. Latency (Round-Trip Time)');
  lines.push('');
  lines.push('All values in **microseconds (µs)**.');
  lines.push('');
  lines.push(tableRow(['QoS Method', 'Traffic Class', 'Avg RTT (µs)', 'Min RTT', 'Max RTT', 'Std Dev', 'vs No QoS']));
  lines.push(tableSep(7));

  for (const q of QOS_KEYS) {
    for (const tc of TC_KEYS) {
      const d  = m[q]?.[tc];
      const base = m.no_qos?.[tc]?.avgRttUs;
      if (!d) continue;
      const vs = (q !== 'no_qos' && base && d.avgRttUs)
        ? `${(base / d.avgRttUs).toFixed(2)}× better`
        : '—';
      lines.push(tableRow([
        QOS_LABELS[q],
        TC_LABELS[tc] || tc.toUpperCase(),
        fmt(d.avgRttUs, 0),
        fmt(d.minRttUs, 0),
        fmt(d.maxRttUs, 0),
        fmt(d.rttStdUs, 0),
        vs,
      ]));
    }
  }
  lines.push('');

  // ── 3. Throughput ─────────────────────────────────────────────────────────
  lines.push('## 3. Throughput');
  lines.push('');
  lines.push('All values in **Mbps**.');
  lines.push('');
  lines.push(tableRow(['QoS Method', 'Traffic Class', 'Throughput (Mbps)', 'Duration (s)', 'Retransmits', 'vs No QoS']));
  lines.push(tableSep(6));

  for (const q of QOS_KEYS) {
    for (const tc of TC_KEYS) {
      const d    = m[q]?.[tc];
      const base = m.no_qos?.[tc]?.throughputMbps;
      if (!d) continue;
      const vs = (q !== 'no_qos' && base && d.throughputMbps)
        ? `${pct(d.throughputMbps, base).trim()}`
        : '—';
      lines.push(tableRow([
        QOS_LABELS[q],
        TC_LABELS[tc] || tc.toUpperCase(),
        fmt(d.throughputMbps),
        fmt(d.durationS, 0),
        fmtK(d.retransmits),
        vs,
      ]));
    }
  }
  lines.push('');

  // ── 4. CPU Utilization ────────────────────────────────────────────────────
  lines.push('## 4. CPU Utilization');
  lines.push('');
  lines.push('Average values from `sar` measurement (% of total CPU).');
  lines.push('');
  lines.push(tableRow(['QoS Method', 'User %', 'System %', 'Softirq %', 'Idle %', 'Total Active %']));
  lines.push(tableSep(6));

  for (const q of QOS_KEYS) {
    const cpu = m[q]?.cpu;
    if (!cpu) continue;
    lines.push(tableRow([
      QOS_LABELS[q],
      fmt(cpu.avgUsr),
      fmt(cpu.avgSys),
      fmt(cpu.avgSoft),
      fmt(cpu.avgIdle),
      fmt(cpu.avgTotal),
    ]));
  }
  lines.push('');

  // ── 5. iperf CPU (per-class from iperf3 json) ─────────────────────────────
  const hasIperfCpu = QOS_KEYS.some(q => TC_KEYS.some(tc => m[q]?.[tc]?.cpuHostTotal != null));
  if (hasIperfCpu) {
    lines.push('### 4.1 iperf3 CPU (host-side, per-stream)');
    lines.push('');
    lines.push(tableRow(['QoS Method', 'Traffic Class', 'Host Total %', 'Host User %', 'Host System %', 'Remote Total %']));
    lines.push(tableSep(6));
    for (const q of QOS_KEYS) {
      for (const tc of TC_KEYS) {
        const d = m[q]?.[tc];
        if (!d || d.cpuHostTotal == null) continue;
        lines.push(tableRow([
          QOS_LABELS[q],
          tc.toUpperCase(),
          fmt(d.cpuHostTotal),
          fmt(d.cpuHostUser),
          fmt(d.cpuHostSystem),
          fmt(d.cpuRemoteTotal),
        ]));
      }
    }
    lines.push('');
  }

  // ── 6. eBPF Map Stats ─────────────────────────────────────────────────────
  if (ebpfMap && Object.keys(ebpfMap).length) {
    lines.push('## 5. eBPF Map Statistics');
    lines.push('');
    lines.push('Per-class counters from the XDP eBPF map dump.');
    lines.push('');
    lines.push(tableRow(['Class', 'Packets', 'Bytes', 'Throughput (Mbps)', 'Borrowed', 'ECN Marked', 'Delayed']));
    lines.push(tableSep(7));
    for (const [cls, s] of Object.entries(ebpfMap)) {
      lines.push(tableRow([
        cls,
        fmtK(s.packets),
        fmtK(s.bytes),
        fmt(s.throughputMbps),
        fmtK(s.borrowed),
        fmtK(s.ecnMarked),
        fmtK(s.delayed),
      ]));
    }
    lines.push('');
    lines.push('**Notes:**');
    lines.push('- **Borrowed**: packets using bandwidth borrowed from a lower-priority class');
    lines.push('- **ECN Marked**: Explicit Congestion Notification marks (active congestion signalling)');
    lines.push('- **Delayed**: packets held back for scheduling (indicates active shaping)');
    lines.push('');
  }

  // ── 7. HTB TC Classes ─────────────────────────────────────────────────────
  const htbTc = m.htb?.tcClasses;
  if (htbTc && Object.keys(htbTc).length) {
    lines.push('## 6. HTB TC Class Statistics');
    lines.push('');
    lines.push('Raw `tc` class counters from the HTB qdisc.');
    lines.push('');
    lines.push(tableRow(['Class ID', 'Rate', 'Bytes Sent', 'Packets', 'Dropped', 'Overlimits', 'Calc. Mbps']));
    lines.push(tableSep(7));
    for (const [cid, s] of Object.entries(htbTc).sort()) {
      lines.push(tableRow([
        cid,
        s.rate,
        fmtK(s.bytesSent),
        fmtK(s.packets),
        fmtK(s.dropped),
        fmtK(s.overlimits),
        fmt(s.throughputMbps),
      ]));
    }
    lines.push('');
  }

  // ── 8. Time Series summary ────────────────────────────────────────────────
  const tsKeys = Object.keys(ts);
  if (tsKeys.length) {
    lines.push('## 7. Time Series Summary');
    lines.push('');
    lines.push('Calculated from per-second iperf3 intervals (30 s test window).');
    lines.push('');
    lines.push(tableRow(['Series', 'Samples', 'Avg Mbps', 'Min Mbps', 'Max Mbps', 'Avg RTT (µs)']));
    lines.push(tableSep(6));
    for (const key of tsKeys.sort()) {
      const points = ts[key];
      if (!points?.length) continue;
      const bps   = points.map(p => p.bitsPerSecond / 1e6).filter(Boolean);
      const rtts  = points.map(p => p.rttUs).filter(Boolean);
      const avg   = n => n.length ? (n.reduce((a, b) => a + b, 0) / n.length).toFixed(2) : '—';
      const min   = n => n.length ? Math.min(...n).toFixed(2) : '—';
      const max   = n => n.length ? Math.max(...n).toFixed(2) : '—';
      lines.push(tableRow([
        key.replace('_', ' / ').toUpperCase(),
        points.length,
        avg(bps),
        min(bps),
        max(bps),
        avg(rtts),
      ]));
    }
    lines.push('');
  }

  // ── 9. Conclusions ────────────────────────────────────────────────────────
  lines.push('## 8. Conclusions');
  lines.push('');

  const conclusions = [];

  if (efNoQos && efEbpf) {
    const rttWin = ((efNoQos.avgRttUs - efEbpf.avgRttUs) / efNoQos.avgRttUs * 100).toFixed(1);
    conclusions.push(`**Latency**: eBPF achieves ${rttWin}% lower EF RTT vs No QoS — demonstrating effective priority queuing for latency-sensitive traffic.`);
  }
  if (efHtb && efEbpf && efEbpf.avgRttUs && efHtb.avgRttUs) {
    const diff = efEbpf.avgRttUs - efHtb.avgRttUs;
    const label = diff <= 0 ? 'lower' : 'higher';
    conclusions.push(`**eBPF vs HTB**: eBPF EF RTT is ${Math.abs(diff).toFixed(0)} µs ${label} than HTB — ${diff <= 0 ? 'indicating superior real-time classification' : 'HTB has slightly lower EF latency but less flexibility'}.`);
  }
  if (ebpfCpu != null && noqosCpu != null) {
    const overhead = (ebpfCpu - noqosCpu).toFixed(2);
    const judgement = parseFloat(overhead) < 5 ? 'acceptable for production workloads' : 'significant — evaluate for high-throughput scenarios';
    conclusions.push(`**CPU overhead**: eBPF adds ${overhead}% CPU vs No QoS — ${judgement}.`);
  }
  if (ebpfMap) {
    const totalEcn = Object.values(ebpfMap).reduce((s, c) => s + (Number(c.ecnMarked) || 0), 0);
    const totalDly = Object.values(ebpfMap).reduce((s, c) => s + (Number(c.delayed)   || 0), 0);
    if (totalEcn > 0 || totalDly > 0)
      conclusions.push(`**Congestion control**: ${fmtK(totalEcn)} ECN marks and ${fmtK(totalDly)} delayed events confirm the eBPF scheduler is actively managing congestion.`);
  }

  if (conclusions.length) {
    conclusions.forEach((c, i) => lines.push(`${i + 1}. ${c}`));
  } else {
    lines.push('_Insufficient data for automated conclusions. Upload complete experiment files._');
  }
  lines.push('');

  // ── Footer ────────────────────────────────────────────────────────────────
  lines.push('---');
  lines.push('');
  lines.push(`*Report generated by eBPF QoS Research Platform · ${now}*`);
  lines.push('');

  return lines.join('\n');
}

module.exports = { buildMarkdown };
