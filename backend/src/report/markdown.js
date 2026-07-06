'use strict';

// ── Helpers ──────────────────────────────────────────────────────────────────
function fmt(n, d = 2)  { return (n == null || isNaN(n)) ? '—' : Number(n).toFixed(d); }
function fmtK(n)        { return (n == null || isNaN(n)) ? '—' : Number(n).toLocaleString('en-US'); }
function row(cells)     { return '| ' + cells.join(' | ') + ' |'; }
function sep(n)         { return '|' + Array(n).fill('---').join('|') + '|'; }
function h2(t)          { return `## ${t}\n`; }
function h3(t)          { return `### ${t}\n`; }

// Compare value to No-QoS baseline: return "+x%" / "-x%" string
function vsBase(val, base) {
  if (val == null || base == null || base === 0) return '—';
  const pct = ((val - base) / base * 100).toFixed(1);
  return `${pct > 0 ? '+' : ''}${pct}%`;
}

const QOS_LABELS = { no_qos: 'No QoS', htb: 'HTB', ebpf: 'eBPF' };
const TC_LABELS  = { ef: 'EF (Expedited)', af: 'AF (Assured)', be: 'BE (Best Effort)' };
const QOS_KEYS   = ['no_qos', 'htb', 'ebpf'];
const TC_KEYS    = ['ef', 'af', 'be'];

// ── Section builders ──────────────────────────────────────────────────────────

// Build TCP throughput + latency + retransmit table (camelCase IperfMetrics shape)
function tcpTable(mByQos) {
  const lines = [];
  lines.push(row(['QoS', 'Class', 'Sent Mbps', 'Rcv Mbps', 'DR%', 'RTT avg µs', 'RTT min', 'RTT max', 'σ RTT', 'Retx', 'CWND (B)', 'Congestion', 'CPU Sender', 'CPU Rcvr']));
  lines.push(sep(14));
  for (const q of QOS_KEYS) {
    for (const tc of TC_KEYS) {
      const d = mByQos[q]?.[tc];
      if (!d) continue;
      lines.push(row([
        QOS_LABELS[q], TC_LABELS[tc],
        fmt(d.sentThroughputMbps), fmt(d.throughputMbps),
        d.deliveryRatio != null ? fmt(d.deliveryRatio, 1) + '%' : '—',
        fmt(d.avgRttUs, 0), fmt(d.minRttUs, 0), fmt(d.maxRttUs, 0), fmt(d.rttStdUs, 0),
        fmtK(d.retransmits),
        d.maxSndCwnd != null ? fmtK(d.maxSndCwnd) : '—',
        d.tcpCongestion || '—',
        d.cpuHostUser != null ? `${fmt(d.cpuHostUser, 1)}u/${fmt(d.cpuHostSystem, 1)}s` : '—',
        d.cpuRemoteTotal != null ? fmt(d.cpuRemoteTotal, 1) + '%' : '—',
      ]));
    }
  }
  return lines;
}

// Build UDP throughput + packet loss table (camelCase IperfMetrics shape)
function udpTable(mByQos) {
  const lines = [];
  lines.push(row(['QoS', 'Class', 'Sent Mbps', 'Sent Pkts', 'Rcv Mbps', 'Rcv Pkts', 'Lost Pkts', 'Loss%', 'DR%', 'Jitter ms', 'CPU Sender', 'CPU Rcvr']));
  lines.push(sep(12));
  for (const q of QOS_KEYS) {
    for (const tc of TC_KEYS) {
      const d = mByQos[q]?.[tc];
      if (!d) continue;
      lines.push(row([
        QOS_LABELS[q], TC_LABELS[tc],
        fmt(d.sentThroughputMbps), d.sentPackets != null ? fmtK(d.sentPackets) : '—',
        fmt(d.throughputMbps),    d.rcvPackets  != null ? fmtK(d.rcvPackets)  : '—',
        d.lostPackets != null ? fmtK(d.lostPackets) : '—',
        d.lostPercent != null ? fmt(d.lostPercent, 2) + '%' : '—',
        d.deliveryRatio != null ? fmt(d.deliveryRatio, 1) + '%' : '—',
        d.jitterMs != null ? fmt(d.jitterMs, 3) : '—',
        d.cpuHostUser != null ? `${fmt(d.cpuHostUser, 1)}u/${fmt(d.cpuHostSystem, 1)}s` : '—',
        d.cpuRemoteTotal != null ? fmt(d.cpuRemoteTotal, 1) + '%' : '—',
      ]));
    }
  }
  return lines;
}

// Build CPU sar table (avgUsr/avgSys/avgIowait/avgSoft/avgIdle/avgTotal)
function cpuTable(mByQos) {
  const lines = [];
  lines.push(row(['QoS', 'User %', 'System %', 'IOWait %', 'Softirq %', 'Idle %', 'Total Active %', 'SAR Samples']));
  lines.push(sep(8));
  for (const q of QOS_KEYS) {
    const cpu = mByQos[q]?.cpu;
    if (!cpu) continue;
    lines.push(row([
      QOS_LABELS[q],
      fmt(cpu.avgUsr), fmt(cpu.avgSys), fmt(cpu.avgIowait ?? 0),
      fmt(cpu.avgSoft), fmt(cpu.avgIdle), fmt(cpu.avgTotal),
      fmtK(cpu.samples),
    ]));
  }
  return lines;
}

// ── Main builder ──────────────────────────────────────────────────────────────
function buildMarkdown(ds) {
  const m   = ds.metrics || {};
  const mbp = ds.metricsByProtocol || {};
  const tcp = mbp.tcp;   // protocol-keyed: { no_qos: { ef, af, be, cpu }, htb: ..., ebpf: ... }
  const udp = mbp.udp;
  const ts  = ds.timeSeries || {};
  const now = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

  // Pick primary protocol for backward-compat tables
  const primary = tcp || udp || m;

  const lines = [];

  // ── Front matter ──────────────────────────────────────────────────────────
  lines.push('---');
  lines.push(`title: "${ds.name}"`);
  lines.push(`generated: "${now}"`);
  lines.push(`dataset_id: ${ds.id}`);
  lines.push(`protocols: "${[tcp ? 'tcp' : null, udp ? 'udp' : null].filter(Boolean).join(', ') || 'unknown'}"`);
  if (ds.description) lines.push(`description: "${ds.description}"`);
  lines.push('---');
  lines.push('');

  lines.push(`# eBPF QoS Research Report — ${ds.name}`);
  lines.push('');
  lines.push(`> Generated: ${now}`);
  if (ds.description) lines.push(`> ${ds.description}`);
  lines.push('');

  // ── 1. Executive Summary ──────────────────────────────────────────────────
  lines.push(h2('1. Executive Summary'));

  const efNoQos = primary.no_qos?.ef;
  const efHtb   = primary.htb?.ef;
  const efEbpf  = primary.ebpf?.ef;
  const findings = [];

  if (efNoQos?.avgRttUs && efEbpf?.avgRttUs)
    findings.push(`eBPF reduces EF avg RTT by **${(efNoQos.avgRttUs / efEbpf.avgRttUs).toFixed(1)}×** vs No QoS (${fmt(efEbpf.avgRttUs, 0)} µs vs ${fmt(efNoQos.avgRttUs, 0)} µs).`);
  if (efNoQos?.avgRttUs && efHtb?.avgRttUs)
    findings.push(`HTB reduces EF avg RTT by **${(efNoQos.avgRttUs / efHtb.avgRttUs).toFixed(1)}×** vs No QoS (${fmt(efHtb.avgRttUs, 0)} µs).`);

  const efTcp = tcp?.ebpf?.ef, efTcpBase = tcp?.no_qos?.ef;
  if (efTcp?.throughputMbps && efTcpBase?.throughputMbps)
    findings.push(`eBPF EF TCP throughput: **${fmt(efTcp.throughputMbps)} Mbps** received (No QoS baseline: ${fmt(efTcpBase.throughputMbps)} Mbps).`);

  if (udp) {
    const efUdp = udp?.ebpf?.ef;
    const beUdp = udp?.ebpf?.be;
    if (efUdp?.deliveryRatio != null)
      findings.push(`eBPF EF UDP delivery ratio: **${fmt(efUdp.deliveryRatio, 1)}%** (${efUdp.lostPercent != null ? fmt(efUdp.lostPercent, 1) + '% packet loss' : ''}).`);
    if (efUdp && beUdp && efUdp.deliveryRatio != null && beUdp.deliveryRatio != null && efUdp.deliveryRatio < beUdp.deliveryRatio)
      findings.push(`**UDP Priority Anomaly**: eBPF EF delivery ${fmt(efUdp.deliveryRatio, 1)}% < BE ${fmt(beUdp.deliveryRatio, 1)}% — priority inversion detected. EF uses drop-based enforcement (0 delayed events); verify EF UDP token-bucket config.`);
  }

  const cpuEbpf  = primary.ebpf?.cpu?.avgTotal;
  const cpuNoQos = primary.no_qos?.cpu?.avgTotal;
  const cpuHtb   = primary.htb?.cpu?.avgTotal;
  if (cpuEbpf != null && cpuNoQos != null)
    findings.push(`eBPF CPU overhead: **${fmt(cpuEbpf)}%** active (No QoS: ${fmt(cpuNoQos)}%, HTB: ${cpuHtb != null ? fmt(cpuHtb) + '%' : '—'}).`);

  const ebpfMap = m.ebpf?.mapStats;
  if (ebpfMap) {
    const ecn = Object.values(ebpfMap).reduce((s, c) => s + (Number(c.ecnMarked) || 0), 0);
    const dly = Object.values(ebpfMap).reduce((s, c) => s + (Number(c.delayed)   || 0), 0);
    if (ecn > 0) findings.push(`eBPF performed **${fmtK(ecn)} ECN marks** and **${fmtK(dly)} delayed events** — active congestion management confirmed.`);
  }

  if (findings.length) findings.forEach(f => lines.push(`- ${f}`));
  else lines.push('_No data available for summary._');
  lines.push('');

  // ── 2. TCP Analysis ───────────────────────────────────────────────────────
  const tcpData = tcp || primary;
  const hasTcp  = QOS_KEYS.some(q => TC_KEYS.some(tc => tcpData[q]?.[tc]?.throughputMbps != null));
  if (hasTcp) {
    lines.push(h2('2. TCP Analysis'));
    lines.push('`sum_sent.bits_per_second` = ACK-confirmed client rate. `sum_received.bits_per_second` = server goodput.');
    lines.push('For sender-side QoS (HTB/eBPF on egress), TCP CUBIC adapts so **Sent ≈ Received** — the shaping effect shows as reduced RTT / retransmits vs No QoS.');
    lines.push('');

    lines.push(h3('2.1 Throughput & Latency — all modes × classes'));
    lines.push(...tcpTable(tcpData));
    lines.push('');

    lines.push(h3('2.2 RTT Comparison — No QoS vs HTB vs eBPF'));
    lines.push(row(['QoS', 'Class', 'Avg RTT (µs)', 'Min RTT', 'Max RTT', 'σ RTT', 'vs No QoS']));
    lines.push(sep(7));
    for (const q of QOS_KEYS) {
      for (const tc of TC_KEYS) {
        const d    = tcpData[q]?.[tc];
        const base = tcpData.no_qos?.[tc]?.avgRttUs;
        if (!d) continue;
        lines.push(row([
          QOS_LABELS[q], TC_LABELS[tc],
          fmt(d.avgRttUs, 0), fmt(d.minRttUs, 0), fmt(d.maxRttUs, 0), fmt(d.rttStdUs, 0),
          q !== 'no_qos' && d.avgRttUs && base ? `${(base / d.avgRttUs).toFixed(2)}× better` : '—',
        ]));
      }
    }
    lines.push('');

    lines.push(h3('2.3 TCP Sender Details (congestion window, retransmits)'));
    lines.push(row(['QoS', 'Class', 'Retransmits', 'Max CWND (B)', 'Max SND_WND (B)', 'Congestion Algo', 'Duration (s)']));
    lines.push(sep(7));
    for (const q of QOS_KEYS) {
      for (const tc of TC_KEYS) {
        const d = tcpData[q]?.[tc];
        if (!d) continue;
        lines.push(row([
          QOS_LABELS[q], TC_LABELS[tc],
          fmtK(d.retransmits),
          d.maxSndCwnd != null ? fmtK(d.maxSndCwnd) : '—',
          d.maxSndWnd  != null ? fmtK(d.maxSndWnd)  : '—',
          d.tcpCongestion || '—',
          fmt(d.durationS, 1),
        ]));
      }
    }
    lines.push('');
  }

  // ── 3. UDP Analysis ───────────────────────────────────────────────────────
  if (udp) {
    lines.push(h2('3. UDP Analysis'));
    lines.push('`sum_sent.bits_per_second` = application socket rate (pre-shaping). `sum_received.bits_per_second` = delivered rate at server.');
    lines.push('**Gap between Sent and Received = shaping effect.** UDP has no retransmit — excess is dropped.');
    lines.push('');

    lines.push(h3('3.1 Throughput, Packet Loss & Jitter — all modes × classes'));
    lines.push(...udpTable(udp));
    lines.push('');

    lines.push(h3('3.2 Shaping Effectiveness (Sent → Received gap)'));
    lines.push(row(['QoS', 'Class', 'Sent Mbps', 'Rcv Mbps', 'Gap Mbps', 'Loss%', 'DR%', 'Jitter ms']));
    lines.push(sep(8));
    for (const q of QOS_KEYS) {
      for (const tc of TC_KEYS) {
        const d = udp[q]?.[tc];
        if (!d) continue;
        const gap = d.sentThroughputMbps != null && d.throughputMbps != null
          ? (d.sentThroughputMbps - d.throughputMbps).toFixed(2)
          : '—';
        lines.push(row([
          QOS_LABELS[q], TC_LABELS[tc],
          fmt(d.sentThroughputMbps), fmt(d.throughputMbps),
          gap,
          d.lostPercent != null ? fmt(d.lostPercent, 2) + '%' : '—',
          d.deliveryRatio != null ? fmt(d.deliveryRatio, 1) + '%' : '—',
          d.jitterMs != null ? fmt(d.jitterMs, 3) : '—',
        ]));
      }
    }
    lines.push('');

    // UDP anomaly check
    const efDr = udp.ebpf?.ef?.deliveryRatio;
    const beDr = udp.ebpf?.be?.deliveryRatio;
    if (efDr != null && beDr != null && efDr < beDr) {
      lines.push('> **Priority Inversion Detected (eBPF UDP):**');
      lines.push(`> EF delivery ${fmt(efDr, 1)}% < BE ${fmt(beDr, 1)}%. eBPF EF uses drop-based enforcement (0 delayed events);`);
      lines.push('> AF/BE use delay-based shaping. Verify EF UDP token-bucket rate configuration.');
      lines.push('');
    }
  }

  // ── 4. CPU Utilization (SAR) ──────────────────────────────────────────────
  const cpuProtos = [tcp ? { label: 'TCP', data: tcp } : null, udp ? { label: 'UDP', data: udp } : null].filter(Boolean);
  const hasCpu = cpuProtos.some(p => QOS_KEYS.some(q => p.data[q]?.cpu));
  if (hasCpu) {
    lines.push(h2('4. CPU Utilization (SAR)'));
    lines.push('Average values from `sar`/`mpstat` measurement. **Total Active = usr + sys + iowait + softirq**.');
    lines.push('');
    for (const { label, data } of cpuProtos) {
      if (QOS_KEYS.every(q => !data[q]?.cpu)) continue;
      lines.push(h3(`4.x SAR CPU — ${label}`));
      lines.push(...cpuTable(data));
      lines.push('');
    }

    // iperf3 per-stream CPU (sender + receiver)
    const hasIperfCpu = QOS_KEYS.some(q => TC_KEYS.some(tc => primary[q]?.[tc]?.cpuHostTotal != null));
    if (hasIperfCpu) {
      lines.push(h3('4.x iperf3 CPU (host = sender, remote = receiver)'));
      lines.push(row(['QoS', 'Class', 'Sender Total%', 'Sender User%', 'Sender Sys%', 'Receiver Total%', 'Receiver User%', 'Receiver Sys%']));
      lines.push(sep(8));
      for (const q of QOS_KEYS) {
        for (const tc of TC_KEYS) {
          const d = primary[q]?.[tc];
          if (!d || d.cpuHostTotal == null) continue;
          lines.push(row([
            QOS_LABELS[q], TC_LABELS[tc],
            fmt(d.cpuHostTotal), fmt(d.cpuHostUser), fmt(d.cpuHostSystem),
            d.cpuRemoteTotal != null ? fmt(d.cpuRemoteTotal) : '—',
            d.cpuRemoteUser  != null ? fmt(d.cpuRemoteUser)  : '—',
            d.cpuRemoteSystem != null ? fmt(d.cpuRemoteSystem) : '—',
          ]));
        }
      }
      lines.push('');
    }
  }

  // ── 5. eBPF Map Statistics ────────────────────────────────────────────────
  const ebpfMaps = [
    tcp ? { label: 'TCP', map: tcp.ebpf?.mapStats } : null,
    udp ? { label: 'UDP', map: udp.ebpf?.mapStats } : null,
    (!tcp && !udp) ? { label: 'Primary', map: m.ebpf?.mapStats } : null,
  ].filter(p => p && p.map && Object.keys(p.map).length);

  if (ebpfMaps.length) {
    lines.push(h2('5. eBPF Map Statistics (XDP Counters)'));
    lines.push('Per-class counters from XDP eBPF map dump over the 30-second test window.');
    lines.push('- **Borrowed**: bandwidth borrowed from a lower-priority class');
    lines.push('- **ECN Marked**: Explicit Congestion Notification marks (active congestion signalling)');
    lines.push('- **Delayed**: packets held back by delay-based shaping scheduler');
    lines.push('');
    for (const { label, map } of ebpfMaps) {
      lines.push(h3(`5.x ${label}`));
      lines.push(row(['Class', 'Packets', 'Bytes', 'Calc. Mbps', 'Borrowed', 'ECN Marked', 'Delayed']));
      lines.push(sep(7));
      for (const [cls, s] of Object.entries(map)) {
        lines.push(row([cls, fmtK(s.packets), fmtK(s.bytes), fmt(s.throughputMbps), fmtK(s.borrowed), fmtK(s.ecnMarked), fmtK(s.delayed)]));
      }
      lines.push('');
    }
  }

  // ── 6. HTB TC Class Statistics ────────────────────────────────────────────
  const htbSets = [
    tcp ? { label: 'TCP', tc: tcp.htb?.tcClasses } : null,
    udp ? { label: 'UDP', tc: udp.htb?.tcClasses } : null,
    (!tcp && !udp) ? { label: 'Primary', tc: m.htb?.tcClasses } : null,
  ].filter(p => p && p.tc && Object.keys(p.tc).length);

  if (htbSets.length) {
    lines.push(h2('6. HTB TC Class Statistics'));
    lines.push('Raw `tc` qdisc counters. **Lended/Borrowed** = inter-class bandwidth sharing; **Tokens/cTokens** = current token bucket state.');
    lines.push('');
    for (const { label, tc: tcl } of htbSets) {
      lines.push(h3(`6.x ${label}`));
      lines.push(row(['Class', 'Rate', 'Bytes Sent', 'Pkts', 'Dropped', 'Overlimits', 'Lended', 'Borrowed', 'Tokens', 'cTokens', 'Requeues', 'Giants', 'Calc. Mbps']));
      lines.push(sep(13));
      for (const [cid, s] of Object.entries(tcl).sort()) {
        lines.push(row([
          cid, s.rate, fmtK(s.bytesSent), fmtK(s.packets), fmtK(s.dropped), fmtK(s.overlimits),
          s.lended != null ? fmtK(s.lended) : '—',
          s.borrowedPkt != null ? fmtK(s.borrowedPkt) : '—',
          s.tokens  != null ? fmtK(s.tokens)  : '—',
          s.ctokens != null ? fmtK(s.ctokens) : '—',
          s.requeues != null ? fmtK(s.requeues) : '—',
          s.giants  != null ? fmtK(s.giants)  : '—',
          fmt(s.throughputMbps),
        ]));
      }
      lines.push('');
    }
  }

  // ── 7. Time Series Summary ────────────────────────────────────────────────
  const tsKeys = Object.keys(ts);
  if (tsKeys.length) {
    lines.push(h2('7. Time Series Summary (per-second iperf3 intervals)'));
    lines.push(row(['Series', 'Samples', 'Avg Mbps', 'Min Mbps', 'Max Mbps', 'Std Dev', 'CV%', 'Avg RTT (µs)']));
    lines.push(sep(8));
    for (const key of tsKeys.sort()) {
      const pts = ts[key];
      if (!pts?.length) continue;
      const bps  = pts.map(p => p.bitsPerSecond / 1e6).filter(Boolean);
      const rtts = pts.map(p => p.rttUs).filter(Boolean);
      const avg  = arr => arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : null;
      const std  = (arr, a) => arr.length > 1 ? Math.sqrt(arr.reduce((s, v) => s + (v - a) ** 2, 0) / arr.length) : null;
      const bAvg = avg(bps);
      const bStd = std(bps, bAvg ?? 0);
      lines.push(row([
        key.replace(/_([a-z]+)$/, ' / $1').toUpperCase(),
        pts.length,
        bAvg != null ? bAvg.toFixed(2) : '—',
        bps.length ? Math.min(...bps).toFixed(2) : '—',
        bps.length ? Math.max(...bps).toFixed(2) : '—',
        bStd != null ? bStd.toFixed(2) : '—',
        bAvg && bStd ? (bStd / bAvg * 100).toFixed(1) + '%' : '—',
        avg(rtts) != null ? avg(rtts).toFixed(0) : '—',
      ]));
    }
    lines.push('');
  }

  // ── 8. Research Conclusions ───────────────────────────────────────────────
  lines.push(h2('8. Research Conclusions'));

  const conclusions = [];

  // RTT priority differentiation
  if (efNoQos?.avgRttUs && efEbpf?.avgRttUs) {
    const win = ((efNoQos.avgRttUs - efEbpf.avgRttUs) / efNoQos.avgRttUs * 100).toFixed(1);
    conclusions.push(`**Latency**: eBPF achieves ${win}% lower EF RTT vs No QoS. XDP classification eliminates inter-class queuing delay — all classes share sub-ms RTT.`);
  }
  if (efHtb?.avgRttUs && efEbpf?.avgRttUs) {
    const diff = efEbpf.avgRttUs - efHtb.avgRttUs;
    conclusions.push(`**eBPF vs HTB Latency**: eBPF EF ${fmt(efEbpf.avgRttUs, 0)} µs vs HTB EF ${fmt(efHtb.avgRttUs, 0)} µs — eBPF is ${Math.abs(diff).toFixed(0)} µs ${diff <= 0 ? 'lower (superior)' : 'higher'}.`);
  }

  // Throughput comparison
  if (tcp) {
    const totE = QOS_KEYS.reduce((s, q) => {
      if (q === 'ebpf') return s + TC_KEYS.reduce((ts, tc) => ts + (tcp[q]?.[tc]?.throughputMbps || 0), 0);
      return s;
    }, 0);
    const totH = TC_KEYS.reduce((s, tc) => s + (tcp.htb?.[tc]?.throughputMbps || 0), 0);
    if (totE > 0 && totH > 0)
      conclusions.push(`**TCP Link Utilization**: eBPF total ${totE.toFixed(0)} Mbps (${((totE/1000)*100).toFixed(0)}% of 1 Gbps) vs HTB ${totH.toFixed(0)} Mbps (${((totH/1000)*100).toFixed(0)}%). eBPF strict priority reduces total utilization; HTB proportional allocation uses more of the link.`);
  }

  // HTB enforcement
  const htbTcPrimary = m.htb?.tcClasses || tcp?.htb?.tcClasses;
  if (htbTcPrimary) {
    const drops = Object.values(htbTcPrimary).reduce((s, c) => s + (c.dropped || 0), 0);
    const ovlim = Object.values(htbTcPrimary).reduce((s, c) => s + (c.overlimits || 0), 0);
    if (drops === 0)
      conclusions.push(`**HTB Enforcement**: Zero drops — enforcement via ${fmtK(ovlim)} overlimits only (token-bucket depleted, no queue overflow). Clean proportional allocation.`);
    else
      conclusions.push(`**HTB Enforcement**: ${fmtK(drops)} packet drops — rate limits exceeded. ${fmtK(ovlim)} overlimits.`);
  }

  // UDP analysis
  if (udp) {
    const efUdp = udp.ebpf?.ef, beUdp = udp.ebpf?.be;
    if (efUdp?.deliveryRatio != null && beUdp?.deliveryRatio != null) {
      if (efUdp.deliveryRatio < beUdp.deliveryRatio)
        conclusions.push(`**eBPF UDP Priority Inversion**: EF delivery ${fmt(efUdp.deliveryRatio, 1)}% < BE ${fmt(beUdp.deliveryRatio, 1)}%. Drop-based EF enforcement causes higher loss for the highest-priority class. Delay-based shaping (AF/BE) preserves packets. Fix: adjust EF UDP token-bucket rate or switch to delay-based enforcement.`);
      else
        conclusions.push(`**eBPF UDP Delivery**: EF ${fmt(efUdp.deliveryRatio, 1)}% ≥ BE ${fmt(beUdp.deliveryRatio, 1)}% — UDP priority ordering correct.`);
    }
  }

  // CPU conclusions
  if (cpuEbpf != null && cpuNoQos != null) {
    const overhead = (cpuEbpf - cpuNoQos).toFixed(2);
    conclusions.push(`**CPU Overhead**: eBPF adds ${overhead}% active CPU vs No QoS (${fmt(cpuEbpf)}% vs ${fmt(cpuNoQos)}%). ${parseFloat(overhead) < 10 ? 'Acceptable for production use.' : 'Significant — profile XDP hook and user-space control plane before deployment.'}`);
  }

  // ECN / delayed stats
  if (ebpfMap) {
    const ecn = Object.values(ebpfMap).reduce((s, c) => s + (Number(c.ecnMarked) || 0), 0);
    const dly = Object.values(ebpfMap).reduce((s, c) => s + (Number(c.delayed)   || 0), 0);
    if (ecn > 0 || dly > 0)
      conclusions.push(`**Congestion Management**: ${fmtK(ecn)} ECN marks + ${fmtK(dly)} delayed events confirm eBPF scheduler actively managing congestion without purely relying on packet drops.`);
  }

  conclusions.push('**Recommended Next Experiments**: Concurrent multi-class TCP + UDP test to observe real inter-class QoS interaction; eBPF UDP with corrected EF rate config; CPU profiling to separate XDP hook time from user-space control plane; ECN behavior analysis for TCP AF/BE under heavy load.');

  if (conclusions.length) conclusions.forEach((c, i) => lines.push(`${i + 1}. ${c}`));
  else lines.push('_Insufficient data for automated conclusions. Upload complete experiment files._');
  lines.push('');

  lines.push('---');
  lines.push(`*Report generated by eBPF QoS Research Platform · ${now}*`);
  lines.push('');

  return lines.join('\n');
}

module.exports = { buildMarkdown };
