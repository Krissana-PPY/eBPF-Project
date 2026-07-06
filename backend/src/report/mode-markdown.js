'use strict';

// ── Helpers ──────────────────────────────────────────────────────────────────
function fmt(n, d = 2)  { return (n == null || isNaN(n)) ? '—' : Number(n).toFixed(d); }
function fmtK(n)        { return (n == null || isNaN(n)) ? '—' : Number(n).toLocaleString('en-US'); }
function row(cells)     { return '| ' + cells.join(' | ') + ' |'; }
function sep(n)         { return '|' + Array(n).fill('---').join('|') + '|'; }
function h2(t)          { return `## ${t}\n`; }
function h3(t)          { return `### ${t}\n`; }

const MODE_LABELS = { no_qos: 'No QoS', htb: 'HTB (Hierarchical Token Bucket)', ebpf: 'eBPF XDP' };
const TC_LABELS   = { ef: 'EF (Expedited Forwarding)', af: 'AF (Assured Forwarding)', be: 'BE (Best Effort)' };
const TC_RATES    = { ef: '500 Mbps', af: '300 Mbps', be: '200 Mbps' };
const TC_KEYS     = ['ef', 'af', 'be'];

// Pick whichever field exists (snake or camel)
function get(obj, ...keys) {
  for (const k of keys) if (obj?.[k] != null) return obj[k];
  return null;
}

// ── Protocol section builders ─────────────────────────────────────────────────
function tcpSection(iperfByTc, label) {
  const lines = [];
  const hasAny = TC_KEYS.some(tc => iperfByTc[tc]);
  if (!hasAny) return lines;

  lines.push(h3(`${label} — TCP Performance`));
  lines.push('`Sent` = ACK-confirmed client rate. `Received` = server goodput. For sender-side QoS, CUBIC adapts → **Sent ≈ Received**; enforcement shows as reduced RTT / retransmits.');
  lines.push('');

  lines.push('**Throughput & Latency**');
  lines.push('');
  lines.push(row(['Class', 'Target Rate', 'Sent Mbps', 'Rcv Mbps', 'DR%', 'RTT avg µs', 'RTT min', 'RTT max', 'σ RTT', 'Duration (s)']));
  lines.push(sep(10));
  for (const tc of TC_KEYS) {
    const d = iperfByTc[tc]?.summary;
    if (!d) continue;
    lines.push(row([
      TC_LABELS[tc] || tc.toUpperCase(), TC_RATES[tc] || '—',
      fmt(get(d, 'sent_throughput_mbps', 'sentThroughputMbps')),
      fmt(get(d, 'throughput_mbps', 'throughputMbps')),
      get(d, 'delivery_ratio', 'deliveryRatio') != null
        ? fmt(get(d, 'delivery_ratio', 'deliveryRatio'), 1) + '%' : '—',
      fmt(get(d, 'avg_rtt_us', 'avgRttUs'), 0),
      fmt(get(d, 'min_rtt_us', 'minRttUs'), 0),
      fmt(get(d, 'max_rtt_us', 'maxRttUs'), 0),
      fmt(get(d, 'rtt_std_us', 'rttStdUs'), 0),
      fmt(get(d, 'duration_s', 'durationS'), 1),
    ]));
  }
  lines.push('');

  lines.push('**TCP Sender Details**');
  lines.push('');
  lines.push(row(['Class', 'Retransmits', 'Max CWND (B)', 'Max SND_WND (B)', 'Congestion Algo', 'CPU Sender (usr/sys)', 'CPU Receiver']));
  lines.push(sep(7));
  for (const tc of TC_KEYS) {
    const d = iperfByTc[tc]?.summary;
    if (!d) continue;
    const cpuU  = get(d, 'cpu_host_user',   'cpuHostUser');
    const cpuS  = get(d, 'cpu_host_system', 'cpuHostSystem');
    const cpuR  = get(d, 'cpu_remote_total','cpuRemoteTotal');
    lines.push(row([
      TC_LABELS[tc] || tc.toUpperCase(),
      fmtK(get(d, 'retransmits')),
      get(d, 'max_snd_cwnd', 'maxSndCwnd') != null ? fmtK(get(d, 'max_snd_cwnd', 'maxSndCwnd')) : '—',
      get(d, 'max_snd_wnd',  'maxSndWnd')  != null ? fmtK(get(d, 'max_snd_wnd',  'maxSndWnd'))  : '—',
      get(d, 'tcp_congestion', 'tcpCongestion') || '—',
      cpuU != null ? `${fmt(cpuU, 1)}u / ${fmt(cpuS, 1)}s` : '—',
      cpuR != null ? fmt(cpuR, 1) + '%' : '—',
    ]));
  }
  lines.push('');
  return lines;
}

function udpSection(iperfByTc, label) {
  const lines = [];
  const hasAny = TC_KEYS.some(tc => iperfByTc[tc]);
  if (!hasAny) return lines;

  lines.push(h3(`${label} — UDP Performance`));
  lines.push('`Sent` = socket-push rate (pre-shaping). `Received` = delivered at server. Gap = QoS drop/delay. UDP has no retransmit — excess is **dropped**.');
  lines.push('');

  lines.push('**Throughput, Packet Loss & Jitter**');
  lines.push('');
  lines.push(row(['Class', 'Target', 'Sent Mbps', 'Sent Pkts', 'Rcv Mbps', 'Rcv Pkts', 'Lost Pkts', 'Loss%', 'DR%', 'Jitter ms', 'Duration (s)']));
  lines.push(sep(11));
  for (const tc of TC_KEYS) {
    const d = iperfByTc[tc]?.summary;
    if (!d) continue;
    lines.push(row([
      TC_LABELS[tc] || tc.toUpperCase(), TC_RATES[tc] || '—',
      fmt(get(d, 'sent_throughput_mbps', 'sentThroughputMbps')),
      get(d, 'sent_packets', 'sentPackets') != null ? fmtK(get(d, 'sent_packets', 'sentPackets')) : '—',
      fmt(get(d, 'throughput_mbps', 'throughputMbps')),
      get(d, 'rcv_packets',  'rcvPackets')  != null ? fmtK(get(d, 'rcv_packets',  'rcvPackets'))  : '—',
      get(d, 'lost_packets', 'lostPackets') != null ? fmtK(get(d, 'lost_packets', 'lostPackets')) : '—',
      get(d, 'lost_percent', 'lostPercent') != null ? fmt(get(d, 'lost_percent', 'lostPercent'), 2) + '%' : '—',
      get(d, 'delivery_ratio', 'deliveryRatio') != null
        ? fmt(get(d, 'delivery_ratio', 'deliveryRatio'), 1) + '%' : '—',
      get(d, 'jitter_ms', 'jitterMs') != null ? fmt(get(d, 'jitter_ms', 'jitterMs'), 3) : '—',
      fmt(get(d, 'duration_s', 'durationS'), 1),
    ]));
  }
  lines.push('');

  lines.push('**Shaping Gap (Sent → Received)**');
  lines.push('');
  lines.push(row(['Class', 'Sent Mbps', 'Rcv Mbps', 'Dropped Mbps', 'Drop Rate', 'CPU Sender (usr/sys)', 'CPU Receiver']));
  lines.push(sep(7));
  for (const tc of TC_KEYS) {
    const d = iperfByTc[tc]?.summary;
    if (!d) continue;
    const sent = get(d, 'sent_throughput_mbps', 'sentThroughputMbps');
    const rcv  = get(d, 'throughput_mbps', 'throughputMbps');
    const gap  = sent != null && rcv != null ? (sent - rcv).toFixed(2) : '—';
    const drop = sent != null && rcv != null && sent > 0 ? ((sent - rcv) / sent * 100).toFixed(1) + '%' : '—';
    const cpuU = get(d, 'cpu_host_user',    'cpuHostUser');
    const cpuS = get(d, 'cpu_host_system',  'cpuHostSystem');
    const cpuR = get(d, 'cpu_remote_total', 'cpuRemoteTotal');
    lines.push(row([
      TC_LABELS[tc] || tc.toUpperCase(),
      fmt(sent), fmt(rcv), gap, drop,
      cpuU != null ? `${fmt(cpuU, 1)}u / ${fmt(cpuS, 1)}s` : '—',
      cpuR != null ? fmt(cpuR, 1) + '%' : '—',
    ]));
  }
  lines.push('');
  return lines;
}

// ── HTB table ─────────────────────────────────────────────────────────────────
function htbTable(htbClasses) {
  if (!htbClasses?.length) return [];
  const lines = [];
  lines.push(row(['Class ID', 'Rate (config)', 'Bytes Sent', 'Pkts', 'Dropped', 'Overlimits', 'Lended', 'Borrowed', 'Tokens', 'cTokens', 'Requeues', 'Giants', 'Calc. Mbps']));
  lines.push(sep(13));
  for (const c of htbClasses) {
    lines.push(row([
      c.class_id, c.rate, fmtK(c.bytes_sent), fmtK(c.packets), fmtK(c.dropped), fmtK(c.overlimits),
      c.lended      != null ? fmtK(c.lended)      : '—',
      c.borrowed_pkt != null ? fmtK(c.borrowed_pkt) : '—',
      c.tokens      != null ? fmtK(c.tokens)      : '—',
      c.ctokens     != null ? fmtK(c.ctokens)     : '—',
      c.requeues    != null ? fmtK(c.requeues)    : '—',
      c.giants      != null ? fmtK(c.giants)      : '—',
      fmt(c.throughput_mbps),
    ]));
  }
  return lines;
}

// ── eBPF table ────────────────────────────────────────────────────────────────
function ebpfTable(ebpfClasses) {
  if (!ebpfClasses?.length) return [];
  const lines = [];
  lines.push(row(['Class Key', 'Class Name', 'Packets', 'Bytes', 'Calc. Mbps', 'Borrowed', 'ECN Marked', 'Delayed']));
  lines.push(sep(8));
  for (const c of ebpfClasses) {
    lines.push(row([
      c.class_key, c.class_name,
      fmtK(c.packets), fmtK(c.bytes),
      fmt(c.throughput_mbps),
      fmtK(c.borrowed), fmtK(c.ecn_marked), fmtK(c.delayed),
    ]));
  }
  return lines;
}

// ── Main builder ──────────────────────────────────────────────────────────────
function buildModeMarkdown(mode) {
  const {
    qos_type: q,
    dataset_name,
    iperf            = {},
    iperfByProtocol  = {},
    cpu              = {},
    htbClasses       = [],
    ebpfClasses      = [],
    htbClassesByProtocol  = {},
    ebpfClassesByProtocol = {},
    timeSeries       = {},
  } = mode;

  const qLabel = MODE_LABELS[q] || q;
  const now = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

  const protocols = Object.keys(iperfByProtocol).filter(p =>
    TC_KEYS.some(tc => iperfByProtocol[p]?.[tc])
  );
  const hasTcp = protocols.includes('tcp');
  const hasUdp = protocols.includes('udp');
  const tcpIperf = iperfByProtocol.tcp || {};
  const udpIperf = iperfByProtocol.udp || {};
  const primaryIperf = hasTcp ? tcpIperf : (hasUdp ? udpIperf : iperf);

  const lines = [];

  lines.push('---');
  lines.push(`title: "${dataset_name} — ${qLabel}"`);
  lines.push(`generated: "${now}"`);
  lines.push(`qos_mode: "${q}"`);
  if (protocols.length) lines.push(`protocols: "${protocols.join(', ')}"`);
  lines.push('---');
  lines.push('');

  lines.push(`# ${qLabel} Mode — Detailed Analysis`);
  lines.push(`**Dataset**: ${dataset_name}`);
  lines.push('');

  // ── 1. Mode Overview ──────────────────────────────────────────────────────
  lines.push(h2('1. Mode Overview'));

  const overviewRows = [
    ['QoS Mode', qLabel],
    ['Protocols tested', protocols.length ? protocols.map(p => p.toUpperCase()).join(', ') : 'TCP (inferred)'],
  ];

  if (q === 'htb') {
    overviewRows.push(
      ['EF target rate', '500 Mbps'], ['AF target rate', '300 Mbps'], ['BE target rate', '200 Mbps'],
      ['HTB mechanism', 'Hierarchical Token Bucket — rate-limited queuing, inter-class lending allowed'],
      ['Enforcement', 'Token-bucket depletion → overlimits or drops; CUBIC adapts for TCP'],
    );
  } else if (q === 'ebpf') {
    overviewRows.push(
      ['EF target rate', '500 Mbps'], ['AF target rate', '300 Mbps'], ['BE target rate', '200 Mbps'],
      ['eBPF mechanism', 'XDP kernel hook — per-packet classification into class keys 0=EF / 1=AF / 2=BE'],
      ['TCP shaping', 'Delay-based + ECN marking for TCP streams'],
      ['UDP shaping', 'Drop-based for EF; delay-based for AF/BE'],
    );
  } else if (q === 'no_qos') {
    overviewRows.push(['QoS mechanism', 'None — baseline measurement, no traffic shaping applied']);
  }

  const durStr = TC_KEYS.map(tc => {
    const d = primaryIperf[tc]?.summary;
    const dur = get(d, 'duration_s', 'durationS');
    return dur != null ? `${tc.toUpperCase()}: ${dur.toFixed(0)} s` : null;
  }).filter(Boolean).join(', ');
  if (durStr) overviewRows.push(['Test duration', durStr]);

  if (htbClasses.length) overviewRows.push(['HTB classes', htbClasses.map(c => c.class_id).join(', ')]);
  if (ebpfClasses.length) overviewRows.push(['eBPF classes', ebpfClasses.map(c => `${c.class_key}=${c.class_name}`).join(', ')]);

  lines.push(row(['Property', 'Value']));
  lines.push(sep(2));
  overviewRows.forEach(([k, v]) => v && lines.push(row([k, v])));
  lines.push('');

  // ── 2. TCP Section ────────────────────────────────────────────────────────
  if (hasTcp || (!hasUdp && Object.keys(primaryIperf).length)) {
    lines.push(h2('2. TCP Traffic Class Analysis'));
    lines.push(...tcpSection(hasTcp ? tcpIperf : primaryIperf, qLabel));
  }

  // ── 3. UDP Section ────────────────────────────────────────────────────────
  if (hasUdp) {
    const udpSectionNum = hasTcp ? 3 : 2;
    lines.push(h2(`${udpSectionNum}. UDP Traffic Class Analysis`));
    lines.push(...udpSection(udpIperf, qLabel));
  }

  const s4 = hasTcp && hasUdp ? 4 : 3;

  // ── HTB Section ───────────────────────────────────────────────────────────
  if (htbClasses.length || Object.keys(htbClassesByProtocol).length) {
    lines.push(h2(`${s4}. HTB TC Class Statistics`));
    lines.push('`tc qdisc` / `tc class` counters accumulated over the test. **Lended/Borrowed** = inter-class bandwidth sharing; **Tokens/cTokens** = remaining token-bucket state at end of test.');
    lines.push('');

    const htbProtos = Object.entries(htbClassesByProtocol);
    if (htbProtos.length) {
      for (const [proto, cls] of htbProtos) {
        lines.push(h3(proto.toUpperCase()));
        lines.push(...htbTable(cls));
        lines.push('');
      }
    } else if (htbClasses.length) {
      lines.push(...htbTable(htbClasses));
      lines.push('');
    }

    if (htbClasses.length) {
      const totalDrops = htbClasses.reduce((s, c) => s + (c.dropped || 0), 0);
      const totalOvlim = htbClasses.reduce((s, c) => s + (c.overlimits || 0), 0);
      const borrowed   = htbClasses.reduce((s, c) => s + (c.borrowed_pkt || 0), 0);
      lines.push(`> **Summary**: ${fmtK(totalDrops)} total drops · ${fmtK(totalOvlim)} overlimits · ${fmtK(borrowed)} borrowed packets.`);
      if (totalDrops === 0) lines.push('> Zero drops — enforcement is purely via overlimit (token-bucket depletion) without queue overflow.');
      lines.push('');
    }
  }

  // ── eBPF Section ──────────────────────────────────────────────────────────
  if (ebpfClasses.length || Object.keys(ebpfClassesByProtocol).length) {
    lines.push(h2(`${s4 + 1}. eBPF XDP Map Statistics`));
    lines.push('Counters from BPF map dumps. Class keys: **0 = EF**, **1 = AF**, **2 = BE**.');
    lines.push('- **Borrowed**: bandwidth lent to this class from another class');
    lines.push('- **ECN Marked**: active congestion notification marks (TCP)');
    lines.push('- **Delayed**: packets held by delay-based shaping scheduler');
    lines.push('');

    const ebpfProtos = Object.entries(ebpfClassesByProtocol);
    if (ebpfProtos.length) {
      for (const [proto, cls] of ebpfProtos) {
        lines.push(h3(proto.toUpperCase()));
        lines.push(...ebpfTable(cls));
        lines.push('');
      }
    } else if (ebpfClasses.length) {
      lines.push(...ebpfTable(ebpfClasses));
      lines.push('');
    }

    if (ebpfClasses.length) {
      const totalEcn = ebpfClasses.reduce((s, c) => s + (Number(c.ecn_marked) || 0), 0);
      const totalDly = ebpfClasses.reduce((s, c) => s + (Number(c.delayed) || 0), 0);
      const totalBrw = ebpfClasses.reduce((s, c) => s + (Number(c.borrowed) || 0), 0);
      lines.push(`> **Summary**: ${fmtK(totalEcn)} ECN marks · ${fmtK(totalDly)} delayed · ${fmtK(totalBrw)} borrowed.`);
      if (totalEcn === 0 && q === 'ebpf') lines.push('> Zero ECN marks — eBPF scheduler in drop mode, not active ECN signalling for these traffic classes.');
      lines.push('');
    }
  }

  // ── CPU Section ───────────────────────────────────────────────────────────
  const snapshots = cpu?.snapshots || [];
  if (snapshots.length) {
    lines.push(h2(`${s4 + 2}. CPU Utilization (SAR)`));
    lines.push('');

    function avg(arr) { return arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : null; }
    function safeN(v) { const n = Number(v); return isNaN(n) ? null : n; }

    const allCpu = snapshots.map(s => ({
      usr:    safeN(s.usr_pct),
      nice:   safeN(s.nice_pct),
      sys:    safeN(s.sys_pct),
      iowait: safeN(s.iowait_pct),
      soft:   safeN(s.soft_pct),
      idle:   safeN(s.idle_pct),
    })).filter(s => s.usr != null);

    if (allCpu.length) {
      const aU  = avg(allCpu.map(s => s.usr));
      const aNi = avg(allCpu.map(s => s.nice).filter(v => v != null));
      const aS  = avg(allCpu.map(s => s.sys));
      const aIo = avg(allCpu.map(s => s.iowait).filter(v => v != null));
      const aSo = avg(allCpu.map(s => s.soft));
      const aId = avg(allCpu.map(s => s.idle));
      const aTo = aId != null ? (100 - aId).toFixed(2) : null;

      lines.push(row(['Metric', 'Average %', 'Notes']));
      lines.push(sep(3));
      if (aU  != null) lines.push(row(['User (usr)',       fmt(aU),  'Application-level CPU']));
      if (aNi != null) lines.push(row(['Nice',             fmt(aNi), 'Low-priority process CPU']));
      if (aS  != null) lines.push(row(['System (sys)',     fmt(aS),  'Kernel syscall CPU']));
      if (aIo != null) lines.push(row(['IOWait',           fmt(aIo), 'CPU stalled on I/O']));
      if (aSo != null) lines.push(row(['Softirq',          fmt(aSo), 'Network stack softIRQ, incl. XDP/NAPI']));
      if (aId != null) lines.push(row(['Idle',             fmt(aId), '']));
      if (aTo != null) lines.push(row(['**Total Active**', `**${aTo}%**`, 'usr+nice+sys+iowait+softirq']));
      lines.push('');

      if (aTo != null) {
        const pct = parseFloat(aTo);
        lines.push(`> **Interpretation**: ${pct < 15 ? 'Low CPU utilization — QoS overhead is negligible.' :
          pct < 35 ? 'Moderate CPU utilization — monitor under higher traffic load.' :
          'High CPU utilization — consider profiling the eBPF/XDP hook and softirq path.'}`);
        lines.push('');
      }
    }

    // iperf3 per-class CPU
    const hasIperfCpu = TC_KEYS.some(tc => {
      const d = primaryIperf[tc]?.summary;
      return d && get(d, 'cpu_host_total', 'cpuHostTotal') != null;
    });
    if (hasIperfCpu) {
      lines.push(h3('iperf3 CPU Report (sender = host, receiver = remote)'));
      lines.push(row(['Class', 'Sender Total%', 'Sender User%', 'Sender Sys%', 'Receiver Total%', 'Receiver User%', 'Receiver Sys%']));
      lines.push(sep(7));
      for (const tc of TC_KEYS) {
        const d = primaryIperf[tc]?.summary;
        if (!d) continue;
        const hT = get(d, 'cpu_host_total',    'cpuHostTotal');
        const hU = get(d, 'cpu_host_user',     'cpuHostUser');
        const hS = get(d, 'cpu_host_system',   'cpuHostSystem');
        const rT = get(d, 'cpu_remote_total',  'cpuRemoteTotal');
        const rU = get(d, 'cpu_remote_user',   'cpuRemoteUser');
        const rS = get(d, 'cpu_remote_system', 'cpuRemoteSystem');
        if (hT == null) continue;
        lines.push(row([
          TC_LABELS[tc] || tc.toUpperCase(),
          fmt(hT), fmt(hU), fmt(hS),
          rT != null ? fmt(rT) : '—',
          rU != null ? fmt(rU) : '—',
          rS != null ? fmt(rS) : '—',
        ]));
      }
      lines.push('');
    }
  }

  // ── Time Series ───────────────────────────────────────────────────────────
  const tsKeys = Object.keys(timeSeries);
  if (tsKeys.length) {
    lines.push(h2(`${s4 + 3}. Time Series (per-second iperf3 intervals)`));
    lines.push(row(['Series', 'Samples', 'Avg Mbps', 'Min Mbps', 'Max Mbps', 'Std Dev', 'CV%', 'Avg RTT (µs)', 'Avg Jitter (ms)']));
    lines.push(sep(9));
    for (const key of tsKeys.sort()) {
      const pts = timeSeries[key];
      if (!pts?.length) continue;
      const bps    = pts.map(p => (p.bitsPerSecond || 0) / 1e6).filter(v => v > 0);
      const rtts   = pts.map(p => p.rttUs).filter(Boolean);
      const jitter = pts.map(p => p.jitterMs).filter(v => v != null);
      const avg    = arr => arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : null;
      const std    = (arr, a) => arr.length > 1 ? Math.sqrt(arr.reduce((s, v) => s + (v - a) ** 2, 0) / arr.length) : null;
      const bAvg   = avg(bps);
      const bStd   = std(bps, bAvg ?? 0);
      lines.push(row([
        key.replace(/_([a-z]+)$/, ' / $1').toUpperCase(),
        pts.length,
        bAvg != null ? bAvg.toFixed(2) : '—',
        bps.length ? Math.min(...bps).toFixed(2) : '—',
        bps.length ? Math.max(...bps).toFixed(2) : '—',
        bStd != null ? bStd.toFixed(2) : '—',
        bAvg && bStd ? (bStd / bAvg * 100).toFixed(1) + '%' : '—',
        avg(rtts)   != null ? avg(rtts).toFixed(0)   : '—',
        avg(jitter) != null ? avg(jitter).toFixed(3) : '—',
      ]));
    }
    lines.push('');
  }

  // ── Analysis & Conclusions ────────────────────────────────────────────────
  lines.push(h2(`${s4 + 4}. Analysis & Conclusions`));

  const conclusions = [];

  const efRtt = get(primaryIperf.ef?.summary, 'avg_rtt_us', 'avgRttUs');
  const afRtt = get(primaryIperf.af?.summary, 'avg_rtt_us', 'avgRttUs');
  const beRtt = get(primaryIperf.be?.summary, 'avg_rtt_us', 'avgRttUs');
  if (efRtt && beRtt) {
    conclusions.push(efRtt < beRtt
      ? `**TCP RTT Priority (Correct)**: EF ${fmt(efRtt, 0)} µs < AF ${afRtt ? fmt(afRtt, 0) : '—'} µs < BE ${fmt(beRtt, 0)} µs. ${qLabel} enforces EF priority correctly.`
      : `**TCP RTT Priority Inversion**: EF ${fmt(efRtt, 0)} µs vs BE ${fmt(beRtt, 0)} µs — EF RTT is NOT lower. Verify traffic class assignment.`);
  }

  const totTcp = TC_KEYS.reduce((s, tc) => {
    return s + (get(primaryIperf[tc]?.summary, 'throughput_mbps', 'throughputMbps') || 0);
  }, 0);
  if (totTcp > 0)
    conclusions.push(`**TCP Link Utilization**: Combined TCP received = ${totTcp.toFixed(0)} Mbps (${((totTcp / 1000) * 100).toFixed(0)}% of 1 Gbps). Remaining capacity = ${(1000 - totTcp).toFixed(0)} Mbps.`);

  const efRetx = get(primaryIperf.ef?.summary, 'retransmits');
  const afRetx = get(primaryIperf.af?.summary, 'retransmits');
  const beRetx = get(primaryIperf.be?.summary, 'retransmits');
  if (efRetx != null) {
    const totalRetx = (efRetx || 0) + (afRetx || 0) + (beRetx || 0);
    conclusions.push(totalRetx === 0
      ? '**TCP Retransmits**: Zero retransmits — CUBIC adapted cleanly to rate limits without induced loss.'
      : `**TCP Retransmits**: EF ${fmtK(efRetx)} / AF ${fmtK(afRetx)} / BE ${fmtK(beRetx)} — ${totalRetx > 100 ? 'significant retransmissions suggest rate enforcement exceeded CUBIC adaptation speed.' : 'low retransmissions.'}`);
  }

  const efCwnd = get(primaryIperf.ef?.summary, 'max_snd_cwnd', 'maxSndCwnd');
  const beCwnd = get(primaryIperf.be?.summary, 'max_snd_cwnd', 'maxSndCwnd');
  if (efCwnd != null && beCwnd != null) {
    conclusions.push(`**CWND**: EF max CWND = ${fmtK(efCwnd)} B vs BE ${fmtK(beCwnd)} B — ${efCwnd > beCwnd ? 'EF maintains larger window, consistent with lower latency' : 'BE maintained larger window; check if EF RTT is actually higher'}.`);
  }

  if (hasUdp) {
    const efUdpD = udpIperf.ef?.summary;
    const beUdpD = udpIperf.be?.summary;
    const efDr   = get(efUdpD, 'delivery_ratio', 'deliveryRatio');
    const beDr   = get(beUdpD, 'delivery_ratio', 'deliveryRatio');
    const efLoss = get(efUdpD, 'lost_percent', 'lostPercent');
    const efJit  = get(efUdpD, 'jitter_ms', 'jitterMs');
    if (efDr != null)
      conclusions.push(`**UDP EF Delivery**: ${fmt(efDr, 1)}% packets delivered${efLoss != null ? ` (${fmt(efLoss, 1)}% lost)` : ''}${efJit != null ? `, jitter ${fmt(efJit, 3)} ms` : ''}.`);
    if (efDr != null && beDr != null && efDr < beDr && q === 'ebpf')
      conclusions.push(`**eBPF UDP Priority Inversion**: EF delivery ${fmt(efDr, 1)}% < BE ${fmt(beDr, 1)}%. EF uses drop-based enforcement; BE uses delay-based — higher EF loss. Recommendation: adjust EF UDP rate or switch to delay-based scheduling.`);

    for (const tc of TC_KEYS) {
      const d    = udpIperf[tc]?.summary;
      const sent = get(d, 'sent_throughput_mbps', 'sentThroughputMbps');
      const rcv  = get(d, 'throughput_mbps', 'throughputMbps');
      if (sent != null && rcv != null && sent > 0) {
        const pct = ((sent - rcv) / sent * 100).toFixed(1);
        if (parseFloat(pct) > 5)
          conclusions.push(`**UDP ${tc.toUpperCase()} Shaping**: Sent ${fmt(sent)} Mbps → Received ${fmt(rcv)} Mbps — ${pct}% dropped by ${qLabel}.`);
      }
    }
  }

  if (htbClasses.length) {
    const drops = htbClasses.reduce((s, c) => s + (c.dropped || 0), 0);
    const ovlim = htbClasses.reduce((s, c) => s + (c.overlimits || 0), 0);
    const brw   = htbClasses.reduce((s, c) => s + (c.borrowed_pkt || 0), 0);
    conclusions.push(drops === 0
      ? `**HTB Enforcement**: Clean — ${fmtK(ovlim)} overlimits, zero drops. Token-bucket depletion only.`
      : `**HTB Enforcement**: ${fmtK(drops)} drops + ${fmtK(ovlim)} overlimits — rate limits exceeded.`);
    if (brw > 0)
      conclusions.push(`**HTB Borrowing**: ${fmtK(brw)} packets borrowed between classes — inter-class lending is active.`);
  }

  if (ebpfClasses.length) {
    const ecn = ebpfClasses.reduce((s, c) => s + (Number(c.ecn_marked) || 0), 0);
    const dly = ebpfClasses.reduce((s, c) => s + (Number(c.delayed) || 0), 0);
    if (ecn > 0)
      conclusions.push(`**eBPF ECN**: ${fmtK(ecn)} ECN marks — XDP scheduler signals congestion to TCP without dropping packets.`);
    if (dly > 0)
      conclusions.push(`**eBPF Delay Scheduler**: ${fmtK(dly)} delayed events — packets held by delay-based shaping (preserved delivery at cost of latency).`);
    if (ecn === 0 && dly === 0)
      conclusions.push('**eBPF Scheduler**: Zero ECN marks and zero delayed events — enforcement is drop-based or traffic stayed within limits.');
  }

  if (!conclusions.length)
    conclusions.push('Insufficient data for automated analysis. Re-upload experiment files after applying the DB migration to populate new metric fields.');

  conclusions.forEach((c, i) => lines.push(`${i + 1}. ${c}`));
  lines.push('');

  lines.push('---');
  lines.push(`*Report generated by eBPF QoS Research Platform · ${now}*`);
  lines.push('');

  return lines.join('\n');
}

module.exports = { buildModeMarkdown };
