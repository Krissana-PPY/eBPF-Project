'use strict';

const { mean, std } = require('./stats');

// ── Detect file type from filename ─────────────────────────────────────────
function detectFileType(filename) {
  const name = filename.replace(/\s*\(\d+\)\s*/g, '').toLowerCase().trim();
  const QOS   = ['no_qos', 'htb', 'ebpf'];
  const TC    = ['ef', 'af', 'be'];
  const PROTO = ['tcp', 'udp'];

  let qosType = null;
  for (const q of QOS.sort((a, b) => b.length - a.length)) {
    if (name.startsWith(q + '_')) { qosType = q; break; }
  }
  if (!qosType) return null;

  let protocol = null;
  for (const p of PROTO) {
    if (name.includes('_' + p + '_') || name.includes('_' + p + '.')) {
      protocol = p; break;
    }
  }

  if (name.includes('ebpf_stats') && name.endsWith('.json'))
    return { qosType, protocol, trafficClass: null, experimentType: 'ebpf_map' };
  if (name.includes('tc_stats') && name.endsWith('.txt'))
    return { qosType, protocol, trafficClass: null, experimentType: 'htb_tc' };
  if (name.includes('cpu') && name.endsWith('.txt'))
    return { qosType, protocol, trafficClass: null, experimentType: 'cpu' };

  for (const tc of TC) {
    if (name.endsWith(`_${tc}.json`) || name.includes(`_${tc}.`))
      return { qosType, protocol, trafficClass: tc, experimentType: 'iperf' };
  }
  return null;
}

// ── iperf3 JSON parser ──────────────────────────────────────────────────────
function parseIperf(text) {
  const data     = JSON.parse(text);
  const end      = data.end || {};
  const received = end.sum_received || {};
  const sent     = end.sum_sent     || {};
  const cpu      = end.cpu_utilization_percent || {};

  // TCP stream-level stats (stream 0, sender side)
  const streamSender = (end.streams || [])[0]?.sender || {};
  const tcpCongestion = streamSender.sender_tcp_congestion || null;

  const intervals = (data.intervals || []).map(iv => {
    const s   = (iv.streams || [])[0] || {};
    const sum = iv.sum || {};
    return {
      start:         sum.start,
      end:           sum.end,
      bytes:         sum.bytes,
      bitsPerSecond: sum.bits_per_second,
      retransmits:   sum.retransmits || 0,
      rttUs:         s.rtt ?? null,
    };
  });

  const rtts = intervals.map(i => i.rttUs).filter(v => v != null && v > 0);

  const sentBytes = sent.bytes ?? 0;
  const rcvBytes  = received.bytes ?? sentBytes;

  return {
    summary: {
      // ── receiver side (post-shaping goodput) ──
      throughputMbps:     (received.bits_per_second ?? sent.bits_per_second) / 1e6 || 0,
      rcvBytes,
      // ── sender side (pre-shaping application rate) ──
      sentThroughputMbps: sent.bits_per_second / 1e6 || 0,
      sentBytes,
      // ── delivery efficiency ──
      deliveryRatio:      sentBytes > 0 ? Math.min(100, (rcvBytes / sentBytes) * 100) : 100,
      // ── RTT (TCP only — sender via ACK, bidirectional) ──
      avgRttUs:           mean(rtts),
      maxRttUs:           Math.max(...rtts, 0),
      minRttUs:           rtts.length ? Math.min(...rtts) : 0,
      rttStdUs:           std(rtts),
      // ── sender TCP congestion window (TCP only) ──
      maxSndCwnd:         streamSender.max_snd_cwnd   ?? null,
      maxSndWnd:          streamSender.max_snd_wnd    ?? null,
      tcpCongestion,
      // ── sender counters ──
      retransmits:        sent.retransmits || 0,
      durationS:          received.seconds || sent.seconds || 0,
      // ── iperf3 host (sender) CPU ──
      cpuHostTotal:       cpu.host_total  || 0,
      cpuHostUser:        cpu.host_user   || 0,
      cpuHostSystem:      cpu.host_system || 0,
      // ── iperf3 remote (receiver) CPU ──
      cpuRemoteTotal:     cpu.remote_total  || 0,
      cpuRemoteUser:      cpu.remote_user   || 0,
      cpuRemoteSystem:    cpu.remote_system || 0,
      // ── UDP-specific (receiver side) ──
      jitterMs:           received.jitter_ms    ?? null,
      lostPackets:        received.lost_packets ?? null,
      rcvPackets:         received.packets      ?? null,
      sentPackets:        sent.packets          ?? null,
      lostPercent:        received.lost_percent ?? null,
    },
    intervals,
  };
}

// ── SAR CPU txt parser ──────────────────────────────────────────────────────
// mpstat -P ALL 1 output — columns (0-indexed after trim + split):
//   0=time  1=CPU  2=%usr  3=%nice  4=%sys  5=%iowait  6=%irq  7=%soft
//   8=%steal  9=%guest  10=%gnice  11=%idle
function parseCpu(text) {
  const lines     = text.split('\n');
  const snapshots = [];
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 12 && parts[1] === 'all') {
      snapshots.push({
        snapshotTime: parts[0],
        cpuCore:      'all',
        usrPct:       parseFloat(parts[2])  || 0,
        nicePct:      parseFloat(parts[3])  || 0,
        sysPct:       parseFloat(parts[4])  || 0,
        iowaitPct:    parseFloat(parts[5])  || 0,
        softPct:      parseFloat(parts[7])  || 0,   // parts[6]=irq, parts[7]=soft
        idlePct:      parseFloat(parts[11]) || 0,   // parts[11]=idle (not parts[10] which is gnice)
      });
    }
  }
  return { snapshots };
}

// ── HTB tc stats txt parser ─────────────────────────────────────────────────
function parseHtbTc(text) {
  const classes = [];
  const blocks  = text.trim().split(/\n(?=class htb)/);
  for (const block of blocks) {
    const rateM    = block.match(/class htb (\S+).*?rate (\S+)/);
    const sentM    = block.match(/Sent (\d+) bytes (\d+) pkt \(dropped (\d+), overlimits (\d+)[^)]*\)/);
    const lentM    = block.match(/lended:\s*(\d+)\s+borrowed:\s*(\d+)/);
    const tokensM  = block.match(/tokens:\s*(-?\d+)\s+ctokens:\s*(-?\d+)/);
    const reqM     = block.match(/requeues:\s*(\d+)/);
    const giantM   = block.match(/giants:\s*(\d+)/);
    if (rateM && sentM) {
      classes.push({
        classId:    rateM[1],
        rate:       rateM[2],
        bytesSent:  parseInt(sentM[1]),
        packets:    parseInt(sentM[2]),
        dropped:    parseInt(sentM[3]),
        overlimits: parseInt(sentM[4]),
        lended:     lentM    ? parseInt(lentM[1])    : 0,
        borrowedPkt:lentM    ? parseInt(lentM[2])    : 0,
        tokens:     tokensM  ? parseInt(tokensM[1])  : 0,
        ctokens:    tokensM  ? parseInt(tokensM[2])  : 0,
        requeues:   reqM     ? parseInt(reqM[1])     : 0,
        giants:     giantM   ? parseInt(giantM[1])   : 0,
      });
    }
  }
  return { classes };
}

// ── eBPF map JSON parser ────────────────────────────────────────────────────
const EBPF_CLASS_NAMES = { 0: 'EF', 1: 'AF', 2: 'BE' };

function parseEbpfMap(text) {
  const data    = JSON.parse(text);
  const classes = data.map(entry => ({
    classKey:  entry.key,
    className: EBPF_CLASS_NAMES[entry.key] || `class_${entry.key}`,
    packets:   entry.value.packets    || 0,
    bytes:     entry.value.bytes      || 0,
    borrowed:  entry.value.borrowed   || 0,
    ecnMarked: entry.value.ecn_marked || 0,
    delayed:   entry.value.delayed    || 0,
  }));
  return { classes };
}

// ── Main parse dispatch ─────────────────────────────────────────────────────
function parseFile(filename, buffer) {
  const meta = detectFileType(filename);
  if (!meta) throw new Error(`Unrecognised filename pattern: ${filename}`);
  const text = buffer.toString('utf-8');
  switch (meta.experimentType) {
    case 'iperf':    return { meta, data: parseIperf(text) };
    case 'cpu':      return { meta, data: parseCpu(text) };
    case 'htb_tc':   return { meta, data: parseHtbTc(text) };
    case 'ebpf_map': return { meta, data: parseEbpfMap(text) };
    default: throw new Error(`Unknown experiment type: ${meta.experimentType}`);
  }
}

module.exports = { parseFile, detectFileType };
