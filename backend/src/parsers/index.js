'use strict';

const { mean, std } = require('./stats'); // eslint-disable-line

// ── Detect file type from filename ─────────────────────────────────────────
function detectFileType(filename) {
  const name = filename.replace(/\s*\(\d+\)\s*/g, '').toLowerCase().trim();
  const QOS  = ['no_qos', 'htb', 'ebpf'];
  const TC   = ['ef', 'af', 'be'];

  let qosType = null;
  for (const q of QOS.sort((a, b) => b.length - a.length)) {
    if (name.startsWith(q + '_')) { qosType = q; break; }
  }
  if (!qosType) return null;

  if (name.includes('ebpf_stats') && name.endsWith('.json'))
    return { qosType, trafficClass: null, experimentType: 'ebpf_map' };

  if (name.includes('tc_stats') && name.endsWith('.txt'))
    return { qosType, trafficClass: null, experimentType: 'htb_tc' };

  if (name.includes('cpu') && name.endsWith('.txt'))
    return { qosType, trafficClass: null, experimentType: 'cpu' };

  // iperf JSON: {qos}_tcp_{class}.json
  for (const tc of TC) {
    if (name.endsWith(`_${tc}.json`) || name.includes(`_${tc}.`))
      return { qosType, trafficClass: tc, experimentType: 'iperf' };
  }

  return null;
}

// ── iperf3 JSON parser ──────────────────────────────────────────────────────
function parseIperf(text) {
  const data = JSON.parse(text);
  const end  = data.end || {};
  const sent = end.sum_sent || {};
  const cpu  = end.cpu_utilization_percent || {};

  const intervals = (data.intervals || []).map(iv => {
    const s   = (iv.streams || [])[0] || {};
    const sum = iv.sum || {};
    return {
      start:         sum.start,
      end:           sum.end,
      bytes:         sum.bytes,
      bitsPerSecond: sum.bits_per_second,
      retransmits:   sum.retransmits || 0,
      rttUs:         s.rtt,
    };
  });

  const rtts  = intervals.map(i => i.rttUs).filter(Boolean);
  const bpss  = intervals.map(i => i.bitsPerSecond).filter(Boolean);

  return {
    summary: {
      throughputMbps:  sent.bits_per_second / 1e6 || 0,
      avgRttUs:        mean(rtts),
      maxRttUs:        Math.max(...rtts, 0),
      minRttUs:        Math.min(...rtts, Infinity) === Infinity ? 0 : Math.min(...rtts),
      rttStdUs:        std(rtts),
      retransmits:     sent.retransmits || 0,
      durationS:       sent.seconds || 0,
      cpuHostTotal:    cpu.host_total || 0,
      cpuHostUser:     cpu.host_user || 0,
      cpuHostSystem:   cpu.host_system || 0,
      cpuRemoteTotal:  cpu.remote_total || 0,
    },
    intervals,
  };
}

// ── SAR CPU txt parser ──────────────────────────────────────────────────────
function parseCpu(text) {
  const lines    = text.split('\n');
  const snapshots = [];
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 11 && parts[1] === 'all') {
      snapshots.push({
        snapshotTime: parts[0],
        cpuCore:      'all',
        usrPct:       parseFloat(parts[2])  || 0,
        sysPct:       parseFloat(parts[4])  || 0,
        softPct:      parseFloat(parts[6])  || 0,
        idlePct:      parseFloat(parts[10]) || 0,
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
    const rateM = block.match(/class htb (\S+).*?rate (\S+)/);
    const sentM = block.match(/Sent (\d+) bytes (\d+) pkt \(dropped (\d+), overlimits (\d+)/);
    if (rateM && sentM) {
      classes.push({
        classId:    rateM[1],
        rate:       rateM[2],
        bytesSent:  parseInt(sentM[1]),
        packets:    parseInt(sentM[2]),
        dropped:    parseInt(sentM[3]),
        overlimits: parseInt(sentM[4]),
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
    packets:   entry.value.packets   || 0,
    bytes:     entry.value.bytes     || 0,
    borrowed:  entry.value.borrowed  || 0,
    ecnMarked: entry.value.ecn_marked || 0,
    delayed:   entry.value.delayed   || 0,
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
