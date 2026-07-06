'use strict';

const { Router }        = require('express');
const { pool }          = require('../db');
const { buildMarkdown }     = require('../report/markdown');
const { buildModeMarkdown } = require('../report/mode-markdown');

const router = Router();

// ── Shared row → object builders ───────────────────────────────────────────
function mkIperfMetric(row) {
  return {
    // receiver (post-shaping goodput)
    throughputMbps:     row.throughput_mbps,
    rcvBytes:           Number(row.rcv_bytes)  ?? 0,
    // sender (pre-shaping application rate)
    sentThroughputMbps: row.sent_throughput_mbps,
    sentBytes:          Number(row.sent_bytes) ?? 0,
    // delivery efficiency
    deliveryRatio:      row.delivery_ratio,
    // RTT (TCP only)
    avgRttUs:           row.avg_rtt_us,
    maxRttUs:           row.max_rtt_us,
    minRttUs:           row.min_rtt_us,
    rttStdUs:           row.rtt_std_us,
    // TCP congestion window
    maxSndCwnd:         row.max_snd_cwnd,
    maxSndWnd:          row.max_snd_wnd,
    tcpCongestion:      row.tcp_congestion,
    // sender counters
    retransmits:        row.retransmits,
    durationS:          row.duration_s,
    // host (sender) CPU from iperf3
    cpuHostTotal:       row.cpu_host_total,
    cpuHostUser:        row.cpu_host_user,
    cpuHostSystem:      row.cpu_host_system,
    // remote (receiver) CPU from iperf3
    cpuRemoteTotal:     row.cpu_remote_total,
    cpuRemoteUser:      row.cpu_remote_user,
    cpuRemoteSystem:    row.cpu_remote_system,
    // UDP-specific
    jitterMs:           row.jitter_ms,
    lostPackets:        row.lost_packets != null ? Number(row.lost_packets) : null,
    sentPackets:        row.sent_packets != null ? Number(row.sent_packets) : null,
    rcvPackets:         row.rcv_packets  != null ? Number(row.rcv_packets)  : null,
    lostPercent:        row.lost_percent,
  };
}

function mkCpuMetric(row) {
  const usr    = row.avg_usr    || 0;
  const sys    = row.avg_sys    || 0;
  const soft   = row.avg_soft   || 0;
  const iowait = row.avg_iowait || 0;
  const nice   = row.avg_nice   || 0;
  return {
    avgUsr:    usr,
    avgNice:   nice,
    avgSys:    sys,
    avgIowait: iowait,
    avgSoft:   soft,
    avgIdle:   row.avg_idle || 0,
    avgTotal:  usr + sys + soft + iowait + nice,
    samples:   row.samples,
  };
}

function mkHtbClass(row) {
  return {
    rate:          row.rate,
    bytesSent:     row.bytes_sent,
    packets:       row.packets,
    dropped:       row.dropped,
    overlimits:    row.overlimits,
    lended:        row.lended       ?? 0,
    borrowedPkt:   row.borrowed_pkt ?? 0,
    tokens:        row.tokens       ?? 0,
    ctokens:       row.ctokens      ?? 0,
    requeues:      row.requeues     ?? 0,
    giants:        row.giants       ?? 0,
    throughputMbps: (row.bytes_sent * 8) / 30 / 1e6,
  };
}

// ── GET /datasets — list all datasets ──────────────────────────────────────
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT d.id, d.name, d.description, d.created_at,
              COUNT(DISTINCT e.id)::int AS experiment_count
       FROM datasets d
       LEFT JOIN experiments e ON e.dataset_id = d.id
       GROUP BY d.id
       ORDER BY d.created_at DESC`
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// ── POST /datasets — create dataset ────────────────────────────────────────
router.post('/', async (req, res, next) => {
  const { name, description } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'name is required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO datasets (name, description) VALUES ($1, $2) RETURNING *`,
      [name.trim(), description?.trim() || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

// ── GET /datasets/:id — full detail with aggregated metrics ────────────────
router.get('/:id', async (req, res, next) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'invalid id' });

  try {
    const dsRes = await pool.query('SELECT * FROM datasets WHERE id = $1', [id]);
    if (!dsRes.rows.length) return res.status(404).json({ error: 'Dataset not found' });

    const dataset = dsRes.rows[0];

    // detect which protocols exist in this dataset (no COALESCE — preserve NULL)
    const protoRes = await pool.query(
      `SELECT DISTINCT protocol FROM experiments WHERE dataset_id = $1`, [id]
    );
    const protocols = protoRes.rows.map(r => r.protocol).filter(Boolean);
    // prefer tcp; fall back to first found; null means legacy rows with no protocol column
    const primaryProto = protocols.includes('tcp') ? 'tcp' : (protocols[0] || null);

    // iperf summaries — filter by primary protocol to avoid TCP/UDP mixing
    const iperfRes = await pool.query(
      `SELECT e.qos_type, e.protocol, e.traffic_class, s.*
       FROM iperf_summary s
       JOIN experiments e ON e.id = s.experiment_id
       WHERE e.dataset_id = $1
         AND (e.protocol = $2 OR ($2 IS NULL AND e.protocol IS NULL))`,
      [id, primaryProto]
    );

    // cpu snapshots — aggregate per qos+protocol
    const cpuRes = await pool.query(
      `SELECT e.qos_type, e.protocol,
              AVG(c.usr_pct)::float     AS avg_usr,
              AVG(c.nice_pct)::float    AS avg_nice,
              AVG(c.sys_pct)::float     AS avg_sys,
              AVG(c.iowait_pct)::float  AS avg_iowait,
              AVG(c.soft_pct)::float    AS avg_soft,
              AVG(c.idle_pct)::float    AS avg_idle,
              COUNT(*)::int             AS samples
       FROM cpu_snapshots c
       JOIN experiments e ON e.id = c.experiment_id
       WHERE e.dataset_id = $1
         AND (e.protocol = $2 OR ($2 IS NULL AND e.protocol IS NULL))
       GROUP BY e.qos_type, e.protocol`,
      [id, primaryProto]
    );

    // HTB tc classes
    const htbRes = await pool.query(
      `SELECT h.*
       FROM htb_class_stats h
       JOIN experiments e ON e.id = h.experiment_id
       WHERE e.dataset_id = $1
         AND (e.protocol = $2 OR ($2 IS NULL AND e.protocol IS NULL))`,
      [id, primaryProto]
    );

    // eBPF map stats
    const ebpfRes = await pool.query(
      `SELECT m.*
       FROM ebpf_class_stats m
       JOIN experiments e ON e.id = m.experiment_id
       WHERE e.dataset_id = $1
         AND (e.protocol = $2 OR ($2 IS NULL AND e.protocol IS NULL))`,
      [id, primaryProto]
    );

    // iperf intervals for time series
    const intervalRes = await pool.query(
      `SELECT e.qos_type, e.protocol, e.traffic_class, i.interval_start, i.interval_end,
              i.bits_per_second, i.rtt_us, i.retransmits
       FROM iperf_intervals i
       JOIN experiments e ON e.id = i.experiment_id
       WHERE e.dataset_id = $1
         AND (e.protocol = $2 OR ($2 IS NULL AND e.protocol IS NULL))
       ORDER BY e.qos_type, e.traffic_class, i.interval_start`,
      [id, primaryProto]
    );

    // build metrics object keyed by qos_type
    const metrics = {};
    for (const row of iperfRes.rows) {
      const q  = row.qos_type;
      const tc = row.traffic_class;
      if (!metrics[q]) metrics[q] = {};
      metrics[q][tc] = mkIperfMetric(row);
    }

    for (const row of cpuRes.rows) {
      const q = row.qos_type;
      if (!metrics[q]) metrics[q] = {};
      metrics[q].cpu = mkCpuMetric(row);
    }

    if (htbRes.rows.length) {
      if (!metrics.htb) metrics.htb = {};
      metrics.htb.tcClasses = {};
      for (const row of htbRes.rows) {
        metrics.htb.tcClasses[row.class_id] = mkHtbClass(row);
      }
    }

    if (ebpfRes.rows.length) {
      if (!metrics.ebpf) metrics.ebpf = {};
      metrics.ebpf.mapStats = {};
      for (const row of ebpfRes.rows) {
        metrics.ebpf.mapStats[row.class_name] = {
          classKey:      row.class_key,
          packets:       row.packets,
          bytes:         row.bytes,
          borrowed:      row.borrowed,
          ecnMarked:     row.ecn_marked,
          delayed:       row.delayed,
          throughputMbps: (row.bytes * 8) / 30 / 1e6,
        };
      }
    }

    // time series grouped by qos + traffic_class
    const timeSeries = {};
    for (const row of intervalRes.rows) {
      const key = `${row.qos_type}_${row.traffic_class}`;
      if (!timeSeries[key]) timeSeries[key] = [];
      timeSeries[key].push({
        t:            row.interval_start,
        bitsPerSecond: row.bits_per_second,
        rttUs:         row.rtt_us,
        retransmits:   row.retransmits,
      });
    }

    // ── Multi-protocol data (TCP + UDP) for comprehensive analysis ──────────
    const [mpIperfRes, mpCpuRes, mpIntervalRes, mpHtbRes, mpEbpfRes] = await Promise.all([
      pool.query(
        `SELECT e.qos_type, e.protocol, e.traffic_class, s.*
         FROM iperf_summary s JOIN experiments e ON e.id = s.experiment_id
         WHERE e.dataset_id = $1 AND e.protocol IS NOT NULL`, [id]),
      pool.query(
        `SELECT e.qos_type, e.protocol,
                AVG(c.usr_pct)::float    AS avg_usr,
                AVG(c.nice_pct)::float   AS avg_nice,
                AVG(c.sys_pct)::float    AS avg_sys,
                AVG(c.iowait_pct)::float AS avg_iowait,
                AVG(c.soft_pct)::float   AS avg_soft,
                AVG(c.idle_pct)::float   AS avg_idle,
                COUNT(*)::int            AS samples
         FROM cpu_snapshots c JOIN experiments e ON e.id = c.experiment_id
         WHERE e.dataset_id = $1 AND e.protocol IS NOT NULL
         GROUP BY e.qos_type, e.protocol`, [id]),
      pool.query(
        `SELECT e.qos_type, e.protocol, e.traffic_class, i.interval_start, i.interval_end,
                i.bits_per_second, i.rtt_us, i.retransmits
         FROM iperf_intervals i JOIN experiments e ON e.id = i.experiment_id
         WHERE e.dataset_id = $1 AND e.protocol IS NOT NULL
         ORDER BY e.protocol, e.qos_type, e.traffic_class, i.interval_start`, [id]),
      pool.query(
        `SELECT e.protocol, h.*
         FROM htb_class_stats h JOIN experiments e ON e.id = h.experiment_id
         WHERE e.dataset_id = $1 AND e.protocol IS NOT NULL
         ORDER BY e.protocol, h.class_id`, [id]),
      pool.query(
        `SELECT e.protocol, m.*
         FROM ebpf_class_stats m JOIN experiments e ON e.id = m.experiment_id
         WHERE e.dataset_id = $1 AND e.protocol IS NOT NULL
         ORDER BY e.protocol, m.class_key`, [id]),
    ]);

    const metricsByProtocol = {};
    for (const row of mpIperfRes.rows) {
      const { protocol: p, qos_type: q, traffic_class: tc } = row;
      if (!metricsByProtocol[p]) metricsByProtocol[p] = {};
      if (!metricsByProtocol[p][q]) metricsByProtocol[p][q] = {};
      metricsByProtocol[p][q][tc] = mkIperfMetric(row);
    }
    for (const row of mpCpuRes.rows) {
      const { protocol: p, qos_type: q } = row;
      if (!metricsByProtocol[p]) metricsByProtocol[p] = {};
      if (!metricsByProtocol[p][q]) metricsByProtocol[p][q] = {};
      metricsByProtocol[p][q].cpu = mkCpuMetric(row);
    }
    for (const row of mpHtbRes.rows) {
      const p = row.protocol;
      if (!metricsByProtocol[p]) metricsByProtocol[p] = {};
      if (!metricsByProtocol[p].htb) metricsByProtocol[p].htb = {};
      if (!metricsByProtocol[p].htb.tcClasses) metricsByProtocol[p].htb.tcClasses = {};
      metricsByProtocol[p].htb.tcClasses[row.class_id] = mkHtbClass(row);
    }
    for (const row of mpEbpfRes.rows) {
      const p = row.protocol;
      if (!metricsByProtocol[p]) metricsByProtocol[p] = {};
      if (!metricsByProtocol[p].ebpf) metricsByProtocol[p].ebpf = {};
      if (!metricsByProtocol[p].ebpf.mapStats) metricsByProtocol[p].ebpf.mapStats = {};
      metricsByProtocol[p].ebpf.mapStats[row.class_name] = {
        classKey: row.class_key, packets: row.packets, bytes: row.bytes,
        borrowed: row.borrowed, ecnMarked: row.ecn_marked, delayed: row.delayed,
        throughputMbps: (row.bytes * 8) / 30 / 1e6,
      };
    }
    const timeSeriesByProtocol = {};
    for (const row of mpIntervalRes.rows) {
      const p   = row.protocol;
      const key = `${row.qos_type}_${row.traffic_class}`;
      if (!timeSeriesByProtocol[p]) timeSeriesByProtocol[p] = {};
      if (!timeSeriesByProtocol[p][key]) timeSeriesByProtocol[p][key] = [];
      timeSeriesByProtocol[p][key].push({
        t: row.interval_start, bitsPerSecond: row.bits_per_second,
        rttUs: row.rtt_us, retransmits: row.retransmits,
      });
    }

    res.json({ ...dataset, protocols, primaryProtocol: primaryProto, metrics, metricsByProtocol, timeSeriesByProtocol, timeSeries });
  } catch (err) { next(err); }
});

// ── GET /datasets/:id/mode/:qosType — single-mode analysis ────────────────
router.get('/:id/mode/:qosType', async (req, res, next) => {
  const id      = parseInt(req.params.id);
  const qosType = req.params.qosType;
  if (isNaN(id)) return res.status(400).json({ error: 'invalid id' });
  if (!['no_qos', 'htb', 'ebpf'].includes(qosType))
    return res.status(400).json({ error: 'qosType must be no_qos | htb | ebpf' });

  try {
    const dsRes = await pool.query('SELECT * FROM datasets WHERE id = $1', [id]);
    if (!dsRes.rows.length) return res.status(404).json({ error: 'Dataset not found' });
    const dataset = dsRes.rows[0];

    // Detect primary protocol (prefer tcp) to avoid mixing TCP/UDP iperf data
    const protoRes = await pool.query(
      `SELECT DISTINCT protocol FROM experiments WHERE dataset_id = $1 AND qos_type = $2 AND protocol IS NOT NULL`,
      [id, qosType]
    );
    const protos = protoRes.rows.map(r => r.protocol);
    const primaryProto = protos.includes('tcp') ? 'tcp' : (protos[0] || null);

    const [iperfRes, intervalsRes, cpuRes, htbRes, ebpfRes] = await Promise.all([
      pool.query(
        `SELECT e.traffic_class, s.*
         FROM iperf_summary s JOIN experiments e ON e.id = s.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2
           AND (e.protocol = $3 OR ($3 IS NULL AND e.protocol IS NULL))`, [id, qosType, primaryProto]),
      pool.query(
        `SELECT e.traffic_class, i.*
         FROM iperf_intervals i JOIN experiments e ON e.id = i.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2
           AND (e.protocol = $3 OR ($3 IS NULL AND e.protocol IS NULL))
         ORDER BY e.traffic_class, i.interval_start`, [id, qosType, primaryProto]),
      pool.query(
        `SELECT c.* FROM cpu_snapshots c JOIN experiments e ON e.id = c.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2
           AND (e.protocol = $3 OR ($3 IS NULL AND e.protocol IS NULL))
         ORDER BY c.id`, [id, qosType, primaryProto]),
      pool.query(
        `SELECT h.* FROM htb_class_stats h JOIN experiments e ON e.id = h.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2
           AND (e.protocol = $3 OR ($3 IS NULL AND e.protocol IS NULL))
         ORDER BY h.class_id`, [id, qosType, primaryProto]),
      pool.query(
        `SELECT m.* FROM ebpf_class_stats m JOIN experiments e ON e.id = m.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2
           AND (e.protocol = $3 OR ($3 IS NULL AND e.protocol IS NULL))
         ORDER BY m.class_key`, [id, qosType, primaryProto]),
    ]);

    // snake_case summary row builder (used by mode endpoint for iperfByProtocol)
    const mkS = (row) => ({
      throughput_mbps:      row.throughput_mbps,
      rcv_bytes:            row.rcv_bytes != null ? Number(row.rcv_bytes) : 0,
      sent_throughput_mbps: row.sent_throughput_mbps,
      sent_bytes:           row.sent_bytes != null ? Number(row.sent_bytes) : 0,
      delivery_ratio:       row.delivery_ratio,
      avg_rtt_us:           row.avg_rtt_us,
      max_rtt_us:           row.max_rtt_us,
      min_rtt_us:           row.min_rtt_us,
      rtt_std_us:           row.rtt_std_us,
      max_snd_cwnd:         row.max_snd_cwnd,
      max_snd_wnd:          row.max_snd_wnd,
      tcp_congestion:       row.tcp_congestion,
      retransmits:          row.retransmits,
      duration_s:           row.duration_s,
      cpu_host_total:       row.cpu_host_total,
      cpu_host_user:        row.cpu_host_user,
      cpu_host_system:      row.cpu_host_system,
      cpu_remote_total:     row.cpu_remote_total,
      cpu_remote_user:      row.cpu_remote_user,
      cpu_remote_system:    row.cpu_remote_system,
      jitter_ms:            row.jitter_ms,
      lost_packets:         row.lost_packets != null ? Number(row.lost_packets) : null,
      sent_packets:         row.sent_packets != null ? Number(row.sent_packets) : null,
      rcv_packets:          row.rcv_packets  != null ? Number(row.rcv_packets)  : null,
      lost_percent:         row.lost_percent,
    });

    // Build iperf object keyed by traffic_class
    const iperf = {};
    for (const row of iperfRes.rows) {
      const tc = row.traffic_class;
      iperf[tc] = { summary: mkS(row), intervals: [] };
    }
    for (const row of intervalsRes.rows) {
      const tc = row.traffic_class;
      if (!iperf[tc]) iperf[tc] = { summary: null, intervals: [] };
      iperf[tc].intervals.push({
        id: row.id, interval_start: row.interval_start, interval_end: row.interval_end,
        bits_per_second: row.bits_per_second, rtt_us: row.rtt_us, retransmits: row.retransmits,
      });
    }

    // Time series (same shape as dataset endpoint)
    const timeSeries = {};
    for (const row of intervalsRes.rows) {
      const key = `${qosType}_${row.traffic_class}`;
      if (!timeSeries[key]) timeSeries[key] = [];
      timeSeries[key].push({ t: row.interval_start, bitsPerSecond: row.bits_per_second, rttUs: row.rtt_us, retransmits: row.retransmits });
    }

    // ── Multi-protocol data for this mode (TCP + UDP) ──────────────────────
    const [mpModeIperfRes, mpModeIntRes, mpModeCpuRes, mpModeHtbRes, mpModeEbpfRes] = await Promise.all([
      pool.query(
        `SELECT e.protocol, e.traffic_class, s.*
         FROM iperf_summary s JOIN experiments e ON e.id = s.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2 AND e.protocol IS NOT NULL`,
        [id, qosType]),
      pool.query(
        `SELECT e.protocol, e.traffic_class, i.*
         FROM iperf_intervals i JOIN experiments e ON e.id = i.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2 AND e.protocol IS NOT NULL
         ORDER BY e.protocol, e.traffic_class, i.interval_start`,
        [id, qosType]),
      pool.query(
        `SELECT e.protocol, c.*
         FROM cpu_snapshots c JOIN experiments e ON e.id = c.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2 AND e.protocol IS NOT NULL
         ORDER BY e.protocol, c.id`,
        [id, qosType]),
      pool.query(
        `SELECT e.protocol, h.*
         FROM htb_class_stats h JOIN experiments e ON e.id = h.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2 AND e.protocol IS NOT NULL
         ORDER BY e.protocol, h.class_id`,
        [id, qosType]),
      pool.query(
        `SELECT e.protocol, m.*
         FROM ebpf_class_stats m JOIN experiments e ON e.id = m.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2 AND e.protocol IS NOT NULL
         ORDER BY e.protocol, m.class_key`,
        [id, qosType]),
    ]);

    const iperfByProtocol = {};
    for (const row of mpModeIperfRes.rows) {
      const { protocol: p, traffic_class: tc } = row;
      if (!iperfByProtocol[p]) iperfByProtocol[p] = {};
      iperfByProtocol[p][tc] = { summary: mkS(row), intervals: [] };
    }
    for (const row of mpModeIntRes.rows) {
      const { protocol: p, traffic_class: tc } = row;
      if (!iperfByProtocol[p]) iperfByProtocol[p] = {};
      if (!iperfByProtocol[p][tc]) iperfByProtocol[p][tc] = { summary: null, intervals: [] };
      iperfByProtocol[p][tc].intervals.push({
        id: row.id, interval_start: row.interval_start, interval_end: row.interval_end,
        bits_per_second: row.bits_per_second, rtt_us: row.rtt_us, retransmits: row.retransmits,
      });
    }
    const cpuByProtocol = {};
    for (const row of mpModeCpuRes.rows) {
      const p = row.protocol;
      if (!cpuByProtocol[p]) cpuByProtocol[p] = { snapshots: [] };
      cpuByProtocol[p].snapshots.push({
        id: row.id, snapshot_time: row.snapshot_time, cpu_core: row.cpu_core,
        usr_pct: row.usr_pct, nice_pct: row.nice_pct, sys_pct: row.sys_pct,
        iowait_pct: row.iowait_pct, soft_pct: row.soft_pct, idle_pct: row.idle_pct,
      });
    }
    const htbClassesByProtocol = {};
    for (const row of mpModeHtbRes.rows) {
      const p = row.protocol;
      if (!htbClassesByProtocol[p]) htbClassesByProtocol[p] = [];
      htbClassesByProtocol[p].push({ id: row.id, class_id: row.class_id, ...mkHtbClass(row) });
    }
    const ebpfClassesByProtocol = {};
    for (const row of mpModeEbpfRes.rows) {
      const p = row.protocol;
      if (!ebpfClassesByProtocol[p]) ebpfClassesByProtocol[p] = [];
      ebpfClassesByProtocol[p].push({ id: row.id, class_key: row.class_key, class_name: row.class_name, packets: row.packets, bytes: row.bytes, borrowed: row.borrowed, ecn_marked: row.ecn_marked, delayed: row.delayed });
    }

    res.json({
      dataset_id: dataset.id,
      dataset_name: dataset.name,
      qos_type: qosType,
      iperf,
      cpu: { snapshots: cpuRes.rows },
      htbClasses:  htbRes.rows,
      ebpfClasses: ebpfRes.rows,
      timeSeries,
      iperfByProtocol,
      cpuByProtocol,
      htbClassesByProtocol,
      ebpfClassesByProtocol,
    });
  } catch (err) { next(err); }
});

// ── GET /datasets/:id/mode/:qosType/report — Markdown for one mode ─────────
router.get('/:id/mode/:qosType/report', async (req, res, next) => {
  const id      = parseInt(req.params.id);
  const qosType = req.params.qosType;
  if (isNaN(id)) return res.status(400).json({ error: 'invalid id' });
  if (!['no_qos', 'htb', 'ebpf'].includes(qosType))
    return res.status(400).json({ error: 'qosType must be no_qos | htb | ebpf' });

  try {
    const dsRes = await pool.query('SELECT * FROM datasets WHERE id = $1', [id]);
    if (!dsRes.rows.length) return res.status(404).json({ error: 'Dataset not found' });
    const dataset = dsRes.rows[0];

    // Detect primary protocol (prefer tcp) to avoid mixing TCP/UDP iperf data
    const protoRes2 = await pool.query(
      `SELECT DISTINCT protocol FROM experiments WHERE dataset_id = $1 AND qos_type = $2 AND protocol IS NOT NULL`,
      [id, qosType]
    );
    const protos2 = protoRes2.rows.map(r => r.protocol);
    const primaryProto2 = protos2.includes('tcp') ? 'tcp' : (protos2[0] || null);

    const [iperfRes, intervalsRes, cpuRes, htbRes, ebpfRes] = await Promise.all([
      pool.query(
        `SELECT e.traffic_class, s.* FROM iperf_summary s JOIN experiments e ON e.id = s.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2
           AND (e.protocol = $3 OR ($3 IS NULL AND e.protocol IS NULL))`,
        [id, qosType, primaryProto2]),
      pool.query(
        `SELECT e.traffic_class, i.* FROM iperf_intervals i JOIN experiments e ON e.id = i.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2
           AND (e.protocol = $3 OR ($3 IS NULL AND e.protocol IS NULL))
         ORDER BY e.traffic_class, i.interval_start`,
        [id, qosType, primaryProto2]),
      pool.query(
        `SELECT c.* FROM cpu_snapshots c JOIN experiments e ON e.id = c.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2
           AND (e.protocol = $3 OR ($3 IS NULL AND e.protocol IS NULL))
         ORDER BY c.id`, [id, qosType, primaryProto2]),
      pool.query(
        `SELECT h.* FROM htb_class_stats h JOIN experiments e ON e.id = h.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2
           AND (e.protocol = $3 OR ($3 IS NULL AND e.protocol IS NULL))
         ORDER BY h.class_id`, [id, qosType, primaryProto2]),
      pool.query(
        `SELECT m.* FROM ebpf_class_stats m JOIN experiments e ON e.id = m.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2
           AND (e.protocol = $3 OR ($3 IS NULL AND e.protocol IS NULL))
         ORDER BY m.class_key`, [id, qosType, primaryProto2]),
    ]);

    // Per-protocol iperf/htb/ebpf data for multi-protocol report sections
    const [allIperfRes, allHtbRes, allEbpfRes] = await Promise.all([
      pool.query(
        `SELECT e.traffic_class, e.protocol, s.*
         FROM iperf_summary s JOIN experiments e ON e.id = s.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2 AND e.protocol IS NOT NULL`,
        [id, qosType]),
      pool.query(
        `SELECT h.*, e.protocol
         FROM htb_class_stats h JOIN experiments e ON e.id = h.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2 AND e.protocol IS NOT NULL
         ORDER BY e.protocol, h.class_id`,
        [id, qosType]),
      pool.query(
        `SELECT m.*, e.protocol
         FROM ebpf_class_stats m JOIN experiments e ON e.id = m.experiment_id
         WHERE e.dataset_id = $1 AND e.qos_type = $2 AND e.protocol IS NOT NULL
         ORDER BY e.protocol, m.class_key`,
        [id, qosType]),
    ]);

    function buildIperfSummary(row) {
      return {
        throughput_mbps: row.throughput_mbps, rcv_bytes: Number(row.rcv_bytes) || 0,
        sent_throughput_mbps: row.sent_throughput_mbps, sent_bytes: Number(row.sent_bytes) || 0,
        delivery_ratio: row.delivery_ratio,
        avg_rtt_us: row.avg_rtt_us,
        max_rtt_us: row.max_rtt_us, min_rtt_us: row.min_rtt_us, rtt_std_us: row.rtt_std_us,
        retransmits: row.retransmits, duration_s: row.duration_s,
        cpu_host_total: row.cpu_host_total, cpu_host_user: row.cpu_host_user,
        cpu_host_system: row.cpu_host_system,
        cpu_remote_total: row.cpu_remote_total, cpu_remote_user: row.cpu_remote_user,
        cpu_remote_system: row.cpu_remote_system,
        max_snd_cwnd: row.max_snd_cwnd, max_snd_wnd: row.max_snd_wnd,
        tcp_congestion: row.tcp_congestion,
        jitter_ms: row.jitter_ms,
        lost_packets: row.lost_packets != null ? Number(row.lost_packets) : null,
        sent_packets: row.sent_packets != null ? Number(row.sent_packets) : null,
        rcv_packets:  row.rcv_packets  != null ? Number(row.rcv_packets)  : null,
        lost_percent: row.lost_percent,
      };
    }

    const iperf = {};
    for (const row of iperfRes.rows) {
      iperf[row.traffic_class] = { summary: buildIperfSummary(row), intervals: [] };
    }
    for (const row of intervalsRes.rows) {
      const tc = row.traffic_class;
      if (!iperf[tc]) iperf[tc] = { summary: null, intervals: [] };
      iperf[tc].intervals.push({ id: row.id, interval_start: row.interval_start, interval_end: row.interval_end, bits_per_second: row.bits_per_second, rtt_us: row.rtt_us, retransmits: row.retransmits });
    }
    const timeSeries = {};
    for (const row of intervalsRes.rows) {
      const key = `${qosType}_${row.traffic_class}`;
      if (!timeSeries[key]) timeSeries[key] = [];
      timeSeries[key].push({ t: row.interval_start, bitsPerSecond: row.bits_per_second, rttUs: row.rtt_us, retransmits: row.retransmits, jitterMs: row.jitter_ms });
    }

    // Build iperfByProtocol
    const iperfByProtocol2 = {};
    for (const row of allIperfRes.rows) {
      const p = row.protocol; const tc = row.traffic_class;
      if (!iperfByProtocol2[p]) iperfByProtocol2[p] = {};
      iperfByProtocol2[p][tc] = { summary: buildIperfSummary(row), intervals: [] };
    }

    // Build htbClassesByProtocol2 / ebpfClassesByProtocol2
    const htbClassesByProtocol2 = {};
    for (const row of allHtbRes.rows) {
      const p = row.protocol;
      if (!htbClassesByProtocol2[p]) htbClassesByProtocol2[p] = [];
      htbClassesByProtocol2[p].push(row);
    }
    const ebpfClassesByProtocol2 = {};
    for (const row of allEbpfRes.rows) {
      const p = row.protocol;
      if (!ebpfClassesByProtocol2[p]) ebpfClassesByProtocol2[p] = [];
      ebpfClassesByProtocol2[p].push(row);
    }

    const modeData = {
      dataset_id: dataset.id, dataset_name: dataset.name, qos_type: qosType,
      iperf, cpu: { snapshots: cpuRes.rows },
      htbClasses: htbRes.rows, ebpfClasses: ebpfRes.rows,
      timeSeries,
      iperfByProtocol: iperfByProtocol2,
      htbClassesByProtocol: htbClassesByProtocol2,
      ebpfClassesByProtocol: ebpfClassesByProtocol2,
    };
    const md  = buildModeMarkdown(modeData);
    const slug = `${qosType}-mode-${dataset.id}`;
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="ebpf-mode-${slug}.md"`);
    res.send(md);
  } catch (err) { next(err); }
});

// ── GET /datasets/:id/report — generate Markdown report ───────────────────
router.get('/:id/report', async (req, res, next) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'invalid id' });
  try {
    // Reuse the same queries as GET /:id
    const dsRes = await pool.query('SELECT * FROM datasets WHERE id = $1', [id]);
    if (!dsRes.rows.length) return res.status(404).json({ error: 'Dataset not found' });

    const dataset = dsRes.rows[0];

    // detect primary protocol (same logic as GET /:id)
    const rptProtoRes = await pool.query(
      `SELECT DISTINCT protocol FROM experiments WHERE dataset_id = $1`, [id]
    );
    const rptProtos = rptProtoRes.rows.map(r => r.protocol).filter(Boolean);
    const rptProto  = rptProtos.includes('tcp') ? 'tcp' : (rptProtos[0] || null);

    const [iperfRes, cpuRes, htbRes, ebpfRes, intervalRes, allProtoIperfRes, allProtoCpuRes] = await Promise.all([
      pool.query(
        `SELECT e.qos_type, e.traffic_class, s.*
         FROM iperf_summary s JOIN experiments e ON e.id = s.experiment_id
         WHERE e.dataset_id = $1
           AND (e.protocol = $2 OR ($2 IS NULL AND e.protocol IS NULL))`, [id, rptProto]),
      pool.query(
        `SELECT e.qos_type,
                AVG(c.usr_pct)::float AS avg_usr, AVG(c.nice_pct)::float AS avg_nice,
                AVG(c.sys_pct)::float AS avg_sys, AVG(c.iowait_pct)::float AS avg_iowait,
                AVG(c.soft_pct)::float AS avg_soft, AVG(c.idle_pct)::float AS avg_idle,
                COUNT(*)::int AS samples
         FROM cpu_snapshots c JOIN experiments e ON e.id = c.experiment_id
         WHERE e.dataset_id = $1
           AND (e.protocol = $2 OR ($2 IS NULL AND e.protocol IS NULL))
         GROUP BY e.qos_type`, [id, rptProto]),
      pool.query(
        `SELECT h.* FROM htb_class_stats h JOIN experiments e ON e.id = h.experiment_id
         WHERE e.dataset_id = $1
           AND (e.protocol = $2 OR ($2 IS NULL AND e.protocol IS NULL))`, [id, rptProto]),
      pool.query(
        `SELECT m.* FROM ebpf_class_stats m JOIN experiments e ON e.id = m.experiment_id
         WHERE e.dataset_id = $1
           AND (e.protocol = $2 OR ($2 IS NULL AND e.protocol IS NULL))`, [id, rptProto]),
      pool.query(
        `SELECT e.qos_type, e.traffic_class, i.interval_start, i.interval_end,
                i.bits_per_second, i.rtt_us, i.retransmits
         FROM iperf_intervals i JOIN experiments e ON e.id = i.experiment_id
         WHERE e.dataset_id = $1
           AND (e.protocol = $2 OR ($2 IS NULL AND e.protocol IS NULL))
         ORDER BY e.qos_type, e.traffic_class, i.interval_start`, [id, rptProto]),
      // Multi-protocol iperf for metricsByProtocol
      pool.query(
        `SELECT e.qos_type, e.traffic_class, e.protocol, s.*
         FROM iperf_summary s JOIN experiments e ON e.id = s.experiment_id
         WHERE e.dataset_id = $1 AND e.protocol IS NOT NULL`, [id]),
      // Multi-protocol CPU for metricsByProtocol
      pool.query(
        `SELECT e.qos_type, e.protocol,
                AVG(c.usr_pct)::float AS avg_usr, AVG(c.nice_pct)::float AS avg_nice,
                AVG(c.sys_pct)::float AS avg_sys, AVG(c.iowait_pct)::float AS avg_iowait,
                AVG(c.soft_pct)::float AS avg_soft, AVG(c.idle_pct)::float AS avg_idle,
                COUNT(*)::int AS samples
         FROM cpu_snapshots c JOIN experiments e ON e.id = c.experiment_id
         WHERE e.dataset_id = $1 AND e.protocol IS NOT NULL
         GROUP BY e.qos_type, e.protocol`, [id]),
    ]);

    function mkMetric(row) {
      return {
        throughputMbps:     row.throughput_mbps,
        rcvBytes:           Number(row.rcv_bytes)  || 0,
        sentThroughputMbps: row.sent_throughput_mbps,
        sentBytes:          Number(row.sent_bytes) || 0,
        deliveryRatio:      row.delivery_ratio,
        avgRttUs:           row.avg_rtt_us,
        maxRttUs:           row.max_rtt_us, minRttUs: row.min_rtt_us, rttStdUs: row.rtt_std_us,
        retransmits:        row.retransmits, durationS: row.duration_s,
        cpuHostTotal:       row.cpu_host_total, cpuHostUser: row.cpu_host_user,
        cpuHostSystem:      row.cpu_host_system,
        cpuRemoteTotal:     row.cpu_remote_total, cpuRemoteUser: row.cpu_remote_user,
        cpuRemoteSystem:    row.cpu_remote_system,
        maxSndCwnd:         row.max_snd_cwnd, maxSndWnd: row.max_snd_wnd,
        tcpCongestion:      row.tcp_congestion,
        jitterMs:           row.jitter_ms,
        lostPackets:        row.lost_packets != null ? Number(row.lost_packets) : null,
        sentPackets:        row.sent_packets != null ? Number(row.sent_packets) : null,
        rcvPackets:         row.rcv_packets  != null ? Number(row.rcv_packets)  : null,
        lostPercent:        row.lost_percent,
      };
    }

    function mkCpuMetric(row) {
      return {
        avgUsr: row.avg_usr, avgNice: row.avg_nice, avgSys: row.avg_sys,
        avgIowait: row.avg_iowait, avgSoft: row.avg_soft, avgIdle: row.avg_idle,
        avgTotal: (row.avg_usr || 0) + (row.avg_nice || 0) + (row.avg_sys || 0) + (row.avg_iowait || 0) + (row.avg_soft || 0),
        samples: row.samples,
      };
    }

    const metrics = {};
    for (const row of iperfRes.rows) {
      const q = row.qos_type; const tc = row.traffic_class;
      if (!metrics[q]) metrics[q] = {};
      metrics[q][tc] = mkMetric(row);
    }
    for (const row of cpuRes.rows) {
      const q = row.qos_type;
      if (!metrics[q]) metrics[q] = {};
      metrics[q].cpu = mkCpuMetric(row);
    }
    if (htbRes.rows.length) {
      if (!metrics.htb) metrics.htb = {};
      metrics.htb.tcClasses = {};
      for (const row of htbRes.rows) {
        metrics.htb.tcClasses[row.class_id] = {
          rate: row.rate, bytesSent: row.bytes_sent, packets: row.packets,
          dropped: row.dropped, overlimits: row.overlimits,
          lended: row.lended, borrowedPkt: row.borrowed_pkt,
          tokens: row.tokens, ctokens: row.ctokens,
          requeues: row.requeues, giants: row.giants,
          throughputMbps: (row.bytes_sent * 8) / 30 / 1e6,
        };
      }
    }
    if (ebpfRes.rows.length) {
      if (!metrics.ebpf) metrics.ebpf = {};
      metrics.ebpf.mapStats = {};
      for (const row of ebpfRes.rows) {
        metrics.ebpf.mapStats[row.class_name] = {
          classKey: row.class_key, packets: row.packets, bytes: row.bytes,
          borrowed: row.borrowed, ecnMarked: row.ecn_marked, delayed: row.delayed,
          throughputMbps: (row.bytes * 8) / 30 / 1e6,
        };
      }
    }
    const timeSeries = {};
    for (const row of intervalRes.rows) {
      const key = `${row.qos_type}_${row.traffic_class}`;
      if (!timeSeries[key]) timeSeries[key] = [];
      timeSeries[key].push({ t: row.interval_start, bitsPerSecond: row.bits_per_second, rttUs: row.rtt_us, retransmits: row.retransmits, jitterMs: row.jitter_ms });
    }

    // Build metricsByProtocol (tcp / udp keyed like metrics)
    const metricsByProtocol = {};
    for (const row of allProtoIperfRes.rows) {
      const p = row.protocol, q = row.qos_type, tc = row.traffic_class;
      if (!metricsByProtocol[p]) metricsByProtocol[p] = {};
      if (!metricsByProtocol[p][q]) metricsByProtocol[p][q] = {};
      metricsByProtocol[p][q][tc] = mkMetric(row);
    }
    for (const row of allProtoCpuRes.rows) {
      const p = row.protocol, q = row.qos_type;
      if (!metricsByProtocol[p]) metricsByProtocol[p] = {};
      if (!metricsByProtocol[p][q]) metricsByProtocol[p][q] = {};
      metricsByProtocol[p][q].cpu = mkCpuMetric(row);
    }

    const md = buildMarkdown({ ...dataset, metrics, metricsByProtocol, timeSeries });

    const slug = dataset.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="ebpf-report-${slug}.md"`);
    res.send(md);
  } catch (err) { next(err); }
});

// ── DELETE /datasets/:id ────────────────────────────────────────────────────
router.delete('/:id', async (req, res, next) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'invalid id' });
  try {
    const { rowCount } = await pool.query('DELETE FROM datasets WHERE id = $1', [id]);
    if (!rowCount) return res.status(404).json({ error: 'Dataset not found' });
    res.json({ success: true });
  } catch (err) { next(err); }
});

module.exports = router;
