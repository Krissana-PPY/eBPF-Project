'use strict';

const { Router }             = require('express');
const { pool }               = require('../db');
const { buildExpMarkdown }   = require('../report/experiment-markdown');

const router = Router();

// ── GET /experiments/dataset/:datasetId — list experiments ─────────────────
router.get('/dataset/:datasetId', async (req, res, next) => {
  const datasetId = parseInt(req.params.datasetId);
  if (isNaN(datasetId)) return res.status(400).json({ error: 'invalid datasetId' });
  try {
    const { rows } = await pool.query(
      `SELECT e.*,
              s.throughput_mbps, s.avg_rtt_us, s.retransmits,
              (SELECT COUNT(*)::int FROM iperf_intervals   WHERE experiment_id = e.id) AS interval_count,
              (SELECT COUNT(*)::int FROM cpu_snapshots     WHERE experiment_id = e.id) AS snapshot_count,
              (SELECT COUNT(*)::int FROM htb_class_stats   WHERE experiment_id = e.id) AS htb_class_count,
              (SELECT COUNT(*)::int FROM ebpf_class_stats  WHERE experiment_id = e.id) AS ebpf_class_count
       FROM experiments e
       LEFT JOIN iperf_summary s ON s.experiment_id = e.id
       WHERE e.dataset_id = $1
       ORDER BY e.qos_type, e.traffic_class, e.experiment_type, e.id`,
      [datasetId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// ── GET /experiments/:id — single experiment detail ────────────────────────
router.get('/:id', async (req, res, next) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'invalid id' });
  try {
    const expRes = await pool.query('SELECT * FROM experiments WHERE id = $1', [id]);
    if (!expRes.rows.length) return res.status(404).json({ error: 'Experiment not found' });
    const exp = expRes.rows[0];

    const [summaryRes, intervalsRes, cpuRes, htbRes, ebpfRes] = await Promise.all([
      pool.query('SELECT * FROM iperf_summary WHERE experiment_id = $1 LIMIT 1', [id]),
      pool.query('SELECT * FROM iperf_intervals WHERE experiment_id = $1 ORDER BY interval_start', [id]),
      pool.query('SELECT * FROM cpu_snapshots WHERE experiment_id = $1 ORDER BY id', [id]),
      pool.query('SELECT * FROM htb_class_stats WHERE experiment_id = $1 ORDER BY class_id', [id]),
      pool.query('SELECT * FROM ebpf_class_stats WHERE experiment_id = $1 ORDER BY class_key', [id]),
    ]);

    res.json({
      ...exp,
      summary:   summaryRes.rows[0] || null,
      intervals: intervalsRes.rows,
      cpuSnapshots: cpuRes.rows,
      htbClasses:   htbRes.rows,
      ebpfClasses:  ebpfRes.rows,
    });
  } catch (err) { next(err); }
});

// ── GET /experiments/:id/report — Markdown report for single experiment ────
router.get('/:id/report', async (req, res, next) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'invalid id' });
  try {
    const expRes = await pool.query(
      `SELECT e.*, d.name AS dataset_name FROM experiments e
       JOIN datasets d ON d.id = e.dataset_id
       WHERE e.id = $1`, [id]
    );
    if (!expRes.rows.length) return res.status(404).json({ error: 'Experiment not found' });
    const exp = expRes.rows[0];

    const [summaryRes, intervalsRes, cpuRes, htbRes, ebpfRes] = await Promise.all([
      pool.query('SELECT * FROM iperf_summary WHERE experiment_id = $1 LIMIT 1', [id]),
      pool.query('SELECT * FROM iperf_intervals WHERE experiment_id = $1 ORDER BY interval_start', [id]),
      pool.query('SELECT * FROM cpu_snapshots WHERE experiment_id = $1 ORDER BY id', [id]),
      pool.query('SELECT * FROM htb_class_stats WHERE experiment_id = $1 ORDER BY class_id', [id]),
      pool.query('SELECT * FROM ebpf_class_stats WHERE experiment_id = $1 ORDER BY class_key', [id]),
    ]);

    const detail = {
      ...exp,
      summary:      summaryRes.rows[0] || null,
      intervals:    intervalsRes.rows,
      cpuSnapshots: cpuRes.rows,
      htbClasses:   htbRes.rows,
      ebpfClasses:  ebpfRes.rows,
    };

    const md   = buildExpMarkdown(detail);
    const slug = `${exp.qos_type}-${exp.experiment_type}${exp.traffic_class ? '-' + exp.traffic_class : ''}-exp${id}`;
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="ebpf-exp-${slug}.md"`);
    res.send(md);
  } catch (err) { next(err); }
});

module.exports = router;
