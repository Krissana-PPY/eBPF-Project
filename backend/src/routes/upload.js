'use strict';

const { Router } = require('express');
const multer     = require('multer');
const path       = require('path');
const { pool }   = require('../db');
const { parseFile } = require('../parsers');

const router = Router();

const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, '../../uploads');
const MAX_MB     = parseInt(process.env.MAX_FILE_SIZE_MB || '200');

const storage = multer.memoryStorage();
const upload  = multer({
  storage,
  limits: { fileSize: MAX_MB * 1024 * 1024, files: 20 },
  fileFilter: (req, file, cb) => {
    const ok = /\.(json|txt)$/i.test(file.originalname);
    cb(ok ? null : new Error(`Only .json and .txt files accepted: ${file.originalname}`), ok);
  },
});

// ── POST /upload/:datasetId — upload files into an existing dataset ─────────
router.post('/:datasetId', upload.array('files'), async (req, res, next) => {
  const datasetId = parseInt(req.params.datasetId);
  if (isNaN(datasetId)) return res.status(400).json({ error: 'invalid datasetId' });
  if (!req.files || !req.files.length) return res.status(400).json({ error: 'No files received' });

  const client = await pool.connect();
  const results = [];

  try {
    await client.query('BEGIN');

    // verify dataset exists
    const ds = await client.query('SELECT id FROM datasets WHERE id = $1', [datasetId]);
    if (!ds.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Dataset not found' });
    }

    for (const file of req.files) {
      try {
        const { meta, data } = parseFile(file.originalname, file.buffer);

        // insert experiment record
        const expRes = await client.query(
          `INSERT INTO experiments (dataset_id, qos_type, protocol, traffic_class, experiment_type, source_filename)
           VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
          [datasetId, meta.qosType, meta.protocol || null, meta.trafficClass, meta.experimentType, file.originalname]
        );
        const expId = expRes.rows[0].id;

        // persist parsed data
        if (meta.experimentType === 'iperf') {
          const s = data.summary;
          await client.query(
            `INSERT INTO iperf_summary
             (experiment_id, throughput_mbps, avg_rtt_us, max_rtt_us, min_rtt_us, rtt_std_us,
              retransmits, duration_s, cpu_host_total, cpu_host_user, cpu_host_system, cpu_remote_total)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
            [expId, s.throughputMbps, s.avgRttUs, s.maxRttUs, s.minRttUs, s.rttStdUs,
             s.retransmits, s.durationS, s.cpuHostTotal, s.cpuHostUser, s.cpuHostSystem, s.cpuRemoteTotal]
          );
          if (data.intervals?.length) {
            const vals = data.intervals.map((iv, i) => `($1,$${i*5+2},$${i*5+3},$${i*5+4},$${i*5+5},$${i*5+6})`).join(',');
            const params = [expId, ...data.intervals.flatMap(iv =>
              [iv.start, iv.end, iv.bytes, iv.bitsPerSecond, iv.rttUs ?? null]
            )];
            await client.query(
              `INSERT INTO iperf_intervals (experiment_id,interval_start,interval_end,bytes,bits_per_second,rtt_us) VALUES ${vals}`,
              params
            );
          }
        } else if (meta.experimentType === 'cpu') {
          for (const snap of data.snapshots) {
            await client.query(
              `INSERT INTO cpu_snapshots (experiment_id, snapshot_time, cpu_core, usr_pct, sys_pct, soft_pct, idle_pct)
               VALUES ($1,$2,$3,$4,$5,$6,$7)`,
              [expId, snap.snapshotTime, snap.cpuCore, snap.usrPct, snap.sysPct, snap.softPct, snap.idlePct]
            );
          }
        } else if (meta.experimentType === 'htb_tc') {
          for (const cls of data.classes) {
            await client.query(
              `INSERT INTO htb_class_stats (experiment_id, class_id, rate, bytes_sent, packets, dropped, overlimits)
               VALUES ($1,$2,$3,$4,$5,$6,$7)`,
              [expId, cls.classId, cls.rate, cls.bytesSent, cls.packets, cls.dropped, cls.overlimits]
            );
          }
        } else if (meta.experimentType === 'ebpf_map') {
          for (const cls of data.classes) {
            await client.query(
              `INSERT INTO ebpf_class_stats (experiment_id, class_key, class_name, packets, bytes, borrowed, ecn_marked, delayed)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
              [expId, cls.classKey, cls.className, cls.packets, cls.bytes, cls.borrowed, cls.ecnMarked, cls.delayed]
            );
          }
        }

        results.push({ file: file.originalname, status: 'ok', ...meta });
      } catch (fileErr) {
        results.push({ file: file.originalname, status: 'error', error: fileErr.message });
      }
    }

    await client.query('COMMIT');
    res.json({ datasetId, results });
  } catch (err) {
    await client.query('ROLLBACK');
    next(err);
  } finally {
    client.release();
  }
});

module.exports = router;
