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
  // full_suite_* research runs (fair_benchmark_trials × 10 + borrow_tests) can exceed 300 files
  limits: { fileSize: MAX_MB * 1024 * 1024, files: 2000 },
  fileFilter: (req, file, cb) => {
    const ok = /\.(json|txt)$/i.test(file.originalname);
    cb(ok ? null : new Error(`Only .json and .txt files accepted: ${file.originalname}`), ok);
  },
});

// ── POST /upload/:datasetId ─────────────────────────────────────────────────
router.post('/:datasetId', upload.array('files'), async (req, res, next) => {
  const datasetId = parseInt(req.params.datasetId);
  if (isNaN(datasetId)) return res.status(400).json({ error: 'invalid datasetId' });
  if (!req.files || !req.files.length) return res.status(400).json({ error: 'No files received' });

  const client = await pool.connect();
  const results = [];

  // relative paths (webkitRelativePath), same order as req.files, used to
  // recover the fair_benchmark_trials/trial_N number — filenames alone repeat
  // identically across trials, so only the folder path carries the trial number.
  let relPaths = [];
  try { relPaths = JSON.parse(req.body.paths || '[]'); } catch { relPaths = []; }

  try {
    await client.query('BEGIN');

    const ds = await client.query('SELECT id FROM datasets WHERE id = $1', [datasetId]);
    if (!ds.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Dataset not found' });
    }

    for (let fi = 0; fi < req.files.length; fi++) {
      const file = req.files[fi];
      try {
        const { meta, data } = parseFile(file.originalname, file.buffer);

        const relPath = relPaths[fi] || '';
        const trialM  = relPath.match(/trial_(\d+)/i);
        const trialNo = trialM ? parseInt(trialM[1]) : null;

        const expRes = await client.query(
          `INSERT INTO experiments (dataset_id, qos_type, protocol, traffic_class, experiment_type, source_filename, phase, scenario, trial_no)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
          [datasetId, meta.qosType, meta.protocol || null, meta.trafficClass, meta.experimentType, file.originalname,
           meta.phase || null, meta.scenario || null, trialNo]
        );
        const expId = expRes.rows[0].id;

        if (meta.experimentType === 'iperf') {
          const s = data.summary;
          await client.query(
            `INSERT INTO iperf_summary
             (experiment_id,
              throughput_mbps, rcv_bytes,
              sent_throughput_mbps, sent_bytes, delivery_ratio,
              avg_rtt_us, max_rtt_us, min_rtt_us, rtt_std_us,
              max_snd_cwnd, max_snd_wnd, tcp_congestion,
              retransmits, duration_s,
              cpu_host_total, cpu_host_user, cpu_host_system,
              cpu_remote_total, cpu_remote_user, cpu_remote_system,
              jitter_ms, lost_packets, sent_packets, rcv_packets, lost_percent,
              target_bitrate_mbps, tos)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)`,
            [expId,
             s.throughputMbps,     s.rcvBytes,
             s.sentThroughputMbps, s.sentBytes,     s.deliveryRatio,
             s.avgRttUs,           s.maxRttUs,      s.minRttUs,      s.rttStdUs,
             s.maxSndCwnd,         s.maxSndWnd,     s.tcpCongestion,
             s.retransmits,        s.durationS,
             s.cpuHostTotal,       s.cpuHostUser,   s.cpuHostSystem,
             s.cpuRemoteTotal,     s.cpuRemoteUser, s.cpuRemoteSystem,
             s.jitterMs,           s.lostPackets,   s.sentPackets,   s.rcvPackets, s.lostPercent,
             s.targetBitrateMbps,  s.tos]
          );

          if (data.intervals?.length) {
            const vals   = data.intervals.map((_, i) =>
              `($1,$${i*5+2},$${i*5+3},$${i*5+4},$${i*5+5},$${i*5+6})`).join(',');
            const params = [expId, ...data.intervals.flatMap(iv =>
              [iv.start, iv.end, iv.bytes, iv.bitsPerSecond, iv.rttUs ?? null])];
            await client.query(
              `INSERT INTO iperf_intervals
               (experiment_id,interval_start,interval_end,bytes,bits_per_second,rtt_us)
               VALUES ${vals}`, params);
          }

        } else if (meta.experimentType === 'cpu') {
          for (const snap of data.snapshots) {
            await client.query(
              `INSERT INTO cpu_snapshots
               (experiment_id, snapshot_time, cpu_core,
                usr_pct, nice_pct, sys_pct, iowait_pct, soft_pct, idle_pct)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
              [expId, snap.snapshotTime, snap.cpuCore,
               snap.usrPct, snap.nicePct, snap.sysPct, snap.iowaitPct, snap.softPct, snap.idlePct]
            );
          }

        } else if (meta.experimentType === 'htb_tc') {
          for (const cls of data.classes) {
            await client.query(
              `INSERT INTO htb_class_stats
               (experiment_id, class_id, rate, bytes_sent, packets, dropped, overlimits,
                lended, borrowed_pkt, tokens, ctokens, requeues, giants)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
              [expId, cls.classId, cls.rate, cls.bytesSent, cls.packets, cls.dropped, cls.overlimits,
               cls.lended, cls.borrowedPkt, cls.tokens, cls.ctokens, cls.requeues, cls.giants]
            );
          }

        } else if (meta.experimentType === 'ebpf_map') {
          for (const cls of data.classes) {
            await client.query(
              `INSERT INTO ebpf_class_stats
               (experiment_id, class_key, class_name, packets, bytes, borrowed, ecn_marked, delayed, dropped)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
              [expId, cls.classKey, cls.className, cls.packets, cls.bytes, cls.borrowed, cls.ecnMarked, cls.delayed, cls.dropped]
            );
          }

        } else if (meta.experimentType === 'bpf_prog') {
          for (const prog of data.programs) {
            await client.query(
              `INSERT INTO bpf_prog_stats
               (experiment_id, prog_id, prog_name, prog_type, run_time_ns, run_cnt)
               VALUES ($1,$2,$3,$4,$5,$6)`,
              [expId, prog.progId, prog.progName, prog.progType, prog.runTimeNs, prog.runCnt]
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
