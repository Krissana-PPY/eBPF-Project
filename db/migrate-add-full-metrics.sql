-- Migration: add all missing metrics — UDP loss/jitter/packets, TCP cwnd,
--             CPU iowait/nice, HTB lended/borrowed/tokens
-- Run ONCE against the database, then re-upload your datasets so the
-- new columns get populated by the fixed parser.
--
-- Usage:
--   docker exec -i ebpf-project-db-1 psql -U ebpf -d ebpf_research \
--     < db/migrate-add-full-metrics.sql

-- ── iperf_summary ─────────────────────────────────────────────────────────
ALTER TABLE iperf_summary
  ADD COLUMN IF NOT EXISTS cpu_remote_user   FLOAT,     -- iperf3 remote (receiver) user CPU %
  ADD COLUMN IF NOT EXISTS cpu_remote_system FLOAT,     -- iperf3 remote (receiver) system CPU %
  ADD COLUMN IF NOT EXISTS jitter_ms         FLOAT,     -- UDP: receiver-side jitter (ms)
  ADD COLUMN IF NOT EXISTS lost_packets      BIGINT,    -- UDP: receiver lost_packets
  ADD COLUMN IF NOT EXISTS sent_packets      BIGINT,    -- UDP: sender total packets
  ADD COLUMN IF NOT EXISTS rcv_packets       BIGINT,    -- UDP: receiver packets received
  ADD COLUMN IF NOT EXISTS lost_percent      FLOAT,     -- UDP: lost_percent (receiver side)
  ADD COLUMN IF NOT EXISTS max_snd_cwnd      BIGINT,    -- TCP: max send congestion window (bytes)
  ADD COLUMN IF NOT EXISTS max_snd_wnd       BIGINT,    -- TCP: max send window (bytes)
  ADD COLUMN IF NOT EXISTS tcp_congestion    VARCHAR(30);-- TCP: congestion algorithm name

-- ── cpu_snapshots ─────────────────────────────────────────────────────────
ALTER TABLE cpu_snapshots
  ADD COLUMN IF NOT EXISTS iowait_pct FLOAT,
  ADD COLUMN IF NOT EXISTS nice_pct   FLOAT;

-- ── htb_class_stats ────────────────────────────────────────────────────────
ALTER TABLE htb_class_stats
  ADD COLUMN IF NOT EXISTS lended       BIGINT,
  ADD COLUMN IF NOT EXISTS borrowed_pkt BIGINT,
  ADD COLUMN IF NOT EXISTS tokens       BIGINT,
  ADD COLUMN IF NOT EXISTS ctokens      BIGINT,
  ADD COLUMN IF NOT EXISTS requeues     INTEGER,
  ADD COLUMN IF NOT EXISTS giants       INTEGER;

SELECT 'Migration complete' AS status;
