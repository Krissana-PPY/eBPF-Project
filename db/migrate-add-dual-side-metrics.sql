-- Migration: add dual-side iperf metrics (sender + receiver)
-- Purpose: store both sum_sent and sum_received from iperf3 JSON
--          so delivery_ratio and shaping impact can be analysed.
--
-- Usage:
--   sudo docker exec -i ebpf-project-db-1 psql -U ebpf -d ebpf_research \
--     < db/migrate-add-dual-side-metrics.sql

ALTER TABLE iperf_summary
  ADD COLUMN IF NOT EXISTS rcv_bytes            BIGINT,
  ADD COLUMN IF NOT EXISTS sent_throughput_mbps FLOAT,
  ADD COLUMN IF NOT EXISTS sent_bytes           BIGINT,
  ADD COLUMN IF NOT EXISTS delivery_ratio       FLOAT;

-- Backfill: existing rows have no sender data — treat as 100% delivery
-- (no way to recover sum_sent without the original JSON files).
UPDATE iperf_summary
SET delivery_ratio = 100
WHERE delivery_ratio IS NULL;

SELECT 'Migration complete.' AS status,
       COUNT(*)                         AS total_rows,
       COUNT(delivery_ratio)            AS rows_with_delivery_ratio,
       COUNT(sent_throughput_mbps)      AS rows_with_sent_throughput
FROM iperf_summary;
