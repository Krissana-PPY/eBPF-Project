-- Migration: add protocol column to experiments
-- Run this if the database already exists (to avoid dropping data)
-- Usage: sudo docker exec -i ebpf-project-db-1 psql -U ebpf -d ebpf_research < db/migrate-add-protocol.sql

ALTER TABLE experiments
  ADD COLUMN IF NOT EXISTS protocol VARCHAR(10);

-- Backfill protocol from source_filename for existing rows
UPDATE experiments
SET protocol = CASE
  WHEN source_filename ILIKE '%_tcp_%' OR source_filename ILIKE '%_tcp.%' THEN 'tcp'
  WHEN source_filename ILIKE '%_udp_%' OR source_filename ILIKE '%_udp.%' THEN 'udp'
  ELSE NULL
END
WHERE protocol IS NULL;

SELECT 'Migration complete.' AS status,
       COUNT(*) FILTER (WHERE protocol = 'tcp') AS tcp_experiments,
       COUNT(*) FILTER (WHERE protocol = 'udp') AS udp_experiments,
       COUNT(*) FILTER (WHERE protocol IS NULL) AS unknown_experiments
FROM experiments;
