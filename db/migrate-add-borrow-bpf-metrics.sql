-- Migration: borrow-test scenarios, before/after phase tagging, trial numbers,
-- eBPF dropped-packet counter, iperf target rate/tos, and bpftool program stats.
-- Run this if the database already exists (to avoid dropping data)
-- Usage: sudo docker exec -i ebpf-project-db-1 psql -U ebpf -d ebpf_research < db/migrate-add-borrow-bpf-metrics.sql

ALTER TABLE experiments      ADD COLUMN IF NOT EXISTS phase      VARCHAR(10);
ALTER TABLE experiments      ADD COLUMN IF NOT EXISTS scenario   VARCHAR(50);
ALTER TABLE experiments      ADD COLUMN IF NOT EXISTS trial_no   INTEGER;

ALTER TABLE ebpf_class_stats ADD COLUMN IF NOT EXISTS dropped    BIGINT DEFAULT 0;

ALTER TABLE iperf_summary    ADD COLUMN IF NOT EXISTS target_bitrate_mbps FLOAT;
ALTER TABLE iperf_summary    ADD COLUMN IF NOT EXISTS tos                 INTEGER;

CREATE TABLE IF NOT EXISTS bpf_prog_stats (
    id            SERIAL PRIMARY KEY,
    experiment_id INTEGER NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
    prog_id       INTEGER,
    prog_name     VARCHAR(100),
    prog_type     VARCHAR(50),
    run_time_ns   BIGINT,
    run_cnt       BIGINT
);
CREATE INDEX IF NOT EXISTS idx_bpf_prog_stats_exp ON bpf_prog_stats(experiment_id);
