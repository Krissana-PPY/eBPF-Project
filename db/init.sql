-- eBPF QoS Research Database Schema (includes all columns from all migrations)

CREATE TABLE IF NOT EXISTS datasets (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ  DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS experiments (
    id              SERIAL PRIMARY KEY,
    dataset_id      INTEGER NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    qos_type        VARCHAR(20)  NOT NULL,  -- 'no_qos' | 'htb' | 'ebpf'
    protocol        VARCHAR(10),            -- 'tcp' | 'udp' | NULL
    traffic_class   VARCHAR(10),            -- 'ef' | 'af' | 'be' | NULL
    experiment_type VARCHAR(30)  NOT NULL,  -- 'iperf' | 'cpu' | 'htb_tc' | 'ebpf_map'
    source_filename VARCHAR(500),
    created_at      TIMESTAMPTZ  DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS iperf_summary (
    id                    SERIAL PRIMARY KEY,
    experiment_id         INTEGER NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
    -- receiver side (post-shaping actual goodput at server)
    throughput_mbps       FLOAT,
    rcv_bytes             BIGINT,
    -- sender side (application rate before shaping at client)
    sent_throughput_mbps  FLOAT,
    sent_bytes            BIGINT,
    -- delivery efficiency
    delivery_ratio        FLOAT,
    -- RTT (TCP only — sender via ACK, bidirectional)
    avg_rtt_us            FLOAT,
    max_rtt_us            FLOAT,
    min_rtt_us            FLOAT,
    rtt_std_us            FLOAT,
    -- TCP congestion window (stream-level)
    max_snd_cwnd          BIGINT,
    max_snd_wnd           BIGINT,
    tcp_congestion        VARCHAR(30),
    -- sender counters
    retransmits           INTEGER,
    duration_s            FLOAT,
    -- iperf3 host (sender) CPU
    cpu_host_total        FLOAT,
    cpu_host_user         FLOAT,
    cpu_host_system       FLOAT,
    -- iperf3 remote (receiver) CPU
    cpu_remote_total      FLOAT,
    cpu_remote_user       FLOAT,
    cpu_remote_system     FLOAT,
    -- UDP-specific (receiver side)
    jitter_ms             FLOAT,
    lost_packets          BIGINT,
    sent_packets          BIGINT,
    rcv_packets           BIGINT,
    lost_percent          FLOAT
);

CREATE TABLE IF NOT EXISTS iperf_intervals (
    id               SERIAL PRIMARY KEY,
    experiment_id    INTEGER NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
    interval_start   FLOAT,
    interval_end     FLOAT,
    bytes            BIGINT,
    bits_per_second  FLOAT,
    retransmits      INTEGER,
    rtt_us           FLOAT
);

CREATE TABLE IF NOT EXISTS cpu_snapshots (
    id            SERIAL PRIMARY KEY,
    experiment_id INTEGER NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
    snapshot_time VARCHAR(20),
    cpu_core      VARCHAR(10),
    usr_pct       FLOAT,
    nice_pct      FLOAT,
    sys_pct       FLOAT,
    iowait_pct    FLOAT,
    soft_pct      FLOAT,
    idle_pct      FLOAT
);

CREATE TABLE IF NOT EXISTS htb_class_stats (
    id            SERIAL PRIMARY KEY,
    experiment_id INTEGER NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
    class_id      VARCHAR(20),
    rate          VARCHAR(20),
    bytes_sent    BIGINT,
    packets       INTEGER,
    dropped       INTEGER,
    overlimits    INTEGER,
    lended        BIGINT,
    borrowed_pkt  BIGINT,
    tokens        BIGINT,
    ctokens       BIGINT,
    requeues      INTEGER,
    giants        INTEGER
);

CREATE TABLE IF NOT EXISTS ebpf_class_stats (
    id            SERIAL PRIMARY KEY,
    experiment_id INTEGER NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
    class_key     INTEGER,
    class_name    VARCHAR(10),
    packets       BIGINT,
    bytes         BIGINT,
    borrowed      BIGINT,
    ecn_marked    BIGINT,
    delayed       BIGINT
);

CREATE INDEX IF NOT EXISTS idx_experiments_dataset ON experiments(dataset_id);
CREATE INDEX IF NOT EXISTS idx_iperf_summary_exp   ON iperf_summary(experiment_id);
CREATE INDEX IF NOT EXISTS idx_iperf_intervals_exp ON iperf_intervals(experiment_id);
CREATE INDEX IF NOT EXISTS idx_cpu_snapshots_exp   ON cpu_snapshots(experiment_id);
