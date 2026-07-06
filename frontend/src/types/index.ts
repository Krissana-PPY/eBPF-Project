// ── iperf3 summary — all sender + receiver metrics ──────────────────────────
export interface IperfMetrics {
  // receiver side (post-shaping actual goodput at server)
  throughputMbps:     number;
  rcvBytes:           number;
  // sender side (pre-shaping application rate at client)
  sentThroughputMbps: number | null;
  sentBytes:          number;
  // delivery efficiency
  deliveryRatio:      number | null;
  // RTT — TCP only (sender via ACK, bidirectional)
  avgRttUs:           number;
  maxRttUs:           number;
  minRttUs:           number;
  rttStdUs:           number;
  // TCP congestion window (stream-level sender stats)
  maxSndCwnd:         number | null;
  maxSndWnd:          number | null;
  tcpCongestion:      string | null;
  // sender counters
  retransmits:        number;
  durationS:          number;
  // iperf3 host (sender) CPU
  cpuHostTotal:       number;
  cpuHostUser:        number;
  cpuHostSystem:      number;
  // iperf3 remote (receiver) CPU
  cpuRemoteTotal:     number;
  cpuRemoteUser:      number | null;
  cpuRemoteSystem:    number | null;
  // UDP-specific (receiver side)
  jitterMs:           number | null;
  lostPackets:        number | null;
  sentPackets:        number | null;
  rcvPackets:         number | null;
  lostPercent:        number | null;
}

// ── SAR CPU aggregate ────────────────────────────────────────────────────────
export interface CpuMetrics {
  avgUsr:    number;
  avgNice:   number;
  avgSys:    number;
  avgIowait: number;
  avgSoft:   number;
  avgIdle:   number;
  avgTotal:  number;
  samples:   number;
}

// ── HTB tc class stats ───────────────────────────────────────────────────────
export interface HtbClassStats {
  rate:           string;
  bytesSent:      number;
  packets:        number;
  dropped:        number;
  overlimits:     number;
  lended:         number;
  borrowedPkt:    number;
  tokens:         number;
  ctokens:        number;
  requeues:       number;
  giants:         number;
  throughputMbps: number;
}

// ── eBPF map class stats ─────────────────────────────────────────────────────
export interface EbpfClassStats {
  classKey:       number;
  packets:        number;
  bytes:          number;
  borrowed:       number;
  ecnMarked:      number;
  delayed:        number;
  throughputMbps: number;
}

// ── QoS aggregate (one mode, one protocol) ──────────────────────────────────
export interface QosMetrics {
  ef?:        IperfMetrics;
  af?:        IperfMetrics;
  be?:        IperfMetrics;
  cpu?:       CpuMetrics;
  tcClasses?: Record<string, HtbClassStats>;
  mapStats?:  Record<string, EbpfClassStats>;
}

// ── Dataset list / detail ────────────────────────────────────────────────────
export interface DatasetSummary {
  id:               number;
  name:             string;
  description?:     string;
  created_at:       string;
  experiment_count: number;
}

export interface Dataset extends DatasetSummary {
  protocols:            string[];
  primaryProtocol:      string | null;
  metrics: {
    no_qos?: QosMetrics;
    htb?:    QosMetrics;
    ebpf?:   QosMetrics;
  };
  metricsByProtocol:    Record<string, { no_qos?: QosMetrics; htb?: QosMetrics; ebpf?: QosMetrics }>;
  timeSeries:           Record<string, TimePoint[]>;
  timeSeriesByProtocol: Record<string, Record<string, TimePoint[]>>;
}

export interface TimePoint {
  t:             number;
  bitsPerSecond: number;
  rttUs:         number;
  retransmits:   number;
}

export type QosType      = 'no_qos' | 'htb' | 'ebpf';
export type TrafficClass = 'ef' | 'af' | 'be';
export type ExperimentType = 'iperf' | 'cpu' | 'htb_tc' | 'ebpf_map';

// ── Experiment list / detail ─────────────────────────────────────────────────
export interface ExperimentSummary {
  id:               number;
  dataset_id:       number;
  qos_type:         QosType;
  protocol:         string | null;
  traffic_class:    TrafficClass | null;
  experiment_type:  ExperimentType;
  source_filename:  string | null;
  created_at:       string;
  throughput_mbps?: number | null;
  avg_rtt_us?:      number | null;
  retransmits?:     number | null;
  interval_count:   number;
  snapshot_count:   number;
  htb_class_count:  number;
  ebpf_class_count: number;
}

// ── iperf3 per-second interval ───────────────────────────────────────────────
export interface IperfInterval {
  id:              number;
  interval_start:  number;
  interval_end:    number;
  bytes:           number;
  bits_per_second: number;
  retransmits:     number;
  rtt_us:          number | null;
}

// ── SAR CPU snapshot (raw row) ───────────────────────────────────────────────
export interface CpuSnapshot {
  id:            number;
  snapshot_time: string;
  cpu_core:      string;
  usr_pct:       number;
  nice_pct:      number;
  sys_pct:       number;
  iowait_pct:    number;
  soft_pct:      number;
  idle_pct:      number;
}

// ── HTB class (raw DB row) ───────────────────────────────────────────────────
export interface HtbClass {
  id:           number;
  class_id:     string;
  rate:         string;
  bytes_sent:   number;
  packets:      number;
  dropped:      number;
  overlimits:   number;
  lended:       number;
  borrowed_pkt: number;
  tokens:       number;
  ctokens:      number;
  requeues:     number;
  giants:       number;
}

// ── eBPF class (raw DB row) ──────────────────────────────────────────────────
export interface EbpfClass {
  id:         number;
  class_key:  number;
  class_name: string;
  packets:    number;
  bytes:      number;
  borrowed:   number;
  ecn_marked: number;
  delayed:    number;
}

// ── iperf summary row (snake_case — API shape for mode endpoint) ─────────────
export interface IperfSummaryRow {
  throughput_mbps:      number;
  rcv_bytes:            number | null;
  sent_throughput_mbps: number | null;
  sent_bytes:           number | null;
  delivery_ratio:       number | null;
  avg_rtt_us:           number;
  max_rtt_us:           number;
  min_rtt_us:           number;
  rtt_std_us:           number;
  max_snd_cwnd:         number | null;
  max_snd_wnd:          number | null;
  tcp_congestion:       string | null;
  retransmits:          number;
  duration_s:           number;
  cpu_host_total:       number;
  cpu_host_user:        number;
  cpu_host_system:      number;
  cpu_remote_total:     number;
  cpu_remote_user:      number | null;
  cpu_remote_system:    number | null;
  jitter_ms:            number | null;
  lost_packets:         number | null;
  sent_packets:         number | null;
  rcv_packets:          number | null;
  lost_percent:         number | null;
}

export interface ModeIperfEntry {
  summary:   IperfSummaryRow | null;
  intervals: IperfInterval[];
}

// ── Mode detail response ─────────────────────────────────────────────────────
export interface ModeData {
  dataset_id:            number;
  dataset_name:          string;
  qos_type:              QosType;
  iperf:                 Partial<Record<TrafficClass, ModeIperfEntry>>;
  cpu:                   { snapshots: CpuSnapshot[] };
  htbClasses:            HtbClass[];
  ebpfClasses:           EbpfClass[];
  timeSeries:            Record<string, TimePoint[]>;
  iperfByProtocol:       Partial<Record<string, Partial<Record<TrafficClass, ModeIperfEntry>>>>;
  cpuByProtocol:         Partial<Record<string, { snapshots: CpuSnapshot[] }>>;
  htbClassesByProtocol:  Partial<Record<string, HtbClass[]>>;
  ebpfClassesByProtocol: Partial<Record<string, EbpfClass[]>>;
}

// ── Experiment detail ────────────────────────────────────────────────────────
export interface ExperimentDetail extends ExperimentSummary {
  dataset_name: string;
  summary:      IperfSummaryRow | null;
  intervals:    IperfInterval[];
  cpuSnapshots: CpuSnapshot[];
  htbClasses:   HtbClass[];
  ebpfClasses:  EbpfClass[];
}
