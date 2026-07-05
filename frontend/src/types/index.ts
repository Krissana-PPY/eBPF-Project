export interface IperfMetrics {
  throughputMbps: number;
  avgRttUs:       number;
  maxRttUs:       number;
  minRttUs:       number;
  rttStdUs:       number;
  retransmits:    number;
  durationS:      number;
  cpuHostTotal:   number;
  cpuHostUser:    number;
  cpuHostSystem:  number;
  cpuRemoteTotal: number;
}

export interface CpuMetrics {
  avgUsr:   number;
  avgSys:   number;
  avgSoft:  number;
  avgIdle:  number;
  avgTotal: number;
  samples:  number;
}

export interface HtbClassStats {
  rate:           string;
  bytesSent:      number;
  packets:        number;
  dropped:        number;
  overlimits:     number;
  throughputMbps: number;
}

export interface EbpfClassStats {
  classKey:       number;
  packets:        number;
  bytes:          number;
  borrowed:       number;
  ecnMarked:      number;
  delayed:        number;
  throughputMbps: number;
}

export interface QosMetrics {
  ef?:        IperfMetrics;
  af?:        IperfMetrics;
  be?:        IperfMetrics;
  cpu?:       CpuMetrics;
  tcClasses?: Record<string, HtbClassStats>;
  mapStats?:  Record<string, EbpfClassStats>;
}

export interface DatasetSummary {
  id:               number;
  name:             string;
  description?:     string;
  created_at:       string;
  experiment_count: number;
}

export interface Dataset extends DatasetSummary {
  metrics: {
    no_qos?: QosMetrics;
    htb?:    QosMetrics;
    ebpf?:   QosMetrics;
  };
  timeSeries: Record<string, TimePoint[]>;
}

export interface TimePoint {
  t:             number;
  bitsPerSecond: number;
  rttUs:         number;
  retransmits:   number;
}

export type QosType = 'no_qos' | 'htb' | 'ebpf';
export type TrafficClass = 'ef' | 'af' | 'be';
export type ExperimentType = 'iperf' | 'cpu' | 'htb_tc' | 'ebpf_map';

export interface ExperimentSummary {
  id:               number;
  dataset_id:       number;
  qos_type:         QosType;
  traffic_class:    TrafficClass | null;
  experiment_type:  ExperimentType;
  source_filename:  string | null;
  created_at:       string;
  // aggregated from iperf_summary (may be null for non-iperf)
  throughput_mbps?: number | null;
  avg_rtt_us?:      number | null;
  retransmits?:     number | null;
  // row counts
  interval_count:   number;
  snapshot_count:   number;
  htb_class_count:  number;
  ebpf_class_count: number;
}

export interface IperfInterval {
  id:              number;
  interval_start:  number;
  interval_end:    number;
  bytes:           number;
  bits_per_second: number;
  retransmits:     number;
  rtt_us:          number | null;
}

export interface CpuSnapshot {
  id:            number;
  snapshot_time: string;
  cpu_core:      string;
  usr_pct:       number;
  sys_pct:       number;
  soft_pct:      number;
  idle_pct:      number;
}

export interface HtbClass {
  id:         number;
  class_id:   string;
  rate:       string;
  bytes_sent: number;
  packets:    number;
  dropped:    number;
  overlimits: number;
}

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

export interface IperfSummaryRow {
  throughput_mbps:  number;
  avg_rtt_us:       number;
  max_rtt_us:       number;
  min_rtt_us:       number;
  rtt_std_us:       number;
  retransmits:      number;
  duration_s:       number;
  cpu_host_total:   number;
  cpu_host_user:    number;
  cpu_host_system:  number;
  cpu_remote_total: number;
}

export interface ModeIperfEntry {
  summary: IperfSummaryRow | null;
  intervals: IperfInterval[];
}

export interface ModeData {
  dataset_id:   number;
  dataset_name: string;
  qos_type:     QosType;
  iperf:        Partial<Record<TrafficClass, ModeIperfEntry>>;
  cpu:          { snapshots: CpuSnapshot[] };
  htbClasses:   HtbClass[];
  ebpfClasses:  EbpfClass[];
  timeSeries:   Record<string, TimePoint[]>;
}

export interface ExperimentDetail extends ExperimentSummary {
  dataset_name: string;
  summary:      IperfSummaryRow | null;
  intervals:    IperfInterval[];
  cpuSnapshots: CpuSnapshot[];
  htbClasses:   HtbClass[];
  ebpfClasses:  EbpfClass[];
}
