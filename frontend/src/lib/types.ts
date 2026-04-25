export type Severity        = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ThreatCategory  = "BRUTE_FORCE" | "PORT_SCAN" | "MALWARE" | "EXFILTRATION" | "ANOMALY" | "BENIGN";
export type PlaybookStatus  = "SIMULATED" | "ESCALATED" | "SKIPPED";

export interface Recommendation {
  action:   string;
  priority: number;
}

export interface Alert {
  alert_id:            string;
  timestamp:           string;
  severity:            Severity;
  category:            ThreatCategory;
  confidence:          number;
  source_ip:           string | null;
  affected_asset:      string | null;
  mitre_techniques:    string[];
  raw_log_excerpt:     string;
  ai_reasoning:        string;
  recommendations:     Recommendation[];
  false_positive_risk: "LOW" | "MEDIUM" | "HIGH";
  log_type:            string;
  source_type:         string;
  playbook_triggered:  string | null;
  scan_run_id:         string | null;
  grounding_available: boolean | null;
  grounding_score:     number | null;
}

export interface DashboardStats {
  // AI-triage alert counts (alerts table)
  total_alerts:      number;
  by_severity:       Record<Severity, number>;
  by_category:       Record<ThreatCategory, number>;
  total_scans:       number;
  last_scan_at:      string | null;
  // Raw CIC-IDS-2017 event counts (cicids_events table)
  total_events:      number;
  critical_events:   number;
  suspicious_events: number;
  benign_events:     number;
  // Business ROI
  hours_saved:       number;
  cost_saved:        number;
}

export interface PlaybookLogEntry {
  id:               number;
  executed_at:      string;
  playbook_name:    string;
  alert_id:         string;
  trigger_category: ThreatCategory;
  confidence:       number;
  simulated_action: string;
  action_detail:    string;
  status:           PlaybookStatus;
  execution_time_ms:number;
  affected_asset:   string | null;
  notes:            string;
}

export interface NarrativeReport {
  scan_run_id:          string;
  generated_at:         string;
  narrative_text:       string;
  kill_chain_stage:     string;
  kill_chain_index:     number;
  total_alerts:         number;
  critical_count:       number;
  high_count:           number;
  unique_attackers:     string[];
  mitre_techniques:     string[];
  recommended_priority: Severity;
  tlp_classification:   string;
  playbooks_fired:      string[];
}

// ── CIC-IDS-2017 ──────────────────────────────────────────────────────────────

export interface CicidsLog {
  id:            number | string;
  ingested_at:   string;
  src_ip:        string | null;
  dst_ip:        string | null;
  dst_port:      number | null;
  protocol:      number | string | null;
  label:         string;
  severity:      Severity;
  category:      string;
  flow_duration: number | null;
  flow_bytes_s:  number | null;
  source_file:   string;
  raw_text?:     string;
}

export interface CicidsStats {
  total:       number;
  by_label:    Record<string, number>;
  by_severity: Record<string, number>;
}

export interface AttackDetail {
  attack_type:      string;
  count:            number;
  description:      string;
  mitre_techniques: string[];
  mitigation_steps: string[];
}

export interface IrReport {
  report_id:                  string;
  generated_at:               string;
  source_file:                string;
  total_events_analyzed:      number;
  executive_summary:          string;
  attack_details:             AttackDetail[];
  immediate_actions:          string[];
  long_term_recommendations:  string[];
  severity_assessment:        string;
  affected_systems:           string[];
}

export interface MonitorStatus {
  active:              boolean;
  watch_path:          string;
  files_processed:     number;
  last_processed_file: string | null;
  last_processed_at:   string | null;
}

export interface MitreTechnique {
  id:     string;
  name:   string;
  tactic: string;
}

export interface CtiEnrichment {
  ip:          string | null;
  abuseipdb: {
    abuse_confidence_score?: number;
    country_code?:           string;
    isp?:                    string;
    domain?:                 string;
    total_reports?:          number;
    last_reported_at?:       string;
    is_tor?:                 boolean;
    usage_type?:             string;
    skipped?:                boolean;
    reason?:                 string;
    error?:                  string;
  };
  virustotal: {
    is_mocked?:     boolean;
    malicious?:     number;
    suspicious?:    number;
    harmless?:      number;
    undetected?:    number;
    total_engines?: number;
    threat_label?:  string;
    last_analysis?: string;
    skipped?:       boolean;
    reason?:        string;
  };
  mitre: MitreTechnique[];
}

export interface CicidsPlaybookLog {
  id:            number;
  executed_at:   string;
  playbook_name: string;
  action:        string;
  status:        string;
  target_ip:     string | null;
  target_port:   number | null;
  label:         string;
  severity:      string;
  source_file:   string;
  action_detail: string;
}

// ── Pipeline telemetry ingestion ─────────────────────────────────────────────

export interface CisoPipelineSummary {
  total_alerts:        number;
  by_severity:         Record<string, number>;
  top_techniques:      { id: string; name: string; count: number }[];
  top_attacker_ips:    { ip: string; count: number }[];
  top_labels:          { label: string; count: number }[];
  analyst_hours_saved: number;
  cost_avoided_usd:    number;
}

export interface PipelineSession {
  session_id:      string;
  filename:        string;
  dataset_type:    string | null;
  started_at:      string;
  completed_at:    string | null;
  status:          "pending" | "running" | "complete" | "error";
  rows_processed:  number;
  alerts_found:    number;
  chain_root_hash: string | null;
  chain_tip_hash:  string | null;
  ciso_summary:    CisoPipelineSummary | null;
}

/** Lightweight polling response from /api/sessions/{id}/status */
export interface SessionStatus {
  session_id:      string;
  status:          "pending" | "running" | "complete" | "error";
  rows_processed:  number;
  alerts_found:    number;
  /** Only present when status === "complete" */
  ciso_summary?:   CisoPipelineSummary | null;
  chain_tip_hash?: string | null;
}

/** Stored in App global state after a pipeline session completes */
export interface PipelineCompletion {
  session_id:      string;
  filename:        string;
  chain_tip_hash:  string;
  ciso_summary:    CisoPipelineSummary;
  rows_processed:  number;
  alerts_found:    number;
}

export interface PipelineAlert {
  id:              number;
  session_id:      string;
  ingested_at:     string;
  dataset_type:    string;
  source_ip:       string | null;
  dest_ip:         string | null;
  dest_port:       number | null;
  protocol:        string | null;
  label:           string;
  severity:        Severity;
  mitre_technique: string | null;
  mitre_name:      string | null;
  bytes_total:     number | null;
  chain_hash:      string | null;
}

export type PipelineWsMessage =
  | { type: "pipeline_stage";    session_id: string; stage: string; message: string; dataset_type?: string }
  | { type: "pipeline_progress"; session_id: string; stage: string; rows_processed: number; alerts_found: number }
  | { type: "pipeline_complete"; session_id: string; filename: string; dataset_type: string; rows_processed: number; alerts_found: number; chain_tip: string; root_hash: string; ciso: CisoPipelineSummary }
  | { type: "pipeline_error";    session_id: string; error: string; traceback?: string };

// ── WebSocket message union ───────────────────────────────────────────────────

export type WsMessage =
  | { type: "scan_started";          scan_run_id: string; dataset: string }
  | { type: "new_alert";             data: Partial<Alert> }
  | { type: "playbook_executed";     data: PlaybookLogEntry }
  | { type: "scan_complete";         scan_run_id: string; alerts_generated: number; playbooks_fired: number }
  | { type: "scan_error";            scan_run_id: string; error: string }
  | { type: "ingest_started";        filename: string; source: string }
  | { type: "ingest_complete";       data: { total_parsed: number; total_stored: number; by_sourcetype: Record<string, number>; skipped: number; dataset_name: string } }
  | { type: "ingest_error";          filename: string; error: string }
  | { type: "cicids_ingest_started"; filename: string; source: string }
  | { type: "cicids_ingest_complete";filename: string; data: CicidsStats }
  | { type: "cicids_ingest_error";   filename: string; error: string }
  | { type: "monitor_file_detected"; filename: string; path: string }
  | { type: "cicids_playbook_fired";    data: CicidsPlaybookLog }
  | { type: "cti_enrichment_started";  filename: string; ip_count: number }
  | { type: "cti_enrichment_complete"; filename: string; results: Record<string, unknown> }
  | { type: "firewall_block";   data: { src_ip: string; category: string; confidence_pct: number; id: number; blocked_at: string; nonce_prefix: string } }
  | { type: "abc_proving";      data: { record_id: number; src_ip: string } }
  | { type: "abc_auto_block";   data: { record_id: number; src_ip: string; fc: number; firewall_rule_id: number; category: string; confidence_pct: number } }
  | { type: "abc_low_confidence"; data: { record_id: number; confidence_pct: number } }
  | PipelineWsMessage;
