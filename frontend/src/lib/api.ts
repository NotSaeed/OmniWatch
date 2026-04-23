import axios from "axios";
import type {
  Alert,
  CicidsLog,
  CicidsPlaybookLog,
  CicidsStats,
  CtiEnrichment,
  DashboardStats,
  IrReport,
  MonitorStatus,
  NarrativeReport,
  PlaybookLogEntry,
} from "./types";

const http = axios.create({ baseURL: "/api" });

export const api = {
  // ── Alerts & stats ───────────────────────────────────────────────────────
  getAlerts: (params?: {
    limit?: number; offset?: number;
    severity?: string; category?: string; source_type?: string;
  }) => http.get<Alert[]>("/alerts", { params }).then(r => r.data),

  getAlert: (id: string) =>
    http.get<Alert>(`/alerts/${id}`).then(r => r.data),

  getStats: () =>
    http.get<DashboardStats>("/stats").then(r => r.data),

  // ── Scans ────────────────────────────────────────────────────────────────
  triggerScan: (dataset = "simulated") =>
    http.post("/trigger-scan", null, { params: { dataset } }).then(r => r.data),

  getNarrative: (scanRunId: string) =>
    http.get<NarrativeReport>(`/scan/${scanRunId}/narrative`).then(r => r.data),

  // ── BOTSv3 ingestion ─────────────────────────────────────────────────────
  ingestDataset: (filePath: string) =>
    http.post("/ingest", null, { params: { file_path: filePath } }).then(r => r.data),

  getDatasetStats: () =>
    http.get("/dataset-stats").then(r => r.data),

  getBotsv3Dashboard: () =>
    http.get("/botsv3/dashboard").then(r => r.data),

  // ── CIC-IDS-2017 upload & logs ───────────────────────────────────────────
  uploadCsv: (file: File, onProgress?: (pct: number) => void) => {
    const form = new FormData();
    form.append("file", file);
    form.append("total_size", file.size.toString());
    return http.post<{ status: string; filename: string; path: string }>(
      "/upload",
      form,
      {
        headers: { "Content-Type": "multipart/form-data" },
        onUploadProgress: e => {
          if (onProgress && e.total) onProgress(Math.round((e.loaded * 100) / e.total));
        },
      },
    ).then(r => r.data);
  },

  getCicidsLogs: (params?: {
    search?: string; severity?: string; label?: string;
    limit?: number; offset?: number;
  }) => http.get<CicidsLog[]>("/cicids/logs", { params }).then(r => r.data),

  getBotsv3Logs: (params?: {
    search?: string; limit?: number; offset?: number;
  }) => http.get<CicidsLog[]>("/botsv3/logs", { params }).then(r => r.data),

  getCicidsStats: () =>
    http.get<CicidsStats>("/cicids/stats").then(r => r.data),

  generateIrReport: (sourceFile = "") =>
    http.post<IrReport>("/cicids/analyze", null, { params: { source_file: sourceFile } }).then(r => r.data),

  analyzeIncident: (log: CicidsLog) =>
    http.post<{ report: string; ai_generated: boolean; generated_at: string; cti: CtiEnrichment }>(
      "/analyze-incident", log,
    ).then(r => r.data),

  // ── Monitor ──────────────────────────────────────────────────────────────
  getMonitorStatus: () =>
    http.get<MonitorStatus>("/monitor/status").then(r => r.data),

  // ── Playbook log ─────────────────────────────────────────────────────────
  getPlaybookLog: (limit = 50) =>
    http.get<PlaybookLogEntry[]>("/playbook-log", { params: { limit } }).then(r => r.data),

  // ── CIC-IDS-2017 SOAR ────────────────────────────────────────────────────
  getCicidsPlaybookLogs: (limit = 100) =>
    http.get<CicidsPlaybookLog[]>("/cicids/playbook-logs", { params: { limit } }).then(r => r.data),

  getActionedIps: () =>
    http.get<string[]>("/cicids/actioned-ips").then(r => r.data),

  getHourlyDistribution: () =>
    http.get<Array<{ hour: number; total: number; threats: number; benign: number }>>(
      "/stats/hourly-distribution"
    ).then(r => r.data),

  getConfigStatus: () =>
    http.get<{
      ollama: boolean; abuseipdb: boolean; virustotal: boolean;
      soar_live: boolean; ollama_model: string;
    }>("/config/status").then(r => r.data),

  resetSystem: () =>
    http.delete<{ status: string; message: string; rows_deleted: number }>(
      "/system/reset",
    ).then(r => r.data),

  // ── Firewall audit ──────────────────────────────────────────────────────────
  getFirewallProof: (ruleId: number) =>
    http.get(`/firewall/proof/${ruleId}`).then(r => r.data),

  // ── Autonomous Breach Containment ────────────────────────────────────────────
  toggleAbc: (enabled: boolean) =>
    http.post<{ enabled: boolean; processed_count: number; confidence_threshold: number }>(
      `/abc/toggle?enabled=${enabled}`,
    ).then(r => r.data),

  getAbcStatus: () =>
    http.get<{ enabled: boolean; processed_count: number; confidence_threshold: number }>(
      "/abc/status",
    ).then(r => r.data),

  // ── Trust Chain / Sprint 5 ──────────────────────────────────────────────
  generateStarkProof: (recordId: number) =>
    http.post<{ success: boolean; receipt_b64: string }>(`/edge/prove/${recordId}`).then(r => r.data),

  fido2SignBegin: (receiptB64: string, mockFido2 = true) =>
    http.post<{ session_id: string; options: any; mock_fido2?: boolean }>(
      "/auth/sign/begin",
      { user_id: "analyst-01", stark_receipt_b64: receiptB64, mock_fido2: mockFido2 },
    ).then(r => r.data),

  verifyRemediation: (payload: {
    session_id: string;
    stark_receipt_b64: string;
    assertion_response: Record<string, unknown>;
    mock_fido2?: boolean;
    src_ip?: string;
  }) =>
    http.post<{
      authorized: boolean; nonce: string;
      is_threat: boolean; category: string; confidence_pct: number;
      triggered_rules: number; credential_id: string; new_sign_count: number;
    }>("/verify-remediation", payload).then(r => r.data),
};
