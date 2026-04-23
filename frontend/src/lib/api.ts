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

  // ── CIC-IDS-2017 upload & logs ───────────────────────────────────────────
  uploadCsv: (file: File, onProgress?: (pct: number) => void) => {
    const form = new FormData();
    form.append("file", file);
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

  getCicidsStats: () =>
    http.get<CicidsStats>("/cicids/stats").then(r => r.data),

  generateIrReport: (sourceFile = "") =>
    http.post<IrReport>("/cicids/analyze", null, { params: { source_file: sourceFile } }).then(r => r.data),

  analyzeIncident: (log: CicidsLog) =>
    http.post<{ report: string; ai_generated: boolean; generated_at: string; cti: CtiEnrichment; rag_chunks?: string[] }>(
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

  getConfigStatus: () =>
    http.get<{
      ollama: boolean; abuseipdb: boolean; virustotal: boolean;
      soar_live: boolean; ollama_model: string;
    }>("/config/status").then(r => r.data),

  resetSystem: () =>
    http.delete<{ status: string; message: string; rows_deleted: number }>(
      "/system/reset",
    ).then(r => r.data),

  // ── WebAuthn / FIDO2 ─────────────────────────────────────────────────────
  webauthn: {
    registerOptions: (username: string) =>
      http.post("/webauthn/register-options", { username }).then(r => r.data),
      
    registerVerify: (username: string, response: any) =>
      http.post<{ status: string }>("/webauthn/register-verify", { username, response }).then(r => r.data),
      
    authOptions: (username: string, nonce: string) =>
      http.post("/webauthn/auth-options", { username, nonce }).then(r => r.data),
      
    authVerify: (username: string, nonce: string, response: any, receipt: any, target_ip?: string, label?: string) =>
      http.post<{ status: string; message: string }>("/webauthn/auth-verify", 
        { username, nonce, response, receipt, target_ip, label }
      ).then(r => r.data),
  }
};
