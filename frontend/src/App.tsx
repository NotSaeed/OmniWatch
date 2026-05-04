import { Component } from "react";
import type { ErrorInfo, ReactNode } from "react";
import { useState, useCallback, useEffect, useRef } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Toaster, toast } from "sonner";
import {
  Area, Bar, BarChart, Brush, CartesianGrid, Cell, ComposedChart,
  ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { useMemo } from "react";
import {
  LayoutDashboard, Search, Zap, Settings2,
  Upload, ChevronLeft, ChevronRight,
  Wifi, WifiOff, Loader2, Eye, Shield, Trash2,
  BarChart2 as BarChart2Icon, TrendingUp as TrendingUpIcon,
} from "lucide-react";

import { api } from "./lib/api";
import type { Alert, CicidsPlaybookLog, CicidsStats, CisoPipelineSummary, DashboardStats, PipelineAlert, PipelineCompletion, PipelineSession, PipelineWsMessage, WsMessage } from "./lib/types";
import { useWebSocket } from "./hooks/useWebSocket";


import { MitreHeatmap } from "./components/MitreHeatmap";
import { LogExplorer } from "./components/LogExplorer";
import type { LogFilters } from "./components/LogExplorer";
import { TopThreatSourcesPanel } from "./components/TopThreatSourcesPanel";
import { ExecutiveBriefDrawer } from "./components/ExecutiveBriefDrawer";
import { SOARActivity } from "./components/SOARActivity";
import { PlaybookTimeline } from "./components/PlaybookTimeline";
import type { ActionOverride } from "./components/PlaybookTimeline";
import { SettingsPage } from "./components/SettingsPage";
import { TrustChainDAG } from "./components/TrustChainDAG";
import { EdgeTelemetryPanel } from "./components/EdgeTelemetryPanel";
import { FirewallHistoryPanel } from "./components/FirewallHistoryPanel";
import { RemediationPlanPanel } from "./components/RemediationPlanPanel";
import { SeverityChart } from "./components/SeverityChart";
import { TelemetryUploader } from "./components/TelemetryUploader";
import { AiIncidentReview } from "./components/AiIncidentReview";
import type { TrustNode, NodeState } from "./components/TrustChainDAG";
import { ErrorBoundary } from "./components/ErrorBoundary";
import logo from "./assets/logo.svg";
import icon from "./assets/icon.svg";

type Page = "dashboard" | "logexplorer" | "playbooks" | "trustchain" | "settings";

// ── Error boundary — prevents a single widget crash from blanking the page ────

class PanelErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(_error: Error, _info: ErrorInfo) { }
  render() {
    if (this.state.error) {
      return (
        <div className="flex items-center justify-center p-6 rounded-lg"
          style={{ background: "#0d0d10", border: "1px solid #2e3038", color: "#4d5060" }}>
          <span className="text-xs font-mono">Panel error — check console</span>
        </div>
      );
    }
    return this.props.children;
  }
}

// ── AI Sparkle icon ───────────────────────────────────────────────────────────

function AISparkleIcon({ className = "w-4 h-4" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" aria-hidden="true">
      <defs>
        <linearGradient id="sparkle-ai" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#d946ef" />
          <stop offset="100%" stopColor="#06b6d4" />
        </linearGradient>
      </defs>
      {/* Main 4-pointed star */}
      <path
        d="M12 2 L13.8 9.2 L21 12 L13.8 14.8 L12 22 L10.2 14.8 L3 12 L10.2 9.2 Z"
        fill="url(#sparkle-ai)"
      />
      {/* Small accent star top-right */}
      <path
        d="M19.5 4 L20.2 6.3 L22.5 7 L20.2 7.7 L19.5 10 L18.8 7.7 L16.5 7 L18.8 6.3 Z"
        fill="url(#sparkle-ai)"
        opacity="0.65"
      />
    </svg>
  );
}

// ── Nav items ─────────────────────────────────────────────────────────────────

type NavItem = {
  page: Page;
  label: string;
  Icon: React.ComponentType<{ className?: string; strokeWidth?: number }>;
  description: string;
};

const NAV_ITEMS: NavItem[] = [
  { page: "dashboard", label: "Dashboard", Icon: LayoutDashboard, description: "Live overview & AI alerts" },
  { page: "logexplorer", label: "Log Explorer", Icon: Search, description: "Network flow telemetry search" },
  { page: "trustchain", label: "Trust Chain", Icon: Shield, description: "Cryptographic verification DAG" },
  { page: "playbooks", label: "Playbook Activity", Icon: Zap, description: "SOAR automation logs" },
  { page: "settings", label: "Settings", Icon: Settings2, description: "API keys & configuration" },
];

// ── Session switcher dropdown ─────────────────────────────────────────────────

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso.slice(0, 10);
  const now = new Date();
  const diff = (now.getTime() - d.getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 86400 * 2) return "yesterday";
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function fmtNum(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}k`;
  return String(n);
}

function SessionSwitcherDropdown({
  activeSessionId,
  activeFileName,
  onSwitch,
  onDelete,
}: {
  activeSessionId: string | null;
  activeFileName: string | null;
  onSwitch: (session: PipelineSession) => void;
  onDelete: (sessionId: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  const { data: sessions, refetch } = useQuery({
    queryKey: ["pipeline-sessions-list"],
    queryFn: () => api.getPipelineSessions(50),
    staleTime: 30_000,
  });

  const handleOpen = () => { setOpen(o => !o); refetch(); };

  const STATUS_DOT: Record<string, string> = {
    complete: "#22c55e",
    running: "#f59e0b",
    pending: "#4e9af1",
    error: "#e84d4d",
  };

  return (
    <div ref={ref} className="relative">
      {/* ── Trigger ── */}
      <button
        onClick={handleOpen}
        className="flex items-center gap-1.5 px-2.5 py-1 rounded transition-colors"
        style={{
          background: open ? "rgba(78,154,241,0.14)" : "rgba(78,154,241,0.08)",
          border: "1px solid rgba(78,154,241,0.25)",
        }}
      >
        <span className="w-1.5 h-1.5 rounded-full shrink-0"
          style={{
            background: activeSessionId ? "#4e9af1" : "#3d3f4a",
            boxShadow: activeSessionId ? "0 0 6px #4e9af180" : "none"
          }} />
        <span className="text-[10px] font-medium" style={{ color: "#4e9af1" }}>
          {activeFileName
            ? <span className="font-mono font-semibold truncate max-w-[160px] inline-block align-bottom"
              style={{ color: "#c5c7d4" }}>{activeFileName}</span>
            : <span style={{ color: "#4d5060" }}>No dataset</span>
          }
        </span>
        <ChevronRight
          className="w-3 h-3 shrink-0 transition-transform"
          style={{ color: "#4e9af1", transform: open ? "rotate(90deg)" : "rotate(0deg)" }}
        />
      </button>

      {/* ── Dropdown panel ── */}
      {open && (
        <div
          className="absolute left-0 top-full mt-1 z-50 rounded-lg overflow-hidden"
          style={{
            width: 340,
            background: "#0d0e14",
            border: "1px solid #2e3038",
            boxShadow: "0 8px 32px rgba(0,0,0,0.6)",
          }}
        >
          <div className="flex items-center justify-between px-3 py-2"
            style={{ borderBottom: "1px solid #1e1f26" }}>
            <span className="text-[9px] uppercase tracking-widest font-semibold" style={{ color: "#4d5060" }}>
              Saved Datasets
            </span>
            <span className="text-[9px] font-mono" style={{ color: "#3d3f4a" }}>
              {sessions?.length ?? 0} session{sessions?.length !== 1 ? "s" : ""}
            </span>
          </div>

          <div className="overflow-y-auto" style={{ maxHeight: 320 }}>
            {!sessions || sessions.length === 0 ? (
              <div className="px-3 py-4 text-center text-[11px]" style={{ color: "#4d5060" }}>
                No sessions found
              </div>
            ) : (
              sessions.map(s => {
                const isActive = s.session_id === activeSessionId;
                const isDeleting = s.session_id === deletingId;
                return (
                  <div
                    key={s.session_id}
                    className="flex items-center gap-2 px-3 py-2 cursor-pointer group"
                    style={{
                      borderBottom: "1px solid #1a1b22",
                      background: isActive ? "rgba(78,154,241,0.06)" : "transparent",
                    }}
                    onMouseEnter={e => { if (!isActive) (e.currentTarget as HTMLDivElement).style.background = "rgba(255,255,255,0.02)"; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.background = isActive ? "rgba(78,154,241,0.06)" : "transparent"; }}
                    onClick={() => { if (!isActive) { onSwitch(s); setOpen(false); } }}
                  >
                    {/* Status dot */}
                    <span className="w-1.5 h-1.5 rounded-full shrink-0"
                      style={{ background: STATUS_DOT[s.status] ?? "#4d5060" }} />

                    {/* Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="text-[11px] font-mono font-medium truncate"
                          style={{ color: isActive ? "#c5c7d4" : "#9ba3b8" }}>
                          {s.filename}
                        </span>
                        {isActive && (
                          <span className="px-1 py-px rounded text-[8px] font-bold uppercase shrink-0"
                            style={{ background: "rgba(78,154,241,0.18)", color: "#4e9af1" }}>
                            ACTIVE
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-[9px] font-mono tabular-nums" style={{ color: "#4d5060" }}>
                          {fmtNum(s.rows_processed)} rows
                        </span>
                        <span style={{ color: "#2e3038" }}>·</span>
                        <span className="text-[9px] font-mono tabular-nums" style={{ color: "#4d5060" }}>
                          {fmtNum(s.alerts_found)} alerts
                        </span>
                        <span style={{ color: "#2e3038" }}>·</span>
                        <span className="text-[9px] font-mono" style={{ color: "#3d3f4a" }}>
                          {fmtDate(s.started_at)}
                        </span>
                      </div>
                    </div>

                    {/* Delete button — confirm on second click */}
                    <button
                      className="shrink-0 w-5 h-5 flex items-center justify-center rounded transition-colors opacity-0 group-hover:opacity-100"
                      style={{
                        background: isDeleting ? "rgba(239,68,68,0.25)" : "rgba(239,68,68,0.08)",
                        border: `1px solid ${isDeleting ? "rgba(239,68,68,0.5)" : "rgba(239,68,68,0.2)"}`,
                        color: "#fca5a5",
                        opacity: isDeleting ? 1 : undefined,
                      }}
                      title={isDeleting ? "Confirm delete" : "Delete session"}
                      onClick={e => {
                        e.stopPropagation();
                        if (isDeleting) {
                          onDelete(s.session_id);
                          setDeletingId(null);
                        } else {
                          setDeletingId(s.session_id);
                          setTimeout(() => setDeletingId(null), 3000);
                        }
                      }}
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                );
              })
            )}
          </div>

          {/* Footer — Purge All */}
          <div className="px-3 py-2 flex items-center justify-between"
            style={{ borderTop: "1px solid #1e1f26" }}>
            <span className="text-[9px] font-mono" style={{ color: "#3d3f4a" }}>
              Click a session to switch · trash to remove
            </span>
            <button
              className="text-[9px] font-mono px-2 py-0.5 rounded transition-colors"
              style={{ color: "#6b6e80", background: "rgba(239,68,68,0.05)", border: "1px solid rgba(239,68,68,0.12)" }}
              onClick={() => { setOpen(false); onDelete("__ALL__"); }}
            >
              Purge All
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── App ───────────────────────────────────────────────────────────────────────

export default function App() {
  const qc = useQueryClient();

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [soarEntries, setSoarEntries] = useState<CicidsPlaybookLog[]>([]);
  const [scanning, setScanning] = useState(false);
  const [lastScanId, setLastScanId] = useState<string | null>(null);
  const [activePage, setActivePage] = useState<Page>("dashboard");
  const [sidebarOpen, setSidebarOpen] = useState(true);

  // ── Trust Chain & ABC State ────────────────────────────────────────────────
  const [isProvingRecordId, setIsProvingRecordId] = useState<number | null>(null);
  // Per-alert slide-over (AiIncidentReview) — set when analyst presses Enter on a row
  const [reviewAlert, setReviewAlert] = useState<import("./lib/types").PipelineAlert | null>(null);
  const [abcEnabled, setAbcEnabled] = useState(false);
  const { data: abcStatus } = useQuery({
    queryKey: ["abc-status"],
    queryFn: api.getAbcStatus,
    refetchInterval: 5000,
  });
  const { data: edgeStatusData } = useQuery({
    queryKey: ["edge-status"],
    queryFn: api.getEdgeStatus,
    refetchInterval: 5000,
  });
  const [dagNodes, setDagNodes] = useState<TrustNode[]>([
    { id: "edge", label: "Edge Telemetry", sublabel: "Pi 4 · Zeek + ICSNPP", state: "pending", position: [-4, 0.5, 0] },
    { id: "bincode", label: "Bincode Payload", sublabel: "61-byte serialized struct", state: "pending", position: [-1.5, 0.5, 0] },
    { id: "zkvm", label: "STARK Proof", sublabel: "RISC Zero zkVM (Machine)", state: "pending", position: [1.5, 0.5, 0] },
    { id: "gate", label: "Verification Gate", sublabel: "ZK Machine Verification", state: "pending", position: [4.5, 0.5, 0] },
    { id: "action", label: "Remediation", sublabel: "Network isolation · Firewall", state: "pending", position: [7, 0.5, 0] },
  ]);

  const updateNodeState = (id: string, state: NodeState) => {
    setDagNodes(prev => prev.map(n => n.id === id ? { ...n, state } : n));
  };

  useEffect(() => {
    const hasEdge = (edgeStatusData?.records_received ?? 0) > 0;
    setDagNodes(prev => prev.map(n =>
      n.id === "edge" || n.id === "bincode"
        ? { ...n, state: hasEdge ? "verified" : "pending" }
        : n,
    ));
  }, [edgeStatusData?.records_received]);

  // Selected pipeline alert for Remediation Bridge (Review & Sign → Trust Chain)
  const [selectedAlert, setSelectedAlert] = useState<PipelineAlert | null>(null);

  // Hydrate edge + zkvm DAG nodes when an alert is selected via Review & Sign
  useEffect(() => {
    if (!selectedAlert) return;
    const ts = new Date(selectedAlert.ingested_at).toLocaleTimeString(undefined, {
      hour: "2-digit", minute: "2-digit",
    });
    setDagNodes(prev => prev.map(n => {
      if (n.id === "edge") {
        return {
          ...n,
          sublabel: `${ts} · ${selectedAlert.mitre_technique ?? selectedAlert.mitre_name ?? "Unknown"} · ${selectedAlert.severity}`,
          state: "verifying" as NodeState,
        };
      }
      if (n.id === "zkvm") {
        return {
          ...n,
          sublabel: selectedAlert.chain_hash
            ? `${selectedAlert.chain_hash.substring(0, 8)}…`
            : "Awaiting proof",
        };
      }
      return n;
    }));
  }, [selectedAlert]);

  // Pipeline uploader modal
  const [showUploader, setShowUploader] = useState(false);
  const [pipelineWsMessage, setPipelineWsMessage] = useState<PipelineWsMessage | null>(null);

  // Global pipeline completion — set when any session reaches "complete".
  // Drives the Dashboard StatsCards and the TrustChain DAG hash display.
  const [pipelineCompletion, setPipelineCompletion] = useState<PipelineCompletion | null>(null);

  // Recover pipelineCompletion from the API on mount if a session_id was
  // stored in localStorage but the WebSocket completion message was missed
  // (e.g. the user reloaded the page after the pipeline finished).
  useEffect(() => {
    const storedId = localStorage.getItem("ow_session_id");
    if (!storedId) return;
    api.getPipelineSession(storedId)
      .then(session => {
        if (session.status === "complete" && session.ciso_summary && session.chain_tip_hash) {
          setPipelineCompletion({
            session_id: session.session_id,
            filename: session.filename,
            chain_tip_hash: session.chain_tip_hash,
            ciso_summary: session.ciso_summary,
            rows_processed: session.rows_processed,
            alerts_found: session.alerts_found,
          });
        }
      })
      .catch(() => {
        // Stored session no longer exists — clear stale localStorage keys
        localStorage.removeItem("ow_session_id");
        localStorage.removeItem("ow_session_file");
        setActiveSessionId(null);
        setActiveFileName(null);
      });
  }, []); // run once on mount only

  // Active session context — persisted in localStorage so a page reload restores
  // the session-scoped Log Explorer and CISO stats without re-uploading.
  const [activeSessionId, setActiveSessionId] = useState<string | null>(
    () => localStorage.getItem("ow_session_id"),
  );
  const [activeFileName, setActiveFileName] = useState<string | null>(
    () => localStorage.getItem("ow_session_file"),
  );

  // Deep-link filters: set by dashboard panels → consumed by LogExplorer on next render.
  const [logFilters, setLogFilters] = useState<LogFilters | null>(null);

  // Selected pipeline alert for Remediation Bridge (Review & Sign → Trust Chain)
  // Moved up

  // Clear-data two-step confirm
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearing, setClearing] = useState(false);
  const confirmTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── Data ───────────────────────────────────────────────────────────────────
  const { data: stats } = useQuery({
    queryKey: ["stats"],
    queryFn: api.getStats,
    refetchInterval: 5_000,
  });

  const { data: cicidsStats } = useQuery<CicidsStats>({
    // Re-fetch automatically when the active session changes.
    queryKey: ["cicids-stats", activeSessionId],
    queryFn: () => api.getCicidsStats(activeSessionId),
    refetchInterval: 60_000,
  });

  const { data: monitor } = useQuery({
    queryKey: ["monitor-status"],
    queryFn: api.getMonitorStatus,
    refetchInterval: 60_000,
  });

  const { data: botsData } = useQuery({
    queryKey: ["botsv3-dashboard"],
    queryFn: api.getBotsv3Dashboard,
    refetchInterval: 60_000,
  });

  const { data: initialAlerts } = useQuery({
    queryKey: ["alerts-init"],
    queryFn: () => api.getAlerts({ limit: 200 }),
  });

  useEffect(() => {
    if (initialAlerts) setAlerts(initialAlerts);
  }, [initialAlerts]);

  useEffect(() => {
    return () => {
      if (confirmTimerRef.current) clearTimeout(confirmTimerRef.current);
    };
  }, []);

  // ── WebSocket ──────────────────────────────────────────────────────────────
  const handleWsMessage = useCallback((msg: WsMessage) => {
    if (msg.type === "scan_started") {
      setScanning(true);
      toast.info("Scan started…");
    }
    if (msg.type === "new_alert" && msg.data) {
      setAlerts(prev => {
        if (prev.some(a => a.alert_id === (msg.data as Alert).alert_id)) return prev;
        return [msg.data as Alert, ...prev].slice(0, 200);
      });
    }
    if (msg.type === "scan_complete") {
      setScanning(false);
      setLastScanId(msg.scan_run_id);
      qc.invalidateQueries({ queryKey: ["stats"] });
      toast.success(`Scan complete — ${msg.alerts_generated} alerts, ${msg.playbooks_fired} playbooks`);
    }
    if (msg.type === "scan_error") {
      setScanning(false);
      toast.error(`Scan error: ${msg.error}`);
    }
    if (msg.type === "ingest_started") {
      toast.info(`BOTSv3: Ingesting ${msg.filename}…`, { description: "Processing rows in the background" });
    }
    if (msg.type === "ingest_complete") {
      qc.invalidateQueries({ queryKey: ["botsv3-dashboard"] });
      qc.invalidateQueries({ queryKey: ["stats"] });
      const total = msg.data.total_stored;
      toast.success(`BOTSv3 Ingestion Complete — ${total.toLocaleString()} raw events stored`, {
        description: "Heuristic Dashboard updated",
      });
    }
    if (msg.type === "ingest_error") {
      toast.error(`BOTSv3 Ingestion failed: ${msg.error}`, {
        description: `File: ${msg.filename}`,
        duration: 8000,
      });
    }
    if (msg.type === "cicids_ingest_started") {
      toast.info(`Ingesting ${msg.filename}…`, { description: "Processing rows in the background" });
    }
    if (msg.type === "cicids_ingest_complete") {
      qc.invalidateQueries({ queryKey: ["cicids-stats"] });
      qc.invalidateQueries({ queryKey: ["cicids-logs"] });
      qc.invalidateQueries({ queryKey: ["cicids-critical"] });
      qc.invalidateQueries({ queryKey: ["cicids-playbook-logs"] });
      qc.invalidateQueries({ queryKey: ["cicids-actioned-ips"] });
      qc.invalidateQueries({ queryKey: ["monitor-status"] });
      const inserted = (msg.data as { inserted?: number })?.inserted ?? 0;
      toast.success(`${msg.filename} — ${inserted.toLocaleString()} rows ingested`, {
        description: "Dashboard and Log Explorer have been updated",
      });
    }
    if (msg.type === "cicids_ingest_error") {
      toast.error(`Ingestion failed: ${msg.error}`);
    }
    if (msg.type === "monitor_file_detected") {
      toast.info(`Monitor: detected ${msg.filename}`);
    }
    if (msg.type === "cicids_playbook_fired" && msg.data) {
      setSoarEntries(prev => [msg.data as CicidsPlaybookLog, ...prev].slice(0, 100));
      const entry = msg.data as CicidsPlaybookLog;
      toast.success(
        `SOAR: ${entry.playbook_name.replace(/_Playbook$/, "").replace(/_/g, " ")} — ${entry.target_ip ?? "unknown"}`,
        { style: { background: "#1e1f23", border: "1px solid #2e3038" } },
      );
    }
    if (msg.type === "firewall_block") {
      qc.invalidateQueries({ queryKey: ["firewall-status"] });
      toast.success(
        `NETWORK ISOLATED — ${msg.data.src_ip} blocked (${msg.data.category} ${msg.data.confidence_pct}%)`,
        { duration: 8000, style: { background: "#052e16", border: "1px solid #16a34a" } },
      );
    }
    if (msg.type === "abc_proving") {
      // ABC uses machine proof only — fido2 stays pending (not involved in ABC)
      setDagNodes(prev => prev.map(n =>
        n.id === "zkvm" ? { ...n, state: "verifying" } :
          n.id === "gate" || n.id === "action" ? { ...n, state: "pending" } : n,
      ));
      toast.info(
        `ABC: Generating STARK proof for ${msg.data.src_ip} (#${msg.data.record_id})…`,
        { duration: 3000 },
      );
    }
    if (msg.type === "abc_auto_block") {
      // ABC is machine-only: STARK-proven but no human FIDO2 — leave fido2 node as pending
      setDagNodes(prev => prev.map(n =>
        n.id === "fido2" ? n : { ...n, state: "verified" as const },
      ));
      qc.invalidateQueries({ queryKey: ["firewall-status"] });
      toast.success(
        `ABC: Auto-blocked ${msg.data.src_ip} — Modbus FC${msg.data.fc} (${msg.data.confidence_pct}% conf.)`,
        { duration: 3000, style: { background: "#052516", border: "1px solid #06b6d4" } },
      );
    }
    if (msg.type === "cti_enrichment_started") {
      toast.info(`CTI: enriching ${msg.ip_count} IPs from ${msg.filename}`, {
        style: { background: "#1e1f23", border: "1px solid #2e3038" },
      });
    }
    if (msg.type === "cti_enrichment_complete") {
      const count = Object.keys(msg.results ?? {}).length;
      toast.success(`CTI complete — ${count} IPs analysed (AbuseIPDB + VirusTotal + MITRE)`, {
        style: { background: "#1e1f23", border: "1px solid #2e3038" },
        duration: 6000,
      });
    }
    if (
      msg.type === "pipeline_stage" || msg.type === "pipeline_progress" ||
      msg.type === "pipeline_complete" || msg.type === "pipeline_error"
    ) {
      setPipelineWsMessage(msg);
    }
    if (msg.type === "pipeline_complete") {
      const m = msg as any;
      const sid: string = m.session_id ?? "";
      const fname: string = m.filename ?? "";
      if (m.ciso_summary && m.chain_tip_hash) {
        setPipelineCompletion({
          session_id: sid,
          filename: fname,
          chain_tip_hash: m.chain_tip_hash,
          ciso_summary: m.ciso_summary,
          rows_processed: m.rows_processed ?? 0,
          alerts_found: m.alerts_found ?? 0,
        });
      }
      qc.invalidateQueries({ queryKey: ["stats"] });
      qc.invalidateQueries({ queryKey: ["botsv3-dashboard"] });
      // Bust both session-scoped stats and the logs query used by LogExplorer
      qc.invalidateQueries({ queryKey: ["cicids-stats"] });
      qc.invalidateQueries({ queryKey: ["pipeline-alerts"] });
      qc.invalidateQueries({ queryKey: ["logs", sid] });
    }
  }, [qc]);

  const wsConnected = useWebSocket(handleWsMessage);

  // ── Actions ────────────────────────────────────────────────────────────────

  // Deep-link from a dashboard panel into the Log Explorer with pre-filled filters.
  const navigateToLogExplorer = useCallback((filters: LogFilters) => {
    setLogFilters(filters);
    setActivePage("logexplorer");
  }, []);

  // Switch the active session — fetch full session details so pipelineCompletion is populated.
  const handleSwitchSession = useCallback(async (session: PipelineSession) => {
    setActiveSessionId(session.session_id);
    setActiveFileName(session.filename);
    localStorage.setItem("ow_session_id", session.session_id);
    localStorage.setItem("ow_session_file", session.filename);
    // Bust all session-scoped queries so they refetch with the new session_id
    qc.invalidateQueries({ queryKey: ["cicids-stats"] });
    qc.invalidateQueries({ queryKey: ["hourly-distribution"] });
    qc.invalidateQueries({ queryKey: ["pipeline-alerts"] });
    qc.invalidateQueries({ queryKey: ["mitre-stats"] });
    qc.invalidateQueries({ queryKey: ["session-soar-feed"] });
    qc.invalidateQueries({ queryKey: ["pipeline-top-ips"] });
    // Fetch full session to restore pipelineCompletion (ciso_summary + chain hashes)
    try {
      const full = await api.getPipelineSession(session.session_id);
      if (full.status === "complete" && full.ciso_summary) {
        setPipelineCompletion({
          session_id: full.session_id,
          filename: full.filename,
          chain_tip_hash: full.chain_tip_hash ?? "",
          ciso_summary: full.ciso_summary,
          rows_processed: full.rows_processed,
          alerts_found: full.alerts_found,
        });
      } else {
        setPipelineCompletion(null);
      }
    } catch {
      setPipelineCompletion(null);
    }
  }, [qc]);

  // Delete one session (or __ALL__ sentinel for full purge).
  const handleDeleteSession = useCallback(async (sessionId: string) => {
    const isPurgeAll = sessionId === "__ALL__";
    const tid = toast.loading(isPurgeAll ? "Purging all data…" : "Deleting session…");
    try {
      let deleted = 0;
      if (isPurgeAll) {
        const r = await api.resetSystem();
        deleted = r.rows_deleted;
        qc.clear();
        setAlerts([]);
        setSoarEntries([]);
        setLastScanId(null);
      } else {
        const r = await api.deleteSession(sessionId);
        deleted = r.rows_deleted;
        qc.invalidateQueries({ queryKey: ["pipeline-sessions-list"] });
      }
      // Clear active state if the deleted session was the active one (or purge all)
      if (isPurgeAll || sessionId === activeSessionId) {
        localStorage.removeItem("ow_session_id");
        localStorage.removeItem("ow_session_file");
        setActiveSessionId(null);
        setActiveFileName(null);
        setPipelineCompletion(null);
        qc.invalidateQueries({ queryKey: ["cicids-stats"] });
        qc.invalidateQueries({ queryKey: ["hourly-distribution"] });
        qc.invalidateQueries({ queryKey: ["pipeline-alerts"] });
      }
      toast.success(
        isPurgeAll
          ? `All data purged — ${deleted.toLocaleString()} rows removed`
          : `Session deleted — ${deleted.toLocaleString()} rows removed`,
        { id: tid, duration: 5000 },
      );
    } catch {
      toast.error("Delete failed — check backend connection", { id: tid });
    }
  }, [qc, activeSessionId]);

  // Two-step confirm — clears active session (or purges all if no session active)
  async function handleClearData() {
    if (!confirmClear) {
      setConfirmClear(true);
      confirmTimerRef.current = setTimeout(() => setConfirmClear(false), 4000);
      return;
    }
    if (confirmTimerRef.current) clearTimeout(confirmTimerRef.current);
    setConfirmClear(false);
    setClearing(true);
    try {
      await handleDeleteSession(activeSessionId ?? "__ALL__");
    } finally {
      setClearing(false);
    }
  }

  // Orchestrator for full Trust Chain Verification
  async function handleProve(recordId: number, modbusLabel: string, srcIp: string, isPipeline = false) {
    setIsProvingRecordId(recordId);
    setActivePage("trustchain");

    // Reset nodes 3-6 to verify fresh request
    setDagNodes(prev => prev.map(n =>
      ["zkvm", "fido2", "gate", "action"].includes(n.id) ? { ...n, state: "pending" } : n
    ));

    updateNodeState("zkvm", "verifying");
    const tid = toast.loading(`Generating Zero-Knowledge STARK Proof for ${modbusLabel}… (takes ~8s)`);

    try {
      // 1. Generate STARK Proof — route based on alert source table
      const res = isPipeline
        ? await api.provePipelineAlert(recordId)
        : await api.generateStarkProof(recordId);
      const receiptB64 = res.receipt_b64;
      updateNodeState("zkvm", "verified");
      toast.success("STARK Proof generated successfully!", { id: tid });

      // 2. FIDO2 Ceremony — software mock (no hardware key enrolled)
      updateNodeState("fido2", "verifying");
      const fdoId = toast.loading("FIDO2 Signing Ceremony [Software Demo Mode]…");

      const authBegin = await api.fido2SignBegin(receiptB64, true);
      const { session_id } = authBegin;

      updateNodeState("fido2", "verified");
      toast.success("Analyst sign-off recorded [Software Demo — no hardware key tap].", { id: fdoId });

      // 3. Verification Gate submission
      updateNodeState("gate", "verifying");
      const gateId = toast.loading("Submitting to Dual-Factor Cryptographic Gate…");

      await api.verifyRemediation({
        session_id,
        stark_receipt_b64: receiptB64,
        assertion_response: { mock_fido2: true },
        mock_fido2: true,
        src_ip: srcIp,
      });

      updateNodeState("gate", "verified");
      updateNodeState("action", "verified");
      toast.success(`NETWORK ISOLATED — ${srcIp} blocked at ICS firewall`, {
        id: gateId,
        duration: 8000,
        style: { background: "#052e16", border: "1px solid #16a34a" },
      });

    } catch (err: any) {
      const errDetail = err?.response?.data?.detail || err?.message || "Verification failed";

      // Heuristic to update the failing node in the DAG
      setDagNodes(prev => {
        const verifying = prev.find(n => n.state === "verifying");
        if (verifying) return prev.map(n => n.id === verifying.id ? { ...n, state: "failed" } : n);
        return prev;
      });

      toast.error(`Cryptographic verification blocked: ${errDetail}`, { id: tid });
    } finally {
      setIsProvingRecordId(null);
    }
  }

  async function handleAbcToggle(enable: boolean) {
    try {
      await api.toggleAbc(enable);
      setAbcEnabled(enable);
      toast.success(
        enable
          ? "Autonomous Breach Containment ENABLED — system will self-heal CRITICAL Modbus threats"
          : "ABC mode disabled — manual PROVE required",
        { duration: 5000, style: enable ? { background: "#052e16", border: "1px solid #16a34a" } : undefined },
      );
    } catch {
      toast.error("Failed to toggle ABC mode");
    }
  }

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="flex min-h-screen" style={{ background: "var(--splunk-bg)", color: "var(--splunk-text)" }}>
      <Toaster
        theme="dark"
        position="bottom-right"
        closeButton
        toastOptions={{
          duration: 3000,
          style: { background: "#1e1f23", border: "1px solid #2e3038", color: "#c5c7d4", fontSize: "12px" },
        }}
      />

      {/* ── Sidebar ──────────────────────────────────────────────────────── */}
      <motion.aside
        animate={{ width: sidebarOpen ? 240 : 56 }}
        transition={{ type: "spring", stiffness: 320, damping: 32, mass: 0.8 }}
        className="shrink-0 flex flex-col h-screen sticky top-0 overflow-hidden z-20"
        style={{ background: "var(--sidebar-bg)", borderRight: "1px solid var(--sidebar-border)" }}
      >
        {/* Brand + collapse toggle row */}
        <div style={{ borderBottom: "1px solid var(--sidebar-border)" }}>
          <div className={`flex items-center px-3 py-3.5 ${sidebarOpen ? "gap-2.5" : "justify-between"}`}>
            {/* Logo mark */}
            <motion.div
              className={`flex items-center shrink-0 ${sidebarOpen ? "w-auto" : "w-7 h-7 justify-center rounded-lg"}`}
              whileHover={{ scale: 1.02 }}
              transition={{ type: "spring", stiffness: 380, damping: 22 }}
              style={!sidebarOpen ? {
                background: "linear-gradient(135deg,rgba(217,70,239,0.25),rgba(6,182,212,0.25))",
                border: "1px solid rgba(217,70,239,0.38)",
                boxShadow: "0 0 14px rgba(217,70,239,0.14), 0 0 28px rgba(6,182,212,0.07)",
              } : {}}
            >
              {sidebarOpen ? (
                <img src={logo} alt="OmniWatch" className="h-6 w-auto" />
              ) : (
                <img src={icon} alt="O" className="w-4 h-4" />
              )}
            </motion.div>

            {/* Collapse toggle — always visible at top-right of brand area */}
            <motion.button
              onClick={() => setSidebarOpen(o => !o)}
              title={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.9 }}
              transition={{ type: "spring", stiffness: 400, damping: 20 }}
              className="shrink-0 flex items-center justify-center w-6 h-6 rounded-md transition-colors hover:bg-white/8 active:opacity-60"
              style={{ color: "var(--splunk-muted)" }}
            >
              {sidebarOpen
                ? <ChevronLeft style={{ width: 13, height: 13 }} />
                : <ChevronRight style={{ width: 13, height: 13 }} />
              }
            </motion.button>
          </div>
          {/* Accent strip below brand */}
          <div className="sidebar-glow-strip" />
        </div>

        {/* Nav */}
        <nav className="flex-1 py-3 px-1.5 space-y-0.5 overflow-y-auto overflow-x-hidden">
          {NAV_ITEMS.map(({ page, label, Icon }) => {
            const active = activePage === page;
            return (
              <div key={page} className="relative group/nav">
                <motion.button
                  onClick={() => setActivePage(page)}
                  whileHover={{ x: active ? 0 : (sidebarOpen ? 3 : 0) }}
                  whileTap={{ scale: 0.97 }}
                  transition={{ type: "spring", stiffness: 420, damping: 28 }}
                  className={`
                    relative w-full flex items-center gap-2.5 px-2.5 py-2 rounded-md text-left
                    transition-colors duration-120
                    ${sidebarOpen ? "" : "justify-center"}
                  `}
                  style={{
                    background: active ? "rgba(6,182,212,0.08)" : "transparent",
                    color: active ? "#e2e8f0" : "var(--splunk-muted)",
                    boxShadow: active ? "inset 0 0 0 1px rgba(6,182,212,0.15)" : "none",
                  }}
                  onMouseEnter={e => { if (!active) e.currentTarget.style.background = "rgba(255,255,255,0.04)"; }}
                  onMouseLeave={e => { if (!active) e.currentTarget.style.background = "transparent"; }}
                >
                  {/* Animated active indicator pip */}
                  {active && (
                    <motion.span
                      layoutId="nav-pip"
                      className="absolute left-0 top-1 bottom-1 w-[2px] rounded-full"
                      style={{ background: "var(--splunk-cyan)" }}
                      transition={{ type: "spring", stiffness: 500, damping: 30 }}
                    />
                  )}
                  <span className="shrink-0" style={{ width: 15, height: 15, color: active ? "var(--splunk-cyan)" : "inherit" }}>
                    <Icon className="w-full h-full" strokeWidth={active ? 2 : 1.75} />
                  </span>
                  {sidebarOpen && (
                    <span className={`text-[12.5px] tracking-tight truncate ${active ? "font-semibold" : "font-medium"}`}>{label}</span>
                  )}
                </motion.button>

                {/* Tooltip — shown on hover only when sidebar is collapsed */}
                {!sidebarOpen && (
                  <div
                    className="pointer-events-none absolute left-full top-1/2 -translate-y-1/2 ml-2 z-50
                               px-2 py-1 rounded text-[11px] font-medium whitespace-nowrap
                               opacity-0 group-hover/nav:opacity-100 transition-opacity duration-150"
                    style={{
                      background: "#1a1b1f",
                      border: "1px solid #2e3038",
                      color: "#c5c7d4",
                      boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
                    }}
                  >
                    {label}
                  </div>
                )}
              </div>
            );
          })}
        </nav>

        {/* Footer — status indicators */}
        <div
          className={`px-2 py-3 space-y-1 ${sidebarOpen ? "" : "flex flex-col items-center"}`}
          style={{ borderTop: "1px solid var(--sidebar-border)" }}
        >
          {/* WS status */}
          <div
            className={`relative group/ws flex items-center gap-2 px-1.5 py-1 rounded ${sidebarOpen ? "" : "justify-center"}`}
            title={!sidebarOpen ? (wsConnected ? "Live — WebSocket connected" : "Offline") : undefined}
          >
            {wsConnected
              ? <Wifi className="shrink-0 text-emerald-500" style={{ width: 11, height: 11 }} />
              : <WifiOff className="shrink-0" style={{ width: 11, height: 11, color: "var(--splunk-muted)" }} />
            }
            {sidebarOpen && (
              <span className="text-[10px]" style={{ color: wsConnected ? "#10b981" : "var(--splunk-muted)" }}>
                {wsConnected ? "Live" : "Offline"}
              </span>
            )}
          </div>

          {/* Monitor status */}
          {monitor?.active && (
            <div
              className={`flex items-center gap-2 px-1.5 py-1 rounded ${sidebarOpen ? "" : "justify-center"}`}
              title={!sidebarOpen ? `Monitor · ${monitor.files_processed} files` : undefined}
            >
              <Eye className="shrink-0 text-cyan-500" style={{ width: 11, height: 11 }} />
              {sidebarOpen && (
                <span className="text-[10px]" style={{ color: "var(--splunk-cyan)" }}>
                  Monitor · {monitor.files_processed}
                </span>
              )}
            </div>
          )}

          {/* Scanning indicator */}
          {scanning && (
            <div
              className={`flex items-center gap-2 px-1.5 py-1 ${sidebarOpen ? "" : "justify-center"}`}
              title={!sidebarOpen ? "Scanning…" : undefined}
            >
              <Loader2 className="shrink-0 animate-spin" style={{ width: 11, height: 11, color: "var(--splunk-amber)" }} />
              {sidebarOpen && (
                <span className="text-[10px]" style={{ color: "var(--splunk-amber)" }}>Scanning…</span>
              )}
            </div>
          )}
        </div>
      </motion.aside>

      {/* ── Main area ────────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0">

        {/* ── Top toolbar ──────────────────────────────────────────────────── */}
        <header
          className="sticky top-0 z-30 flex items-center gap-3 px-5 py-3"
          style={{ background: "var(--splunk-surface)", borderBottom: "1px solid var(--splunk-border)" }}
        >
          <span className="text-[13px] font-bold text-white tracking-wide">
            {NAV_ITEMS.find(n => n.page === activePage)?.label}
          </span>
          <span className="text-[11px]" style={{ color: "var(--splunk-muted)" }}>
            {NAV_ITEMS.find(n => n.page === activePage)?.description}
          </span>

          {/* Dataset switcher — always visible; shows "No dataset" when empty */}
          <SessionSwitcherDropdown
            activeSessionId={activeSessionId}
            activeFileName={activeFileName}
            onSwitch={handleSwitchSession}
            onDelete={handleDeleteSession}
          />

          <div className="ml-auto flex items-center gap-2">
            {/* Clear Data + Upload CSV — only shown on Dashboard */}
            {activePage === "dashboard" && (
              <>
                <button
                  onClick={handleClearData}
                  disabled={clearing}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium
                             disabled:opacity-40 disabled:cursor-not-allowed transition-all active:opacity-70"
                  style={{
                    background: confirmClear ? "rgba(239,68,68,0.18)" : "rgba(239,68,68,0.08)",
                    border: `1px solid ${confirmClear ? "rgba(239,68,68,0.55)" : "rgba(239,68,68,0.25)"}`,
                    color: "#fca5a5",
                    boxShadow: confirmClear ? "0 0 12px rgba(239,68,68,0.20)" : "none",
                  }}
                >
                  {clearing
                    ? <><span className="w-2 h-2 rounded-full border border-current border-t-transparent animate-spin" /> Clearing…</>
                    : confirmClear
                      ? <><Trash2 className="w-3 h-3" /> Confirm?</>
                      : activeSessionId
                        ? <><Trash2 className="w-3 h-3" /> Clear Session</>
                        : <><Trash2 className="w-3 h-3" /> Purge All</>
                  }
                </button>

                <button
                  onClick={() => setShowUploader(true)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium
                             transition-opacity active:opacity-70"
                  style={{ background: "rgba(114,200,17,0.12)", border: "1px solid rgba(114,200,17,0.3)", color: "var(--splunk-green)" }}
                >
                  <Upload className="w-3 h-3" /> Upload CSV
                </button>
              </>
            )}
          </div>
        </header>

        {/* ── Page content ──────────────────────────────────────────────── */}
        <div className="flex-1 overflow-auto">
          <ErrorBoundary>
            <AnimatePresence mode="wait">
              {activePage === "dashboard" && (
                <motion.div key="dashboard"
                  initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                  transition={{ duration: 0.16, ease: [0.22, 1, 0.36, 1] }}
                  className="h-[calc(100vh-53px)] flex flex-col"
                >
                  <DashboardPage
                    stats={stats}
                    cicidsStats={cicidsStats}
                    botsData={botsData}
                    pipelineCiso={pipelineCompletion?.ciso_summary}
                    sessionId={pipelineCompletion?.session_id ?? activeSessionId ?? undefined}
                    isProving={isProvingRecordId !== null}
                    onIpClick={ip => navigateToLogExplorer({ source_ip: ip })}
                    onMitreClick={id => navigateToLogExplorer({ mitre: id })}
                  />
                </motion.div>
              )}

              {activePage === "logexplorer" && (
                <motion.div key="logexplorer"
                  initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                  transition={{ duration: 0.16, ease: [0.22, 1, 0.36, 1] }}
                  className="h-[calc(100vh-53px)] flex flex-col"
                >
                  <LogExplorer
                    sessionId={activeSessionId}
                    onReviewSign={(alert) => setReviewAlert(alert)}
                    initialFilters={logFilters}
                  />
                </motion.div>
              )}

              {activePage === "playbooks" && (
                <motion.div key="playbooks"
                  initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                  transition={{ duration: 0.16, ease: [0.22, 1, 0.36, 1] }}
                >
                  <PlaybooksPage soarEntries={soarEntries} activeSessionId={activeSessionId} />
                </motion.div>
              )}

              {activePage === "trustchain" && (
                <motion.div key="trustchain"
                  initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                  transition={{ duration: 0.16, ease: [0.22, 1, 0.36, 1] }}
                  className="p-3 space-y-3"
                >
                  {/* DAG + Payload Detail side-by-side when an alert is selected */}
                  <div className={selectedAlert ? "grid grid-cols-3 gap-3" : ""}>
                    <div className={`rounded-xl overflow-hidden ${selectedAlert ? "col-span-2" : ""}`}
                      style={{ background: "#0a0a0d", border: "1px solid #1a1a1f" }}>
                      <TrustChainDAG
                        nodes={dagNodes}
                        pipelineHash={pipelineCompletion?.chain_tip_hash ?? undefined}
                        isProving={isProvingRecordId !== null}
                      />
                    </div>

                    {/* Payload Detail — shown when navigated via Review & Sign */}
                    {selectedAlert && (
                      <div className="rounded-xl p-4 space-y-3 flex flex-col"
                        style={{ background: "#0d0d10", border: "1px solid rgba(217,70,239,0.25)" }}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-violet-500" />
                            <span className="text-[10px] uppercase tracking-widest font-semibold" style={{ color: "#d946ef" }}>
                              Payload Detail
                            </span>
                          </div>
                          <button
                            onClick={() => setSelectedAlert(null)}
                            className="text-slate-600 hover:text-slate-300 text-xs transition-colors"
                          >
                            ✕
                          </button>
                        </div>

                        <div className="space-y-2 flex-1">
                          {[
                            { label: "Timestamp", value: new Date(selectedAlert.ingested_at).toLocaleString() },
                            { label: "Severity", value: selectedAlert.severity },
                            { label: "Label", value: selectedAlert.label },
                            { label: "MITRE Technique", value: selectedAlert.mitre_technique ?? "—" },
                            { label: "MITRE Tactic", value: selectedAlert.mitre_name ?? "—" },
                            { label: "Anomaly Score", value: selectedAlert.z_score_bytes != null ? selectedAlert.z_score_bytes.toFixed(2) : "—" },
                            { label: "Chain Hash", value: selectedAlert.chain_hash ? `${selectedAlert.chain_hash.substring(0, 16)}…` : "—" },
                          ].map(({ label, value }) => (
                            <div key={label}>
                              <p className="text-[9px] uppercase tracking-widest font-semibold" style={{ color: "#4d5060" }}>{label}</p>
                              <p className="text-[11px] font-mono mt-0.5 break-all" style={{ color: "#c5c7d4" }}>{value}</p>
                            </div>
                          ))}
                        </div>

                        <button
                          onClick={() => handleProve(selectedAlert.id, selectedAlert.label, selectedAlert.source_ip ?? "0.0.0.0", !!(selectedAlert as any).session_id)}
                          className="w-full py-2 rounded text-xs font-bold transition-all active:scale-95 disabled:opacity-40"
                          style={{
                            background: "linear-gradient(135deg,rgba(217,70,239,0.20),rgba(6,182,212,0.20))",
                            border: "1px solid rgba(217,70,239,0.40)",
                            color: "#e0aaff",
                          }}
                        >
                          ⚡ Generate STARK Proof & Sign
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Info cards + ABC toggle */}
                  <motion.div
                    className="grid grid-cols-3 gap-2.5"
                    initial="hidden"
                    animate="visible"
                    variants={{ hidden: {}, visible: { transition: { staggerChildren: 0.06 } } }}
                  >
                    {/* ABC Toggle */}
                    <motion.div
                      variants={{ hidden: { opacity: 0, y: 10 }, visible: { opacity: 1, y: 0, transition: { duration: 0.22, ease: [0.22, 1, 0.36, 1] } } }}
                      className="rounded-lg p-3 flex flex-col justify-between glow-card"
                      style={{
                        background: abcEnabled ? "rgba(6,182,212,0.07)" : "var(--splunk-card)",
                        border: `1px solid ${abcEnabled ? "rgba(6,182,212,0.30)" : "var(--splunk-border)"}`,
                        transition: "background 0.3s, border-color 0.3s",
                      }}
                    >
                      <div>
                        <p className="text-[9px] font-semibold uppercase tracking-widest" style={{ color: abcEnabled ? "#06b6d4" : "#4d5060" }}>
                          Autonomous Mode
                        </p>
                        <p className="text-sm font-bold mt-1 font-mono" style={{ color: abcEnabled ? "#06b6d4" : "#6b6e80" }}>
                          {abcEnabled ? "ACTIVE" : "STANDBY"}
                        </p>
                        <p className="text-[9px] mt-1" style={{ color: "#3d3f4a" }}>
                          ABC · ≥98% confidence · 15 s poll
                        </p>
                        {(abcStatus?.processed_count ?? 0) > 0 && (
                          <p className="text-[9px] mt-0.5 font-mono" style={{ color: "#06b6d480" }}>
                            {abcStatus!.processed_count} auto-blocked
                          </p>
                        )}
                      </div>
                      <button
                        onClick={() => handleAbcToggle(!abcEnabled)}
                        className="mt-2 w-full text-[9px] font-bold py-1.5 rounded transition-all"
                        style={{
                          background: abcEnabled ? "rgba(6,182,212,0.2)" : "rgba(255,255,255,0.05)",
                          border: `1px solid ${abcEnabled ? "#06b6d460" : "var(--splunk-border)"}`,
                          color: abcEnabled ? "#06b6d4" : "#6b6e80",
                        }}
                      >
                        {abcEnabled ? "DISABLE ABC" : "ENABLE ABC"}
                      </button>
                    </motion.div>

                    <motion.div
                      variants={{ hidden: { opacity: 0, y: 10 }, visible: { opacity: 1, y: 0, transition: { duration: 0.22, ease: [0.22, 1, 0.36, 1] } } }}
                      className="rounded-lg p-3 glow-card"
                      style={{ background: "var(--splunk-card)", border: "1px solid var(--splunk-border)" }}
                    >
                      <p className="text-[9px] font-semibold uppercase tracking-widest" style={{ color: "var(--splunk-muted)" }}>Machine Proof</p>
                      <p className="text-sm font-bold mt-1 font-mono" style={{ color: "#06b6d4" }}>STARK Receipt</p>
                      <p className="text-[10px] mt-1" style={{ color: "#3d4a5c" }}>RISC Zero zkVM · ~96-bit security</p>
                    </motion.div>

                    <motion.div
                      variants={{ hidden: { opacity: 0, y: 10 }, visible: { opacity: 1, y: 0, transition: { duration: 0.22, ease: [0.22, 1, 0.36, 1] } } }}
                      className="rounded-lg p-3 glow-card"
                      style={{ background: "var(--splunk-card)", border: "1px solid var(--splunk-border)" }}
                    >
                      <p className="text-[9px] font-semibold uppercase tracking-widest" style={{ color: "var(--splunk-muted)" }}>Replay Shield</p>
                      <p className="text-sm font-bold mt-1 font-mono" style={{ color: "#22c55e" }}>Spent-Receipt Registry</p>
                      <p className="text-[10px] mt-1" style={{ color: "#3d4a5c" }}>SQLite WAL · Atomic INSERT OR IGNORE</p>
                    </motion.div>
                  </motion.div>

                  {/* Main panels */}
                  <div className="grid grid-cols-3 gap-3">
                    <div className="col-span-2">
                      <EdgeTelemetryPanel onProve={handleProve} isProvingRecordId={isProvingRecordId} />
                    </div>
                    {/* Right column: firewall history + remediation plan */}
                    <div className="flex flex-col gap-3">
                      <div className="flex-1">
                        <FirewallHistoryPanel />
                      </div>
                      <div className="rounded-xl p-3 overflow-auto"
                        style={{ background: "var(--splunk-card)", border: "1px solid var(--splunk-border)", maxHeight: 340 }}>
                        <p className="text-[9px] uppercase tracking-widest font-semibold mb-2"
                          style={{ color: "var(--splunk-muted)" }}>Remediation Plan</p>
                        <RemediationPlanPanel pipelineCiso={pipelineCompletion?.ciso_summary ?? undefined} />
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {activePage === "settings" && (
                <motion.div key="settings"
                  initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                  transition={{ duration: 0.16, ease: [0.22, 1, 0.36, 1] }}
                >
                  <SettingsPage />
                </motion.div>
              )}
            </AnimatePresence>
          </ErrorBoundary>
        </div>
      </div>

      {showUploader && (
        <TelemetryUploader
          onClose={() => { setShowUploader(false); setPipelineWsMessage(null); }}
          pipelineWsMessage={pipelineWsMessage}
          onComplete={(result) => {
            setPipelineCompletion(result);
            setActiveSessionId(result.session_id);
            setActiveFileName(result.filename);
            localStorage.setItem("ow_session_id", result.session_id);
            localStorage.setItem("ow_session_file", result.filename);
            // Bust session-scoped queries so the dashboard fetches fresh data
            qc.invalidateQueries({ queryKey: ["cicids-stats", result.session_id] });
          }}
        />
      )}

      {/* Global AI incident review slide-over — triggered from LogExplorer */}
      <AiIncidentReview
        alert={reviewAlert}
        onClose={() => setReviewAlert(null)}
        onReviewSign={(alert) => {
          setReviewAlert(null);
          setSelectedAlert(alert);
          setActivePage("trustchain");
        }}
      />
    </div>
  );
}

// ── Dashboard loading skeleton ────────────────────────────────────────────────

function DashboardSkeleton() {
  const shimmer = "rounded-md bg-white/5 animate-pulse";
  return (
    <div className="flex flex-col h-full gap-3 p-3">
      <div className="grid grid-cols-3 gap-3 shrink-0">
        {[...Array(3)].map((_, i) => <div key={i} className={`h-20 ${shimmer}`} />)}
      </div>
      <div className="grid grid-cols-12 gap-3 flex-1 min-h-0">
        <div className={`col-span-7 ${shimmer}`} />
        <div className={`col-span-5 ${shimmer}`} />
      </div>
      <div className={`flex-1 min-h-0 ${shimmer}`} />
    </div>
  );
}

// ── Hero KPI card ─────────────────────────────────────────────────────────────

function HeroKpi({ label, value, sub, theme, pulse = false }: {
  label: string; value: string; sub?: string;
  theme: "neutral" | "red" | "amber" | "cyan";
  pulse?: boolean;
}) {
  const accent =
    theme === "red" ? "#e84d4d" :
      theme === "amber" ? "#f59e0b" :
        theme === "cyan" ? "#06b6d4" : "#4e9af1";
  return (
    <div
      className="rounded-lg p-4 flex flex-col gap-1.5"
      style={{ background: `${accent}08`, border: `1px solid ${accent}25`, borderTop: `2px solid ${accent}` }}
    >
      <p className="text-[10px] uppercase tracking-widest font-semibold flex items-center gap-1.5"
        style={{ color: `${accent}99` }}>
        {pulse && (
          <span className="inline-block w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: accent }} />
        )}
        {label}
      </p>
      <p className="text-2xl font-bold font-mono leading-none tabular-nums" style={{ color: accent }}>
        {value}
      </p>
      {sub && <p className="text-[9px]" style={{ color: "#4d5060" }}>{sub}</p>}
    </div>
  );
}

// ── Dashboard page ────────────────────────────────────────────────────────────

function DashboardPage({
  stats, cicidsStats, botsData, pipelineCiso, sessionId, isProving,
  onIpClick, onMitreClick,
}: {
  stats: DashboardStats | undefined;
  cicidsStats: CicidsStats | undefined;
  botsData: any | undefined;
  pipelineCiso: CisoPipelineSummary | undefined;
  sessionId: string | undefined;
  isProving: boolean;
  onIpClick?: (ip: string) => void;
  onMitreClick?: (id: string) => void;
}) {
  const [briefingOpen, setBriefingOpen] = useState(false);

  // Fetch full pipeline session to get real-time pending_proofs count
  const { data: pipelineSession } = useQuery({
    queryKey: ["pipeline-session", sessionId],
    queryFn: () => api.getPipelineSession(sessionId!),
    enabled: !!sessionId,
    refetchInterval: 5000,
  });

  if (stats === undefined && cicidsStats === undefined && botsData === undefined) {
    return <DashboardSkeleton />;
  }

  const bySev = cicidsStats?.by_severity ?? {};
  // Prefer rows_processed (full CSV row count) over total (alerts only) for Total Flows KPI
  const total = cicidsStats?.rows_processed ?? cicidsStats?.total ?? stats?.total_events ?? 0;
  const crit = bySev.CRITICAL ?? stats?.critical_events ?? 0;
  const high = bySev.HIGH ?? 0;
  const med = bySev.MEDIUM ?? stats?.suspicious_events ?? 0;
  const low = bySev.LOW ?? 0;
  const threats = crit + high;
  const warnings = med + low;

  // STARK queue KPI — shows how many alerts are candidates for ZK verification.
  // When `isProving` is true a proof is actively generating (15–32 s window).
  const starkCount = pipelineSession?.pending_proofs ?? pipelineCiso?.total_alerts ?? 0;
  const starkValue = isProving ? "Verifying…" : starkCount.toLocaleString();
  const starkSub = isProving ? "STARK proof generating · 15–32 s" : "alerts pending ZK verification";
  const starkTheme = isProving ? "amber" : (starkCount > 0 ? "cyan" : "neutral") as "amber" | "cyan" | "neutral";

  return (
    <div className="flex flex-col h-full gap-3 p-3 overflow-hidden">

      {/* Row 1 — Hero KPIs (4-wide) */}
      <div className="grid grid-cols-4 gap-3 shrink-0">
        <HeroKpi label="Total Flows" value={total.toLocaleString()} sub="network events processed" theme="neutral" />
        <HeroKpi label="Active Threats" value={threats.toLocaleString()} sub="CRITICAL + HIGH (non-benign)" theme="red" />
        <HeroKpi label="Warnings" value={warnings.toLocaleString()} sub="MEDIUM + LOW detections" theme="amber" />
        <HeroKpi label="STARK Queue" value={starkValue} sub={starkSub} theme={starkTheme} pulse={isProving} />
      </div>

      {/* Row 2 — Threat Core: timeline + severity donut + top sources */}
      <div className="grid grid-cols-12 gap-3 flex-1 min-h-0">
        <div className="col-span-5 splunk-panel overflow-hidden flex flex-col">
          <div className="splunk-panel-header">
            <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: "var(--splunk-muted)" }} />
            Threat Activity
          </div>
          <div className="flex-1 p-3 min-h-0">
            <PanelErrorBoundary>
              <ThreatTimelineChart cicidsStats={cicidsStats} sessionId={sessionId} />
            </PanelErrorBoundary>
          </div>
        </div>
        <div className="col-span-3 splunk-panel overflow-hidden flex flex-col">
          <div className="splunk-panel-header">
            <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: "var(--splunk-muted)" }} />
            Severity Distribution
          </div>
          <div className="flex-1 p-2 min-h-0 flex items-center justify-center">
            <PanelErrorBoundary>
              <SeverityChart stats={stats} cicidsStats={cicidsStats} botsTactics={botsData?.mitre_tactics} />
            </PanelErrorBoundary>
          </div>
        </div>
        <div className="col-span-4 splunk-panel overflow-hidden flex flex-col">
          <div className="splunk-panel-header">
            <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: "var(--splunk-muted)" }} />
            Top Threat Sources
            {pipelineCiso && (
              <button
                onClick={() => setBriefingOpen(true)}
                className="ml-auto flex items-center gap-1 px-2 py-0.5 rounded text-[9px] font-semibold transition-all"
                style={{ background: "rgba(217,70,239,0.10)", border: "1px solid rgba(217,70,239,0.30)", color: "#d946ef" }}
              >
                <AISparkleIcon className="w-2.5 h-2.5" /> AI Briefing
              </button>
            )}
          </div>
          <div className="flex-1 overflow-auto">
            <PanelErrorBoundary>
              <TopThreatSourcesPanel sessionId={sessionId} pipelineCiso={pipelineCiso} onIpClick={onIpClick} />
            </PanelErrorBoundary>
          </div>
        </div>
      </div>

      {/* Row 3 — ATT&CK Intelligence */}
      <div className="flex-1 min-h-0 splunk-panel overflow-hidden flex flex-col">
        <div className="splunk-panel-header">
          <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: "var(--splunk-muted)" }} />
          ATT&amp;CK Intelligence
        </div>
        <div className="flex-1 overflow-auto p-3">
          <PanelErrorBoundary>
            <MitreHeatmap
              alerts={[]}
              cicidsStats={cicidsStats}
              botsTactics={botsData?.mitre_tactics}
              sessionId={sessionId}
              onMitreClick={onMitreClick}
            />
          </PanelErrorBoundary>
        </div>
      </div>

      <ExecutiveBriefDrawer
        open={briefingOpen}
        onClose={() => setBriefingOpen(false)}
        pipelineCiso={pipelineCiso}
        cicidsStats={cicidsStats}
      />
    </div>
  );
}

// ── AI Executive Summary text generator ──────────────────────────────────────

function generateAiSummary(ciso: CisoPipelineSummary): string {
  const total = ciso.total_alerts ?? 0;
  if (total === 0) return "No threat events detected in this pipeline session.";

  const crit = ciso.by_severity?.CRITICAL ?? 0;
  const high = ciso.by_severity?.HIGH ?? 0;
  const med = ciso.by_severity?.MEDIUM ?? 0;
  const topLabel = ciso.top_labels?.[0];
  const topIp = ciso.top_attacker_ips?.[0];
  const topTech = ciso.top_techniques?.[0];
  const techCount = ciso.top_techniques?.length ?? 0;

  let text = `Pipeline analysis complete. Detected ${total.toLocaleString()} threat events`;
  const sevParts: string[] = [];
  if (crit > 0) sevParts.push(`${crit.toLocaleString()} CRITICAL`);
  if (high > 0) sevParts.push(`${high.toLocaleString()} HIGH`);
  if (med > 0) sevParts.push(`${med.toLocaleString()} MEDIUM`);
  if (sevParts.length > 0) text += ` — ${sevParts.join(", ")}`;
  text += `.`;

  if (topLabel) {
    const pct = Math.round(topLabel.count / total * 100);
    text += ` Dominant attack pattern: ${topLabel.label} (${topLabel.count.toLocaleString()} events · ${pct}% of detections).`;
  }
  if (topIp) {
    text += ` Highest-volume threat source: ${topIp.ip} (${topIp.count.toLocaleString()} malicious flows).`;
  }
  if (techCount > 0 && topTech) {
    text += ` Correlated ${techCount} MITRE ATT&CK technique${techCount > 1 ? "s" : ""} — top: ${topTech.name} (${topTech.id}).`;
  }
  return text;
}

// ── CISO KPI card ─────────────────────────────────────────────────────────────

function CisoKpiCard({
  label, value, sub, accent, icon,
}: {
  label: string;
  value: string;
  sub: string;
  accent: string;
  icon: string;
}) {
  return (
    <div
      className="flex-1 rounded-lg p-3 flex flex-col justify-between min-h-0"
      style={{
        background: "#0d0d10",
        border: `1px solid ${accent}30`,
        borderTop: `2px solid ${accent}`,
      }}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-[9px] uppercase tracking-widest font-semibold truncate"
            style={{ color: accent + "99" }}>
            {label}
          </p>
          <p className="text-xl font-bold font-mono mt-1 leading-none tabular-nums"
            style={{ color: accent }}>
            {value}
          </p>
        </div>
        <span className="text-lg shrink-0 opacity-35 mt-0.5">{icon}</span>
      </div>
      <p className="text-[9px] mt-2 truncate" style={{ color: "#4d5060" }}>{sub}</p>
    </div>
  );
}

// ── Pipeline Executive Brief ──────────────────────────────────────────────────

function PipelineExecutiveBrief({
  pipelineCiso, cicidsStats, botsData, sessionId,
}: {
  pipelineCiso: CisoPipelineSummary;
  cicidsStats: CicidsStats | undefined;
  botsData: any | undefined;
  sessionId: string | undefined;
}) {
  const { data: liveTopIps } = useQuery({
    queryKey: ["pipeline-top-ips", sessionId],
    queryFn: () => api.getTopIps(sessionId!),
    enabled: !!sessionId,
    staleTime: 60_000,
  });

  // Prefer live query result over cached ciso_summary to handle sessions where
  // source_ip was not populated at pipeline-completion time.
  const topAttackerIps = (liveTopIps && liveTopIps.length > 0)
    ? liveTopIps
    : (pipelineCiso.top_attacker_ips ?? []);

  const summary = generateAiSummary(pipelineCiso);
  const sevEntries = Object.entries(pipelineCiso.by_severity ?? {})
    .filter(([, v]) => (v as number) > 0)
    .sort((a, b) => (b[1] as number) - (a[1] as number));

  return (
    <div className="px-3 pt-3 pb-1 space-y-2.5">

      {/* ── AI Analysis panel (full-width) ───────────────────────────────── */}
      <div
        className="rounded-lg p-4 flex flex-col gap-3"
        style={{
          background: "linear-gradient(135deg,rgba(14,18,28,0.97) 0%,rgba(10,12,20,0.97) 100%)",
          border: "1px solid rgba(217,70,239,0.22)",
          boxShadow: "inset 0 0 60px rgba(217,70,239,0.025)",
        }}
      >
        {/* Header row */}
        <div className="flex items-center gap-2">
          <svg viewBox="0 0 24 24" className="w-3.5 h-3.5 shrink-0" fill="none" aria-hidden="true">
            <defs>
              <linearGradient id="brief-sparkle" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#d946ef" />
                <stop offset="100%" stopColor="#06b6d4" />
              </linearGradient>
            </defs>
            <path d="M12 2 L13.8 9.2 L21 12 L13.8 14.8 L12 22 L10.2 14.8 L3 12 L10.2 9.2 Z"
              fill="url(#brief-sparkle)" />
            <path d="M19.5 4 L20.2 6.3 L22.5 7 L20.2 7.7 L19.5 10 L18.8 7.7 L16.5 7 L18.8 6.3 Z"
              fill="url(#brief-sparkle)" opacity="0.6" />
          </svg>
          <span className="text-[10px] uppercase tracking-widest font-semibold ai-gradient">
            AI Executive Analysis
          </span>
          <div className="flex-1" />
          <span
            className="text-[9px] font-mono px-2 py-0.5 rounded-full"
            style={{
              background: "rgba(114,200,17,0.10)",
              border: "1px solid rgba(114,200,17,0.30)",
              color: "#72c811",
            }}
          >
            ● Pipeline Complete
          </span>
        </div>

        {/* Summary text */}
        <p className="text-[12px] leading-relaxed" style={{ color: "#a8abc0" }}>
          {summary}
        </p>

        {/* Severity breakdown pills */}
        {sevEntries.length > 0 && (
          <div className="flex flex-wrap gap-1.5 pt-0.5">
            {sevEntries.map(([sev, cnt]) => {
              const color =
                sev === "CRITICAL" ? "#e84d4d"
                  : sev === "HIGH" ? "#f4a926"
                    : sev === "MEDIUM" ? "#facc15"
                      : sev === "LOW" ? "#72c811"
                        : "#6b6e80";
              return (
                <span
                  key={sev}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono font-bold"
                  style={{
                    background: `${color}14`,
                    border: `1px solid ${color}40`,
                    color,
                  }}
                >
                  <span className="w-1.5 h-1.5 rounded-full shrink-0"
                    style={{ background: color, opacity: 0.8 }} />
                  {sev} · {(cnt as number).toLocaleString()}
                </span>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Row 2: Top Threat Sources + Top Attack Vectors ───────────────── */}
      <div className="grid grid-cols-2 gap-2.5">
        <BentoPanel title="Top Threat Sources (IPs)">
          <PanelErrorBoundary>
            {topAttackerIps.length > 0 ? (
              <TopAttackerIpsWidget ips={topAttackerIps} />
            ) : (
              <div className="flex items-center justify-center h-24 text-xs" style={{ color: "#4d5060" }}>
                No attacker IP data in this session
              </div>
            )}
          </PanelErrorBoundary>
        </BentoPanel>
        <BentoPanel title="Top Attack Vectors — MITRE Techniques">
          <PanelErrorBoundary>
            <ThreatVectorChart
              cicidsStats={cicidsStats}
              botsTactics={botsData?.mitre_tactics}
              pipelineCiso={pipelineCiso}
            />
          </PanelErrorBoundary>
        </BentoPanel>
      </div>

      {/* ── Row 3: Hourly Activity Trends (full width) ───────────────────── */}
      <BentoPanel title="Threat Activity Trends — Hourly Distribution">
        <PanelErrorBoundary>
          <ThreatTimelineChart cicidsStats={cicidsStats} sessionId={sessionId} />
        </PanelErrorBoundary>
      </BentoPanel>

    </div>
  );
}

// ── Top Attacker IPs widget ───────────────────────────────────────────────────

function TopAttackerIpsWidget({ ips }: { ips: { ip: string; count: number }[] }) {
  const top = ips.slice(0, 8);
  const max = Math.max(1, ...top.map(d => d.count));
  return (
    <div className="space-y-2 pt-1">
      {top.map((d, i) => (
        <div key={d.ip} className="flex items-center gap-2">
          <span className="text-[9px] font-mono w-4 shrink-0 text-right tabular-nums" style={{ color: "#4d5060" }}>
            {i + 1}
          </span>
          <span className="text-[10px] font-mono flex-1 truncate" style={{ color: "#c5c7d4" }}>{d.ip}</span>
          <div className="w-16 h-2 rounded-sm overflow-hidden shrink-0" style={{ background: "#0d0d10" }}>
            <div
              className="h-full rounded-sm"
              style={{
                width: `${(d.count / max) * 100}%`,
                background: "#e84d4d",
                opacity: 0.75,
                boxShadow: "0 0 4px rgba(232,77,77,0.4)",
              }}
            />
          </div>
          <span className="text-[9px] font-mono tabular-nums w-8 text-right shrink-0" style={{ color: "#e84d4d" }}>
            {d.count.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  );
}

// ── ThreatVectorChart — horizontal bar chart of attack type distribution ───────

const ATTACK_COLORS: Record<string, string> = {
  DoS: "#e84d4d",
  DDoS: "#e84d4d",
  PortScan: "#f4a926",
  Bot: "#8b5cf6",
  Infiltration: "#e040fb",
  "FTP-Patator": "#00d4c8",
  "SSH-Patator": "#00d4c8",
  Heartbleed: "#f4a926",
  "Web Attack": "#4e9af1",
};

function vectorColor(label: string | null | undefined): string {
  if (!label) return "#72c811";
  for (const [k, c] of Object.entries(ATTACK_COLORS)) {
    if (label.startsWith(k)) return c;
  }
  return "#72c811";
}

function ThreatVectorChart({
  cicidsStats, botsTactics, pipelineCiso,
}: {
  cicidsStats: CicidsStats | undefined;
  botsTactics?: any[];
  pipelineCiso?: CisoPipelineSummary;
}) {
  // Priority: pipeline MITRE techniques → CIC-IDS by_label → BOTSv3 tactics
  const entries = useMemo<{ label: string; count: number }[]>(() => {
    const techniques = pipelineCiso?.top_techniques ?? [];
    if (techniques.length > 0) {
      const mapped = techniques
        .filter(t => t.id != null || t.name != null)
        .slice(0, 8)
        .map(t => ({ label: (t.name || t.id) as string, count: t.count }));
      if (mapped.length > 0) return mapped;
    }
    const fromLabel = Object.entries(cicidsStats?.by_label ?? {})
      .filter(([l]) => l.toUpperCase() !== "BENIGN")
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([label, count]) => ({ label, count }));
    if (fromLabel.length > 0) return fromLabel;
    if (botsTactics && botsTactics.length > 0)
      return botsTactics.map(t => ({ label: t.tactic, count: t.count }));
    return [];
  }, [pipelineCiso, cicidsStats, botsTactics]);

  if (entries.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-44 gap-2" style={{ color: "#4d5060" }}>
        <BarChart2Icon className="w-8 h-8 opacity-15" style={{ color: "var(--splunk-muted)" }} />
        <p className="text-xs">No telemetry data — upload a network flow CSV to visualise attack vectors</p>
      </div>
    );
  }

  const total = entries.reduce((s, e) => s + e.count, 0);

  return (
    <div>
      <div className="flex items-center justify-between mb-3 px-1">
        <span className="text-[10px] font-mono tabular-nums" style={{ color: "#6b6e80" }}>
          <span className="font-semibold" style={{ color: "#c5c7d4" }}>{total.toLocaleString()}</span>
          {" "}threat events · top {entries.length} attack vectors detected
        </span>
        <span className="text-[9px] uppercase tracking-wider font-semibold" style={{ color: "#72c811" }}>
          Live Telemetry
        </span>
      </div>
      <ResponsiveContainer width="100%" height={entries.length * 30 + 16}>
        <BarChart data={entries} layout="vertical" margin={{ left: 8, right: 32, top: 0, bottom: 0 }}>
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="label"
            tick={{ fontSize: 10, fill: "#6b6e80", fontFamily: "JetBrains Mono, monospace" }}
            width={112}
          />
          <Tooltip
            contentStyle={{
              background: "#1e1f23",
              border: "1px solid #2e3038",
              borderRadius: 4,
              fontSize: 11,
              color: "#c5c7d4",
            }}
            cursor={{ fill: "rgba(255,255,255,0.03)" }}
            formatter={(value: any) => [value.toLocaleString(), "Events"]}
          />
          <Bar dataKey="count" radius={[0, 3, 3, 0]} maxBarSize={18} label={{ position: "right", fontSize: 10, fill: "#6b6e80", fontFamily: "JetBrains Mono, monospace", formatter: (v: any) => v.toLocaleString() }}>
            {entries.map(e => (
              <Cell key={e.label} fill={vectorColor(e.label)} opacity={0.82} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── ThreatTimelineChart — SOC severity-stratified temporal view ───────────────

type TimeWindow = "1h" | "24h" | "7d" | "all";

const TIME_WINDOW_OPTIONS: { value: TimeWindow; label: string }[] = [
  { value: "1h", label: "1H" },
  { value: "24h", label: "24H" },
  { value: "7d", label: "7D" },
  { value: "all", label: "ALL" },
];

function fmtYAxis(v: number): string {
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`;
  if (v >= 1_000) return `${(v / 1_000).toFixed(0)}k`;
  return String(v);
}

function ThreatTimelineChart({
  cicidsStats,
  sessionId,
}: {
  cicidsStats: CicidsStats | undefined;
  sessionId?: string;
}) {
  const [win, setWin] = useState<TimeWindow>("24h");
  const [brushRange, setBrushRange] = useState<{ start: number; end: number } | null>(null);

  useEffect(() => { setBrushRange(null); }, [win]);

  const { data: raw } = useQuery({
    queryKey: ["hourly-distribution", win, sessionId ?? null],
    queryFn: () => api.getHourlyDistribution(win, sessionId ?? null),
    refetchInterval: 120_000,
    staleTime: 60_000,
  });

  const data = useMemo(() => {
    if (!raw) return [];
    return raw.map(h => ({
      time: h.bucket,
      threats: h.threats,
      medium: h.medium ?? 0,
      benign: h.benign,
      total: h.total,
    }));
  }, [raw]);

  const avgThreats = useMemo(() => {
    const active = data.filter(d => d.threats > 0);
    if (!active.length) return 0;
    return Math.round(active.reduce((s, d) => s + d.threats, 0) / active.length);
  }, [data]);

  const peakIdx = useMemo(
    () => data.reduce((mi, d, i, arr) => d.threats > arr[mi].threats ? i : mi, 0),
    [data],
  );

  const tickInterval = useMemo(() => {
    if (data.length <= 8) return 0;
    if (data.length <= 16) return 1;
    if (data.length <= 30) return 2;
    return Math.ceil(data.length / 10);
  }, [data.length]);

  const totalThreats = useMemo(() => data.reduce((s, d) => s + d.threats, 0), [data]);
  const totalMedium = useMemo(() => data.reduce((s, d) => s + d.medium, 0), [data]);
  const totalBenign = useMemo(() => data.reduce((s, d) => s + d.benign, 0), [data]);

  const hasAnyData = (cicidsStats?.total ?? 0) > 0;
  const hasWindowData = data.some(d => d.total > 0);
  const showBrush = data.length > 12 || win === "all" || win === "7d";

  const jumpToPeak = useCallback(() => {
    if (!data.length) return;
    const half = Math.min(6, Math.floor(data.length / 4));
    setBrushRange({ start: Math.max(0, peakIdx - half), end: Math.min(data.length - 1, peakIdx + half) });
  }, [peakIdx, data.length]);

  // Shared window-picker element
  const windowPicker = (
    <div className="flex items-center rounded overflow-hidden shrink-0"
      style={{ background: "#0d0d10", border: "1px solid #2e3038" }}>
      {TIME_WINDOW_OPTIONS.map(opt => {
        const active = opt.value === win;
        return (
          <button key={opt.value} onClick={() => setWin(opt.value)}
            className="px-3 py-1.5 text-[11px] font-bold uppercase tracking-wider transition-colors"
            style={{
              background: active ? "rgba(6,182,212,0.15)" : "transparent",
              color: active ? "#06b6d4" : "#4d5060",
              borderRight: "1px solid #2e3038",
            }}>
            {opt.label}
          </button>
        );
      })}
    </div>
  );

  if (!hasAnyData) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-2" style={{ color: "#4d5060" }}>
        <TrendingUpIcon className="w-8 h-8 opacity-15" />
        <p className="text-xs">Upload telemetry to see threat activity</p>
      </div>
    );
  }

  // Data exists globally but nothing in this time window
  if (!hasWindowData) {
    return (
      <div className="flex flex-col h-full">
        <div className="flex items-center justify-between mb-2 px-1">
          <span className="text-[10px] font-mono" style={{ color: "#4d5060" }}>
            No events in this window — try a wider range
          </span>
          {windowPicker}
        </div>
      </div>
    );
  }

  const peakPoint = data[peakIdx];
  const ttStyle = {
    background: "#13141a", border: "1px solid #2e3038",
    borderRadius: 6, fontSize: 11, color: "#c5c7d4", padding: "8px 12px",
  };

  return (
    <div className="flex flex-col h-full">
      {/* ── Header: summary badges + jump-to-peak + window picker ── */}
      <div className="flex items-start justify-between mb-2 px-1 shrink-0 gap-2 flex-wrap">
        <div className="flex flex-wrap items-center gap-1.5 min-w-0">
          {totalThreats > 0 && (
            <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold tabular-nums"
              style={{ background: "rgba(232,77,77,0.12)", color: "#e84d4d", border: "1px solid rgba(232,77,77,0.2)" }}>
              ● {totalThreats.toLocaleString()} C/H
            </span>
          )}
          {totalMedium > 0 && (
            <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold tabular-nums"
              style={{ background: "rgba(245,158,11,0.10)", color: "#f59e0b", border: "1px solid rgba(245,158,11,0.2)" }}>
              ● {totalMedium.toLocaleString()} MED
            </span>
          )}
          {totalBenign > 0 && (
            <span className="px-2 py-0.5 rounded font-mono text-[10px] tabular-nums"
              style={{ color: "#4d5060" }}>
              {totalBenign.toLocaleString()} benign
            </span>
          )}
          {/* Jump to highest-threat bucket */}
          {peakPoint && totalThreats > 0 && (
            <button onClick={jumpToPeak}
              className="px-2 py-0.5 rounded font-mono text-[10px] transition-colors"
              style={{ background: "rgba(78,154,241,0.08)", color: "#4e9af1", border: "1px solid rgba(78,154,241,0.18)" }}>
              ⤢ peak @ {peakPoint.time}
            </button>
          )}
        </div>
        {windowPicker}
      </div>

      {/* ── Chart ── */}
      <div className="flex-1 min-h-0">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={data} margin={{ left: 0, right: 8, top: 6, bottom: showBrush ? 24 : 4 }}>
            <defs>
              <linearGradient id="gc2" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#e84d4d" stopOpacity={0.52} />
                <stop offset="100%" stopColor="#e84d4d" stopOpacity={0.02} />
              </linearGradient>
              <linearGradient id="gm2" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.38} />
                <stop offset="100%" stopColor="#f59e0b" stopOpacity={0.02} />
              </linearGradient>
            </defs>

            <CartesianGrid stroke="#1a1b22" strokeDasharray="3 3" vertical={false} />

            {/* Right axis — only used by the total-volume bar (hidden, auto-scales independently) */}
            <YAxis yAxisId="right" orientation="right" hide />
            {/* Left axis — threats + medium; scaled to threat range so spikes are visible */}
            <YAxis yAxisId="left"
              tickFormatter={fmtYAxis}
              tick={{ fontSize: 10, fill: "#4d5060", fontFamily: "JetBrains Mono, monospace" }}
              tickLine={false} axisLine={false} width={36}
            />
            <XAxis dataKey="time"
              tick={{ fontSize: 10, fill: "#4d5060", fontFamily: "JetBrains Mono, monospace" }}
              tickLine={false} axisLine={{ stroke: "#1a1b22" }}
              interval={tickInterval}
            />

            <Tooltip cursor={{ stroke: "rgba(255,255,255,0.04)", strokeWidth: 20 }}
              content={({ active, payload, label }) => {
                if (!active || !payload?.length) return null;
                const d = payload[0]?.payload;
                return (
                  <div style={ttStyle}>
                    <p className="font-mono font-semibold mb-1.5" style={{ color: "#c5c7d4" }}>{label}</p>
                    <div className="space-y-0.5">
                      {d.threats > 0 && <p><span style={{ color: "#e84d4d" }}>● CRIT/HIGH </span><span className="font-mono font-bold tabular-nums" style={{ color: "#e84d4d" }}>{d.threats.toLocaleString()}</span></p>}
                      {d.medium > 0 && <p><span style={{ color: "#f59e0b" }}>● MEDIUM    </span><span className="font-mono font-bold tabular-nums" style={{ color: "#f59e0b" }}>{d.medium.toLocaleString()}</span></p>}
                      {d.benign > 0 && <p><span style={{ color: "#4e9af1" }}>● BENIGN    </span><span className="font-mono tabular-nums" style={{ color: "#4e9af1" }}>{d.benign.toLocaleString()}</span></p>}
                      <p className="pt-0.5 mt-0.5" style={{ borderTop: "1px solid #2e3038", color: "#6b6e80" }}>
                        Total <span className="font-mono tabular-nums">{d.total.toLocaleString()}</span>
                      </p>
                    </div>
                  </div>
                );
              }}
            />

            {/* Faint total-volume bar (right axis) — traffic context without distorting threat Y-scale */}
            <Bar yAxisId="right" dataKey="total" fill="#4e9af1" fillOpacity={0.07}
              radius={[2, 2, 0, 0]} isAnimationActive={false} />

            {/* Average threat baseline */}
            {avgThreats > 0 && (
              <ReferenceLine yAxisId="left" y={avgThreats}
                stroke="#e84d4d" strokeDasharray="4 3" strokeOpacity={0.4}
                label={{
                  value: `avg ${fmtYAxis(avgThreats)}`, position: "insideTopRight",
                  fontSize: 9, fill: "#e84d4d60", fontFamily: "JetBrains Mono, monospace"
                }} />
            )}

            {/* Medium — amber area (left axis) */}
            <Area yAxisId="left" type="monotone" dataKey="medium"
              stroke="#f59e0b" strokeWidth={1.5} fill="url(#gm2)"
              dot={false} isAnimationActive={false} connectNulls={true} />

            {/* CRIT/HIGH — red area on top (left axis, scaled to threat range) */}
            <Area yAxisId="left" type="monotone" dataKey="threats"
              stroke="#e84d4d" strokeWidth={2} fill="url(#gc2)"
              dot={false} isAnimationActive={false} connectNulls={true} />

            {/* Brush — pan/zoom for multi-day or long datasets */}
            {showBrush && (
              <Brush dataKey="time" height={18}
                startIndex={brushRange?.start ?? 0}
                endIndex={brushRange?.end ?? Math.max(0, data.length - 1)}
                onChange={r => {
                  if (r && typeof r.startIndex === "number" && typeof r.endIndex === "number")
                    setBrushRange({ start: r.startIndex, end: r.endIndex });
                }}
                fill="#0d0d10" stroke="#2e3038" travellerWidth={7}
                tick={{ fontSize: 9, fill: "#4d5060", fontFamily: "JetBrains Mono, monospace" }}
              />
            )}
          </ComposedChart>
        </ResponsiveContainer>
      </div>

      {/* ── Legend ── */}
      <div className="flex items-center gap-4 mt-1 px-1 shrink-0">
        {[
          { color: "#e84d4d", label: "CRIT/HIGH" },
          { color: "#f59e0b", label: "MEDIUM" },
          { color: "#4e9af1", label: "Total traffic" },
        ].map(({ color, label }) => (
          <span key={label} className="flex items-center gap-1.5 text-[9px]" style={{ color: "#6b6e80" }}>
            <span className="w-3 h-px shrink-0" style={{ background: color, display: "inline-block" }} />
            {label}
          </span>
        ))}
        {sessionId && (
          <span className="ml-auto text-[8px] uppercase tracking-wider font-semibold" style={{ color: "#22c55e40" }}>
            · session
          </span>
        )}
      </div>
    </div>
  );
}

// ── Playbook editor constants ─────────────────────────────────────────────────

const PLAYBOOK_NAMES: Record<string, string> = {
  Block_IP_Playbook: "Block IP",
  Isolate_Host_Playbook: "Isolate Host",
  C2_Containment_Playbook: "C2 Containment",
  Rate_Limit_Playbook: "Rate Limit",
  Lock_Account_Playbook: "Lock Account",
};

const ACTION_OPTIONS: { id: string; label: string; sublabel: string }[] = [
  { id: "pan", label: "Block IP on Palo Alto Firewall", sublabel: "PAN-OS API commit + push" },
  { id: "cs", label: "Isolate Endpoint via CrowdStrike", sublabel: "RTR containment command" },
  { id: "slack", label: "Send Slack Alert to SOC Team", sublabel: "Webhook to #soc-alerts" },
  { id: "bgp", label: "Null-Route via BGP", sublabel: "RTBHv4 community 65535:666" },
];

// ── Playbook editor modal (per-execution — keyed by entry.id) ─────────────────

function PlaybookEditorModal({
  entry, currentOverride, onSave, onClose,
}: {
  entry: CicidsPlaybookLog;
  currentOverride: ActionOverride | undefined;
  onSave: (override: ActionOverride) => void;
  onClose: () => void;
}) {
  const initId = ACTION_OPTIONS.find(o => o.label === currentOverride?.label)?.id ?? "pan";
  const [selectedId, setSelectedId] = useState(initId);
  const selectedOpt = ACTION_OPTIONS.find(o => o.id === selectedId) ?? ACTION_OPTIONS[0];

  function handleSave() {
    onSave({ label: selectedOpt.label, sublabel: selectedOpt.sublabel });
    onClose();
  }

  const displayName = PLAYBOOK_NAMES[entry.playbook_name] ?? entry.playbook_name.replace(/_Playbook$/, "").replace(/_/g, " ");

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40"
        style={{ background: "rgba(0,0,0,0.70)", backdropFilter: "blur(12px)" }}
        onClick={onClose}
      />

      {/* Modal */}
      <div className="fixed z-50 inset-0 flex items-center justify-center p-4 pointer-events-none">
        <div
          className="pointer-events-auto w-full max-w-md rounded-xl shadow-2xl anim-fade-up"
          style={{ background: "#1e1f23", border: "1px solid #2e3038" }}
        >
          {/* Header */}
          <div
            className="flex items-center justify-between px-5 py-4"
            style={{ background: "#222429", borderBottom: "1px solid #2e3038", borderRadius: "12px 12px 0 0" }}
          >
            <div>
              <p className="text-sm font-semibold text-white">Edit Enforcement Action</p>
              <p className="text-[10px] mt-0.5" style={{ color: "#6b6e80" }}>
                Execution #{entry.id} · <span style={{ color: "#a78bfa" }}>{displayName}</span>
                {entry.target_ip && <> · <span className="font-mono text-red-400">{entry.target_ip}</span></>}
              </p>
            </div>
            <button
              onClick={onClose}
              className="w-7 h-7 flex items-center justify-center rounded-lg text-slate-500
                         hover:text-slate-200 bg-slate-800/60 border border-slate-700/50 transition-all text-sm"
            >
              ✕
            </button>
          </div>

          {/* Body */}
          <div className="p-5">
            <div className="rounded-lg p-4" style={{ background: "rgba(255,255,255,0.03)", border: "1px solid #2e3038" }}>
              <p className="text-[10px] uppercase tracking-widest font-semibold mb-3" style={{ color: "#4d5060" }}>
                Select Enforcement Action
              </p>
              <select
                value={selectedId}
                onChange={e => setSelectedId(e.target.value)}
                className="w-full text-xs rounded px-3 py-2 focus:outline-none transition-all cursor-pointer"
                style={{ background: "#141518", border: "1px solid #3e4048", color: "#c5c7d4" }}
              >
                {ACTION_OPTIONS.map(opt => (
                  <option key={opt.id} value={opt.id}>{opt.label}</option>
                ))}
              </select>
              <p className="text-[9px] font-mono mt-2" style={{ color: "#6b6e80" }}>
                Method: <span style={{ color: "#72c811" }}>{selectedOpt.sublabel}</span>
              </p>
            </div>
          </div>

          {/* Footer */}
          <div
            className="flex items-center justify-end gap-2 px-5 py-3"
            style={{ borderTop: "1px solid #2e3038" }}
          >
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded text-xs font-medium transition-all active:opacity-70"
              style={{ background: "rgba(255,255,255,0.04)", border: "1px solid #3e4048", color: "#6b6e80" }}
            >
              Keep Current
            </button>
            <button
              onClick={handleSave}
              className="px-4 py-1.5 rounded text-xs font-semibold transition-all active:scale-95"
              style={{ background: "rgba(114,200,17,0.15)", border: "1px solid rgba(114,200,17,0.40)", color: "#72c811" }}
            >
              Save Changes
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

// ── Playbooks page ────────────────────────────────────────────────────────────

function PlaybooksPage({
  soarEntries,
  activeSessionId,
}: {
  soarEntries: CicidsPlaybookLog[];
  activeSessionId: string | null;
}) {
  const qc = useQueryClient();
  const [editingEntry, setEditingEntry] = useState<CicidsPlaybookLog | null>(null);
  const [actionOverrides, setActionOverrides] = useState<Record<number, ActionOverride>>({});

  const { data: persisted = [] } = useQuery({
    queryKey: ["cicids-playbook-logs"],
    queryFn: () => api.getCicidsPlaybookLogs(50),
    refetchInterval: 30_000,
  });

  const { data: aiPlaybookLog = [] } = useQuery({
    queryKey: ["ai-playbook-log"],
    queryFn: () => api.getPlaybookLog(50),
    refetchInterval: 30_000,
  });

  // Session-scoped SOAR feed — always active when a pipeline session is loaded.
  // Uses the /api/pipeline/soar-feed endpoint which maps CRITICAL/HIGH/MEDIUM
  // alerts to realistic playbook execution entries, bypassing the need for a
  // live SOAR engine to have fired.
  const { data: sessionSoarFeed = [] } = useQuery({
    queryKey: ["session-soar-feed", activeSessionId],
    queryFn: () => api.getSessionSoarFeed(activeSessionId!, 50),
    enabled: !!activeSessionId,
    staleTime: 60_000,
  });

  const seen = new Set<number>();
  const merged: CicidsPlaybookLog[] = [];
  for (const e of [...soarEntries, ...persisted, ...sessionSoarFeed]) {
    if (!seen.has(e.id)) { seen.add(e.id); merged.push(e); }
  }
  const allEntries = merged.slice(0, 50);

  function refreshAll() {
    qc.invalidateQueries({ queryKey: ["cicids-playbook-logs"] });
    qc.invalidateQueries({ queryKey: ["cicids-stats"] });
    qc.invalidateQueries({ queryKey: ["cicids-logs"] });
    qc.invalidateQueries({ queryKey: ["cicids-actioned-ips"] });
  }

  return (
    <div className="p-3 space-y-3">
      {/* Page toolbar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-widest font-semibold" style={{ color: "#4d5060" }}>
            Automated Response Engine
          </span>
          <span
            className="text-[9px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider anim-glow"
            style={{ background: "rgba(114,200,17,0.10)", border: "1px solid rgba(114,200,17,0.30)", color: "#72c811" }}
          >
            Palo Alto NGFW · Live
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={refreshAll}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium
                       transition-opacity active:opacity-70"
            style={{ background: "rgba(78,154,241,0.10)", border: "1px solid rgba(78,154,241,0.30)", color: "#4e9af1" }}
          >
            ↻ Refresh
          </button>
        </div>
      </div>

      <BentoPanel title="SOAR Execution Timeline — Automated Response Workflows" accent noPad>
        <div className="p-3">
          <PlaybookTimeline
            entries={allEntries}
            actionOverrides={actionOverrides}
            onEditEntry={setEditingEntry}
          />
        </div>
      </BentoPanel>
      <BentoPanel title="SOAR Activity Feed — Enforcement Log">
        <SOARActivity liveEntries={soarEntries} />
      </BentoPanel>

      {aiPlaybookLog.length > 0 && (
        <BentoPanel title="AI Triage SOAR Log — Claude-Triggered Playbooks">
          <div className="space-y-1 p-1">
            {aiPlaybookLog.map(entry => (
              <div
                key={entry.id}
                className="flex items-start gap-3 px-3 py-2 rounded text-[10px] font-mono"
                style={{ background: "#0d0d10", border: "1px solid #1a1a1f" }}
              >
                <span className="shrink-0 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase"
                  style={{ background: "rgba(114,200,17,0.10)", color: "#72c811", border: "1px solid #72c81130" }}>
                  {entry.status}
                </span>
                <div className="flex-1 min-w-0">
                  <span style={{ color: "#c0c4d0" }}>{entry.playbook_name}</span>
                  <span className="mx-1.5" style={{ color: "#3d3f4a" }}>·</span>
                  <span style={{ color: "#6b6e80" }}>{entry.simulated_action}</span>
                </div>
                <span className="shrink-0" style={{ color: "#3d3f4a" }}>
                  {new Date(entry.executed_at).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        </BentoPanel>
      )}

      {editingEntry && (
        <PlaybookEditorModal
          entry={editingEntry}
          currentOverride={actionOverrides[editingEntry.id]}
          onSave={override => setActionOverrides(prev => ({ ...prev, [editingEntry.id]: override }))}
          onClose={() => setEditingEntry(null)}
        />
      )}
    </div>
  );
}

// ── Shared UI primitives ──────────────────────────────────────────────────────

function BentoPanel({ title, children, noPad = false, accent = false }: {
  title: string; children: React.ReactNode; noPad?: boolean; accent?: boolean;
}) {
  return (
    <div className="splunk-panel overflow-hidden">
      <div className="splunk-panel-header">
        <span
          className="w-1.5 h-1.5 rounded-full shrink-0"
          style={{ background: accent ? "var(--splunk-green)" : "var(--splunk-muted)" }}
        />
        {title}
      </div>
      <div className={noPad ? "" : "p-3"}>{children}</div>
    </div>
  );
}


