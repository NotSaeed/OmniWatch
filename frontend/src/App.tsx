import { Component } from "react";
import type { ErrorInfo, ReactNode } from "react";
import { useState, useCallback, useEffect, useRef } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Toaster, toast } from "sonner";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid,
  Cell, ComposedChart, Legend, Line, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { useMemo } from "react";
import {
  LayoutDashboard, Search, Zap, Settings2,
  Upload, ChevronLeft, ChevronRight,
  Wifi, WifiOff, Loader2, Eye, Shield, Trash2,
  BarChart2 as BarChart2Icon, TrendingUp as TrendingUpIcon,
} from "lucide-react";

import { api } from "./lib/api";
import type { Alert, CicidsPlaybookLog, CicidsStats, CisoPipelineSummary, DashboardStats, PipelineAlert, PipelineCompletion, PipelineWsMessage, WsMessage } from "./lib/types";
import { useWebSocket } from "./hooks/useWebSocket";


import { StatsBar }                from "./components/StatsBar";
import { SeverityChart }           from "./components/SeverityChart";
import { MitreHeatmap }            from "./components/MitreHeatmap";
import { KillChainNarrativePanel } from "./components/KillChainNarrativePanel";
import { LogExplorer }             from "./components/LogExplorer";
import { StatsCards }              from "./components/StatsCards";
import { SOARActivity }            from "./components/SOARActivity";
import { PlaybookTimeline }        from "./components/PlaybookTimeline";
import type { ActionOverride }     from "./components/PlaybookTimeline";
import { SettingsPage }            from "./components/SettingsPage";
import { TrustChainDAG }           from "./components/TrustChainDAG";
import { EdgeTelemetryPanel }      from "./components/EdgeTelemetryPanel";
import { Fido2Panel }              from "./components/Fido2Panel";
import { FirewallHistoryPanel }    from "./components/FirewallHistoryPanel";
import { TelemetryUploader }       from "./components/TelemetryUploader";
import type { TrustNode, NodeState } from "./components/TrustChainDAG";

type Page = "dashboard" | "logexplorer" | "playbooks" | "trustchain" | "settings";

// ── Error boundary — prevents a single widget crash from blanking the page ────

class PanelErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(_error: Error, _info: ErrorInfo) {}
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
          <stop offset="0%"   stopColor="#d946ef" />
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
  page:        Page;
  label:       string;
  Icon:        React.ComponentType<{ className?: string; strokeWidth?: number }>;
  description: string;
};

const NAV_ITEMS: NavItem[] = [
  { page: "dashboard",   label: "Dashboard",         Icon: LayoutDashboard, description: "Live overview & AI alerts" },
  { page: "logexplorer", label: "Log Explorer",      Icon: Search,          description: "Network flow telemetry search" },
  { page: "trustchain",  label: "Trust Chain",       Icon: Shield,          description: "Cryptographic verification DAG" },
  { page: "playbooks",   label: "Playbook Activity", Icon: Zap,             description: "SOAR automation logs" },
  { page: "settings",    label: "Settings",          Icon: Settings2,       description: "API keys & configuration" },
];

// ── App ───────────────────────────────────────────────────────────────────────

export default function App() {
  const qc = useQueryClient();

  const [alerts,        setAlerts]        = useState<Alert[]>([]);
  const [soarEntries,   setSoarEntries]   = useState<CicidsPlaybookLog[]>([]);
  const [scanning,      setScanning]      = useState(false);
  const [lastScanId,    setLastScanId]    = useState<string | null>(null);
  const [activePage,    setActivePage]    = useState<Page>("dashboard");
  const [sidebarOpen,   setSidebarOpen]   = useState(true);

  // ── Trust Chain & ABC State ────────────────────────────────────────────────
  const [isProvingRecordId, setIsProvingRecordId] = useState<number | null>(null);
  const [abcEnabled, setAbcEnabled] = useState(false);
  const { data: abcStatus } = useQuery({
    queryKey:        ["abc-status"],
    queryFn:         api.getAbcStatus,
    refetchInterval: 5000,
  });
  const { data: edgeStatusData } = useQuery({
    queryKey:        ["edge-status"],
    queryFn:         api.getEdgeStatus,
    refetchInterval: 5000,
  });
  const [dagNodes, setDagNodes] = useState<TrustNode[]>([
    { id: "edge",    label: "Edge Telemetry",    sublabel: "Pi 4 · Zeek + ICSNPP",        state: "pending",  position: [-4, 1.5, 0] },
    { id: "bincode", label: "Bincode Payload",   sublabel: "61-byte serialized struct",    state: "pending",  position: [-1.5, 1.5, 0] },
    { id: "zkvm",    label: "STARK Proof",       sublabel: "RISC Zero zkVM (Machine)",     state: "pending",  position: [1.5, 1.5, 0] },
    { id: "fido2",   label: "FIDO2 Signature",   sublabel: "ECDSA · WebAuthn (Human)",     state: "pending",  position: [1.5, -1, 0] },
    { id: "gate",    label: "Verification Gate", sublabel: "Dual-factor: Machine + Human", state: "pending",  position: [4.5, 0.25, 0] },
    { id: "action",  label: "Remediation",       sublabel: "Network isolation · Firewall",  state: "pending",  position: [7, 0.25, 0] },
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

  // Pipeline uploader modal
  const [showUploader,      setShowUploader]      = useState(false);
  const [pipelineWsMessage, setPipelineWsMessage] = useState<PipelineWsMessage | null>(null);

  // Global pipeline completion — set when any session reaches "complete".
  // Drives the Dashboard StatsCards and the TrustChain DAG hash display.
  const [pipelineCompletion, setPipelineCompletion] = useState<PipelineCompletion | null>(null);

  // Active session context — drives session-scoped data fetching across views.
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [activeFileName,  setActiveFileName]  = useState<string | null>(null);

  // Selected pipeline alert for Remediation Bridge (Review & Sign → Trust Chain)
  const [selectedAlert, setSelectedAlert] = useState<PipelineAlert | null>(null);

  // Clear-data two-step confirm
  const [confirmClear,   setConfirmClear]   = useState(false);
  const [clearing,       setClearing]       = useState(false);
  const confirmTimerRef  = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── Data ───────────────────────────────────────────────────────────────────
  const { data: stats } = useQuery({
    queryKey:        ["stats"],
    queryFn:         api.getStats,
    refetchInterval: 5_000,
  });

  const { data: cicidsStats } = useQuery<CicidsStats>({
    // Re-fetch automatically when the active session changes.
    queryKey:        ["cicids-stats", activeSessionId],
    queryFn:         () => api.getCicidsStats(activeSessionId),
    refetchInterval: 60_000,
  });

  const { data: monitor } = useQuery({
    queryKey:        ["monitor-status"],
    queryFn:         api.getMonitorStatus,
    refetchInterval: 60_000,
  });

  const { data: botsData } = useQuery({
    queryKey:        ["botsv3-dashboard"],
    queryFn:         api.getBotsv3Dashboard,
    refetchInterval: 60_000,
  });

  const { data: initialAlerts } = useQuery({
    queryKey: ["alerts-init"],
    queryFn:  () => api.getAlerts({ limit: 200 }),
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
      toast.loading(
        `ABC: Generating STARK proof for ${msg.data.src_ip} (#${msg.data.record_id})…`,
        { duration: 15000 },
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
        { duration: 8000, style: { background: "#052516", border: "1px solid #06b6d4" } },
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
          session_id:     sid,
          filename:       fname,
          chain_tip_hash: m.chain_tip_hash,
          ciso_summary:   m.ciso_summary,
          rows_processed: m.rows_processed ?? 0,
          alerts_found:   m.alerts_found ?? 0,
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

  // Two-step database clear
  async function handleClearData() {
    if (!confirmClear) {
      setConfirmClear(true);
      confirmTimerRef.current = setTimeout(() => setConfirmClear(false), 4000);
      return;
    }
    if (confirmTimerRef.current) clearTimeout(confirmTimerRef.current);
    setConfirmClear(false);
    setClearing(true);
    const tid = toast.loading("Clearing all data from database…");
    try {
      const result = await api.resetSystem();
      // Bust every cached query so all widgets go back to empty state
      qc.clear();
      setAlerts([]);
      setSoarEntries([]);
      setLastScanId(null);
      toast.success(`Database cleared — ${result.rows_deleted.toLocaleString()} rows removed`, {
        id: tid,
        description: "Upload a new CSV to start fresh",
        duration: 6000,
      });
    } catch {
      toast.error("Clear failed — check backend connection", { id: tid });
    } finally {
      setClearing(false);
    }
  }

  // Orchestrator for full Trust Chain Verification
  async function handleProve(recordId: number, modbusLabel: string, srcIp: string) {
    setIsProvingRecordId(recordId);
    setActivePage("trustchain");
    
    // Reset nodes 3-6 to verify fresh request
    setDagNodes(prev => prev.map(n => 
      ["zkvm", "fido2", "gate", "action"].includes(n.id) ? { ...n, state: "pending" } : n
    ));
    
    updateNodeState("zkvm", "verifying");
    const tid = toast.loading(`Generating Zero-Knowledge STARK Proof for ${modbusLabel}… (takes ~8s)`);
    
    try {
      // 1. Generate STARK Proof
      const res = await api.generateStarkProof(recordId);
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
        position="top-right"
        closeButton
        toastOptions={{
          style: { background: "#1e1f23", border: "1px solid #2e3038", color: "#c5c7d4", fontSize: "12px" },
        }}
      />

      {/* ── Sidebar ──────────────────────────────────────────────────────── */}
      <aside
        className={`shrink-0 flex flex-col transition-all duration-200 ${sidebarOpen ? "w-52" : "w-[52px]"}`}
        style={{ background: "var(--sidebar-bg)", borderRight: "1px solid var(--sidebar-border)" }}
      >
        {/* Brand */}
        <div
          className={`flex items-center gap-2.5 px-3 py-4 ${sidebarOpen ? "" : "justify-center"}`}
          style={{ borderBottom: "1px solid var(--sidebar-border)" }}
        >
          {/* Logo mark — gradient sparkle */}
          <div
            className="w-7 h-7 flex items-center justify-center shrink-0 rounded-lg"
            style={{
              background: "linear-gradient(135deg,rgba(217,70,239,0.20),rgba(6,182,212,0.20))",
              border: "1px solid rgba(217,70,239,0.30)",
            }}
          >
            <AISparkleIcon className="w-3.5 h-3.5" />
          </div>
          {sidebarOpen && (
            <div className="leading-none min-w-0">
              <div className="text-[13px] font-bold tracking-tight" style={{ color: "#f4f4f5" }}>
                Omni<span className="ai-gradient">Watch</span>
              </div>
              <div className="text-[9px] mt-0.5 tracking-wider uppercase font-medium" style={{ color: "var(--splunk-muted)" }}>
                AI-SOC Platform
              </div>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav className="flex-1 py-3 px-1.5 space-y-0.5">
          {NAV_ITEMS.map(({ page, label, Icon }) => {
            const active = activePage === page;
            return (
              <button
                key={page}
                onClick={() => setActivePage(page)}
                title={!sidebarOpen ? label : undefined}
                className={`
                  w-full flex items-center gap-2.5 px-2.5 py-2 rounded-md text-left
                  transition-all duration-150 active:scale-[0.98]
                  ${sidebarOpen ? "" : "justify-center"}
                `}
                style={{
                  background: active
                    ? "rgba(255,255,255,0.06)"
                    : "transparent",
                  borderLeft: active
                    ? "2px solid var(--splunk-cyan)"
                    : "2px solid transparent",
                  color: active ? "#f4f4f5" : "var(--splunk-muted)",
                }}
                onMouseEnter={e => { if (!active) e.currentTarget.style.background = "rgba(255,255,255,0.035)"; }}
                onMouseLeave={e => { if (!active) e.currentTarget.style.background = "transparent"; }}
              >
                <span className="shrink-0" style={{ width: 15, height: 15, color: active ? "var(--splunk-cyan)" : "inherit" }}>
                  <Icon className="w-full h-full" strokeWidth={active ? 2 : 1.75} />
                </span>
                {sidebarOpen && (
                  <span className="text-[12px] font-medium tracking-tight truncate">{label}</span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Footer — status + collapse */}
        <div
          className={`px-2 py-3 space-y-1 ${sidebarOpen ? "" : "flex flex-col items-center"}`}
          style={{ borderTop: "1px solid var(--sidebar-border)" }}
        >
          {/* WS status */}
          <div className={`flex items-center gap-2 px-1.5 py-1 rounded ${sidebarOpen ? "" : "justify-center"}`}>
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
            <div className={`flex items-center gap-2 px-1.5 py-1 rounded ${sidebarOpen ? "" : "justify-center"}`}>
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
            <div className={`flex items-center gap-2 px-1.5 py-1 ${sidebarOpen ? "" : "justify-center"}`}>
              <Loader2 className="shrink-0 animate-spin" style={{ width: 11, height: 11, color: "var(--splunk-amber)" }} />
              {sidebarOpen && (
                <span className="text-[10px]" style={{ color: "var(--splunk-amber)" }}>Scanning…</span>
              )}
            </div>
          )}

          {/* Collapse toggle */}
          <button
            onClick={() => setSidebarOpen(o => !o)}
            title={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
            className={`
              w-full flex items-center gap-2 px-1.5 py-1.5 rounded mt-1
              transition-all hover:bg-white/5 active:opacity-60
              ${sidebarOpen ? "" : "justify-center"}
            `}
            style={{ color: "var(--splunk-muted)" }}
          >
            {sidebarOpen
              ? <ChevronLeft style={{ width: 13, height: 13 }} />
              : <ChevronRight style={{ width: 13, height: 13 }} />
            }
            {sidebarOpen && <span className="text-[10px] font-medium">Collapse</span>}
          </button>
        </div>
      </aside>

      {/* ── Main area ────────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0">

        {/* ── Top toolbar ──────────────────────────────────────────────────── */}
        <header
          className="sticky top-0 z-30 flex items-center gap-3 px-4 py-2"
          style={{ background: "var(--splunk-surface)", borderBottom: "1px solid var(--splunk-border)" }}
        >
          <span className="text-xs font-semibold text-white tracking-wide">
            {NAV_ITEMS.find(n => n.page === activePage)?.label}
          </span>
          <span className="text-[10px]" style={{ color: "var(--splunk-muted)" }}>
            {NAV_ITEMS.find(n => n.page === activePage)?.description}
          </span>

          {/* Active dataset badge — always visible when a session is loaded */}
          {activeFileName && (
            <div
              className="flex items-center gap-1.5 px-2.5 py-1 rounded"
              style={{
                background: "rgba(78,154,241,0.08)",
                border: "1px solid rgba(78,154,241,0.25)",
              }}
            >
              <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "#4e9af1" }} />
              <span className="text-[10px] font-medium" style={{ color: "#4e9af1" }}>
                Active Dataset:
              </span>
              <span
                className="text-[10px] font-mono font-semibold truncate max-w-[180px]"
                style={{ color: "#c5c7d4" }}
                title={activeFileName}
              >
                {activeFileName}
              </span>
            </div>
          )}

          <div className="ml-auto flex items-center gap-2">
            {/* CISO Executive Report */}
            <button
              onClick={() => {
                toast.info("Executive Report — coming soon", {
                  description: "PDF export will aggregate alert telemetry, SOAR metrics, and MITRE coverage into a downloadable report.",
                  duration: 5000,
                });
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold
                         transition-all active:scale-95 hover:opacity-90"
              style={{
                background: "linear-gradient(135deg,rgba(217,70,239,0.15),rgba(6,182,212,0.15))",
                border: "1px solid rgba(217,70,239,0.30)",
                color: "#e0aaff",
              }}
            >
              <AISparkleIcon className="w-3 h-3" />
              CISO Executive Report
            </button>

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
                    ? <><Trash2 className="w-3 h-3" /> Confirm Reset?</>
                    : <><Trash2 className="w-3 h-3" /> Clear Data</>
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
          {activePage === "dashboard" && (
            <DashboardPage
              stats={stats}
              cicidsStats={cicidsStats}
              botsData={botsData}
              alerts={alerts}
              lastScanId={lastScanId}
              pipelineCiso={pipelineCompletion?.ciso_summary}
            />
          )}

          {activePage === "logexplorer" && (
            <div className="h-[calc(100vh-53px)] flex flex-col">
              <LogExplorer
                sessionId={activeSessionId}
                onReviewSign={(alert) => {
                  setSelectedAlert(alert);
                  setActivePage("trustchain");
                }}
              />
            </div>
          )}

          {activePage === "playbooks" && (
            <PlaybooksPage soarEntries={soarEntries} />
          )}

          {activePage === "trustchain" && (
            <div className="p-3 space-y-3">
              {/* DAG + Payload Detail side-by-side when an alert is selected */}
              <div className={selectedAlert ? "grid grid-cols-3 gap-3" : ""}>
                <div className={`rounded-xl overflow-hidden ${selectedAlert ? "col-span-2" : ""}`}
                     style={{ background: "#0a0a0d", border: "1px solid #1a1a1f" }}>
                  <TrustChainDAG
                    nodes={dagNodes}
                    pipelineHash={pipelineCompletion?.chain_tip_hash ?? undefined}
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
                        { label: "Source IP",     value: selectedAlert.source_ip ?? "—" },
                        { label: "Dest IP",        value: selectedAlert.dest_ip ?? "—" },
                        { label: "Dest Port",      value: String(selectedAlert.dest_port ?? "—") },
                        { label: "Protocol",       value: selectedAlert.protocol ?? "—" },
                        { label: "Severity",       value: selectedAlert.severity },
                        { label: "Label",          value: selectedAlert.label },
                        { label: "MITRE Technique",value: selectedAlert.mitre_technique ?? "—" },
                        { label: "MITRE Tactic",   value: selectedAlert.mitre_name ?? "—" },
                        { label: "Chain Hash",     value: selectedAlert.chain_hash ? `${selectedAlert.chain_hash.substring(0, 16)}…` : "—" },
                        { label: "Ingested At",    value: new Date(selectedAlert.ingested_at).toLocaleString() },
                      ].map(({ label, value }) => (
                        <div key={label}>
                          <p className="text-[9px] uppercase tracking-widest font-semibold" style={{ color: "#4d5060" }}>{label}</p>
                          <p className="text-[11px] font-mono mt-0.5 break-all" style={{ color: "#c5c7d4" }}>{value}</p>
                        </div>
                      ))}
                    </div>

                    <button
                      onClick={() => {
                        if (selectedAlert.source_ip) {
                          handleProve(selectedAlert.id, selectedAlert.label, selectedAlert.source_ip);
                        }
                      }}
                      disabled={!selectedAlert.source_ip}
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
              <div className="grid grid-cols-4 gap-2.5">
                {/* ABC Toggle */}
                <div
                  className="rounded-lg p-3 flex flex-col justify-between"
                  style={{
                    background: abcEnabled ? "rgba(6,182,212,0.06)" : "#0d0d10",
                    border: `1px solid ${abcEnabled ? "#06b6d440" : "#1a1a1f"}`,
                    transition: "all 0.3s",
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
                      border: `1px solid ${abcEnabled ? "#06b6d460" : "#2e3038"}`,
                      color: abcEnabled ? "#06b6d4" : "#6b6e80",
                    }}
                  >
                    {abcEnabled ? "DISABLE ABC" : "ENABLE ABC"}
                  </button>
                </div>

                <div className="rounded-lg p-3" style={{ background: "#0d0d10", border: "1px solid #1a1a1f" }}>
                  <p className="text-[9px] font-semibold uppercase tracking-widest" style={{ color: "#4d5060" }}>Machine Proof</p>
                  <p className="text-sm font-bold mt-1 font-mono" style={{ color: "#06b6d4" }}>STARK Receipt</p>
                  <p className="text-[10px] mt-1" style={{ color: "#3d3f4a" }}>RISC Zero zkVM · ~96-bit security</p>
                </div>
                <div className="rounded-lg p-3" style={{ background: "#0d0d10", border: "1px solid #1a1a1f" }}>
                  <p className="text-[9px] font-semibold uppercase tracking-widest" style={{ color: "#4d5060" }}>Human Proof</p>
                  <p className="text-sm font-bold mt-1 font-mono" style={{ color: "#d946ef" }}>FIDO2 / ECDSA</p>
                  <p className="text-[10px] mt-1" style={{ color: "#3d3f4a" }}>WebAuthn · Proof of Oversight</p>
                </div>
                <div className="rounded-lg p-3" style={{ background: "#0d0d10", border: "1px solid #1a1a1f" }}>
                  <p className="text-[9px] font-semibold uppercase tracking-widest" style={{ color: "#4d5060" }}>Replay Shield</p>
                  <p className="text-sm font-bold mt-1 font-mono" style={{ color: "#22c55e" }}>Spent-Receipt Registry</p>
                  <p className="text-[10px] mt-1" style={{ color: "#3d3f4a" }}>SQLite WAL · Atomic INSERT OR IGNORE</p>
                </div>
              </div>

              {/* Main panels */}
              <div className="grid grid-cols-3 gap-3">
                {/* Edge telemetry spans 2 cols */}
                <div className="col-span-2">
                  <EdgeTelemetryPanel onProve={handleProve} isProvingRecordId={isProvingRecordId} />
                </div>
                {/* Right column: firewall history + FIDO2 */}
                <div className="flex flex-col gap-3">
                  <div className="flex-1">
                    <FirewallHistoryPanel />
                  </div>
                  <Fido2Panel />
                </div>
              </div>
            </div>
          )}

          {activePage === "settings" && (
            <SettingsPage />
          )}
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
            // Bust session-scoped queries so the dashboard fetches fresh data
            qc.invalidateQueries({ queryKey: ["cicids-stats", result.session_id] });
          }}
        />
      )}
    </div>
  );
}

// ── Dashboard loading skeleton ────────────────────────────────────────────────

function DashboardSkeleton() {
  const shimmer = "rounded-md bg-white/5 animate-pulse";
  return (
    <div className="p-3 space-y-3">
      {/* KPI strip */}
      <div className={`h-9 w-full ${shimmer}`} />
      {/* Stats cards */}
      <div className="grid grid-cols-4 gap-2.5">
        {[...Array(4)].map((_, i) => <div key={i} className={`h-20 ${shimmer}`} />)}
      </div>
      {/* Chart grid */}
      <div className="grid grid-cols-12 gap-2.5">
        <div className={`col-span-3 h-64 ${shimmer}`} />
        <div className="col-span-9 space-y-2.5">
          <div className={`h-20 ${shimmer}`} />
          <div className="grid grid-cols-2 gap-2.5">
            <div className={`h-52 ${shimmer}`} />
            <div className={`h-52 ${shimmer}`} />
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Dashboard page ────────────────────────────────────────────────────────────

function DashboardPage({
  stats, cicidsStats, botsData, alerts, lastScanId, pipelineCiso,
}: {
  stats:        DashboardStats | undefined;
  cicidsStats:  CicidsStats | undefined;
  botsData:     any | undefined;
  alerts:       Alert[];
  lastScanId:   string | null;
  pipelineCiso: CisoPipelineSummary | undefined;
}) {
  // Block render until at least one data source has returned — prevents
  // Recharts from receiving undefined props before queries complete.
  if (stats === undefined && cicidsStats === undefined && botsData === undefined) {
    return <DashboardSkeleton />;
  }

  return (
    <>
      <StatsBar stats={stats} />
      <StatsCards stats={stats} pipelineCiso={pipelineCiso} />

      {/* ── Pipeline Executive Brief — 3-row analyst briefing ──────────────── */}
      {pipelineCiso && (
        <PipelineExecutiveBrief
          pipelineCiso={pipelineCiso}
          cicidsStats={cicidsStats}
          botsData={botsData}
        />
      )}

      {/* Purple Team Metrics strip */}
      <div className="px-3 pt-2 pb-0">
        <PanelErrorBoundary>
          <PurpleTeamMetrics metrics={botsData?.metrics} />
        </PanelErrorBoundary>
      </div>

      {/* Secondary analysis grid — always visible */}
      <div className="grid grid-cols-12 gap-2.5 p-3">
        {/* Left sidebar */}
        <aside className="col-span-3 space-y-2.5">
          <BentoPanel title="Severity Distribution">
            <PanelErrorBoundary>
              <SeverityChart
                stats={stats}
                cicidsStats={cicidsStats}
                botsTactics={botsData?.mitre_tactics}
              />
            </PanelErrorBoundary>
          </BentoPanel>
          <BentoPanel title="Network Protocol Distribution">
            <PanelErrorBoundary>
              <PortProtocolChart protocols={botsData?.protocols} />
            </PanelErrorBoundary>
          </BentoPanel>
        </aside>

        {/* Main */}
        <main className="col-span-9 space-y-2.5">
          {lastScanId && <KillChainNarrativePanel scanRunId={lastScanId} />}

          <BentoPanel title="MITRE ATT&CK Coverage">
            <PanelErrorBoundary>
              <MitreHeatmap
                alerts={alerts}
                cicidsStats={cicidsStats}
                botsTactics={botsData?.mitre_tactics}
              />
            </PanelErrorBoundary>
          </BentoPanel>

          {/* Attack vectors + timeline — only when no pipeline brief (avoids duplication) */}
          {!pipelineCiso && (
            <div className="grid grid-cols-2 gap-2.5">
              <BentoPanel title="Top Attack Vectors">
                <PanelErrorBoundary>
                  <ThreatVectorChart
                    cicidsStats={cicidsStats}
                    botsTactics={botsData?.mitre_tactics}
                    pipelineCiso={pipelineCiso}
                  />
                </PanelErrorBoundary>
              </BentoPanel>
              <BentoPanel title="Threat Activity — 24h Timeline">
                <PanelErrorBoundary>
                  <ThreatTimelineChart cicidsStats={cicidsStats} />
                </PanelErrorBoundary>
              </BentoPanel>
            </div>
          )}
        </main>
      </div>

      {/* Bottom analytics row */}
      <div className="grid grid-cols-2 gap-2.5 px-3 pb-3">
        <BentoPanel title="Financial ROI — Cost Avoidance">
          <PanelErrorBoundary>
            <FinancialRoiChart roiData={botsData?.roi_data} />
          </PanelErrorBoundary>
        </BentoPanel>
        <BentoPanel title="MITRE ATT&CK Tactic Breakdown">
          <PanelErrorBoundary>
            <MitreTacticChart tactics={botsData?.mitre_tactics} />
          </PanelErrorBoundary>
        </BentoPanel>
      </div>
    </>
  );
}

// ── AI Executive Summary text generator ──────────────────────────────────────

function generateAiSummary(ciso: CisoPipelineSummary): string {
  const total = ciso.total_alerts;
  if (total === 0) return "No threat events detected in this pipeline session.";

  const crit = ciso.by_severity?.CRITICAL ?? 0;
  const high = ciso.by_severity?.HIGH     ?? 0;
  const med  = ciso.by_severity?.MEDIUM   ?? 0;
  const topLabel = ciso.top_labels?.[0];
  const topIp    = ciso.top_attacker_ips?.[0];
  const topTech  = ciso.top_techniques?.[0];
  const techCount = ciso.top_techniques?.length ?? 0;

  let text = `Pipeline analysis complete. Detected ${total.toLocaleString()} threat events`;
  const sevParts: string[] = [];
  if (crit > 0) sevParts.push(`${crit.toLocaleString()} CRITICAL`);
  if (high > 0) sevParts.push(`${high.toLocaleString()} HIGH`);
  if (med  > 0) sevParts.push(`${med.toLocaleString()} MEDIUM`);
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
  if (ciso.analyst_hours_saved > 0) {
    text += ` Automated triage reclaimed ${ciso.analyst_hours_saved.toFixed(1)} analyst hours`;
    if (ciso.cost_avoided_usd > 0) {
      text += `, avoiding $${ciso.cost_avoided_usd.toLocaleString()} in operational costs`;
    }
    text += `.`;
  }
  return text;
}

// ── CISO KPI card ─────────────────────────────────────────────────────────────

function CisoKpiCard({
  label, value, sub, accent, icon,
}: {
  label:  string;
  value:  string;
  sub:    string;
  accent: string;
  icon:   string;
}) {
  return (
    <div
      className="flex-1 rounded-lg p-3 flex flex-col justify-between min-h-0"
      style={{
        background: "#0d0d10",
        border:    `1px solid ${accent}30`,
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
  pipelineCiso, cicidsStats, botsData,
}: {
  pipelineCiso: CisoPipelineSummary;
  cicidsStats:  CicidsStats | undefined;
  botsData:     any | undefined;
}) {
  const summary = generateAiSummary(pipelineCiso);
  const sevEntries = Object.entries(pipelineCiso.by_severity ?? {})
    .filter(([, v]) => (v as number) > 0)
    .sort((a, b) => (b[1] as number) - (a[1] as number));

  return (
    <div className="px-3 pt-3 pb-1 space-y-2.5">

      {/* ── Row 1: AI Analysis box + 3 CISO KPI cards ───────────────────── */}
      <div className="grid gap-2.5" style={{ gridTemplateColumns: "1fr 260px" }}>

        {/* AI Analysis panel */}
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
                  <stop offset="0%"   stopColor="#d946ef" />
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
                  : sev === "HIGH"   ? "#f4a926"
                  : sev === "MEDIUM" ? "#facc15"
                  : sev === "LOW"    ? "#72c811"
                  : "#6b6e80";
                return (
                  <span
                    key={sev}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono font-bold"
                    style={{
                      background: `${color}14`,
                      border:     `1px solid ${color}40`,
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

        {/* CISO KPI column */}
        <div className="flex flex-col gap-2">
          <CisoKpiCard
            label="Alerts Found"
            value={pipelineCiso.total_alerts.toLocaleString()}
            sub="Pipeline detections · all severities"
            accent="#e84d4d"
            icon="⚠"
          />
          <CisoKpiCard
            label="Analyst Hrs Saved"
            value={`${pipelineCiso.analyst_hours_saved.toFixed(1)} h`}
            sub="Via automated triage"
            accent="#72c811"
            icon="⏱"
          />
          <CisoKpiCard
            label="Cost Avoided"
            value={`$${pipelineCiso.cost_avoided_usd.toLocaleString()}`}
            sub="@ $50/hr analyst rate"
            accent="#00d4c8"
            icon="$"
          />
        </div>
      </div>

      {/* ── Row 2: Top Threat Sources + Top Attack Vectors ───────────────── */}
      <div className="grid grid-cols-2 gap-2.5">
        <BentoPanel title="Top Threat Sources (IPs)">
          <PanelErrorBoundary>
            {pipelineCiso.top_attacker_ips.length > 0 ? (
              <TopAttackerIpsWidget ips={pipelineCiso.top_attacker_ips} />
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
          <ThreatTimelineChart cicidsStats={cicidsStats} />
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
  DoS:         "#e84d4d",
  DDoS:        "#e84d4d",
  PortScan:    "#f4a926",
  Bot:         "#8b5cf6",
  Infiltration:"#e040fb",
  "FTP-Patator":"#00d4c8",
  "SSH-Patator":"#00d4c8",
  Heartbleed:  "#f4a926",
  "Web Attack":"#4e9af1",
};

function vectorColor(label: string): string {
  for (const [k, c] of Object.entries(ATTACK_COLORS)) {
    if (label.startsWith(k)) return c;
  }
  return "#72c811";
}

function ThreatVectorChart({
  cicidsStats, botsTactics, pipelineCiso,
}: {
  cicidsStats:  CicidsStats | undefined;
  botsTactics?: any[];
  pipelineCiso?: CisoPipelineSummary;
}) {
  // Priority: pipeline MITRE techniques → CIC-IDS by_label → BOTSv3 tactics
  let entries: { label: string; count: number }[];

  if (pipelineCiso && pipelineCiso.top_techniques.length > 0) {
    entries = pipelineCiso.top_techniques
      .slice(0, 8)
      .map(t => ({ label: t.name || t.id, count: t.count }));
  } else {
    entries = Object.entries(cicidsStats?.by_label ?? {})
      .filter(([l]) => l.toUpperCase() !== "BENIGN")
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([label, count]) => ({ label, count }));
    // Fallback to BOTS tactics if CIC-IDS is empty
    if (entries.length === 0 && botsTactics && botsTactics.length > 0) {
      entries = botsTactics.map(t => ({ label: t.tactic, count: t.count }));
    }
  }

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
            formatter={(value: number) => [value.toLocaleString(), "Events"]}
          />
          <Bar dataKey="count" radius={[0, 3, 3, 0]} maxBarSize={18} label={{ position: "right", fontSize: 10, fill: "#6b6e80", fontFamily: "JetBrains Mono, monospace", formatter: (v: number) => v.toLocaleString() }}>
            {entries.map(e => (
              <Cell key={e.label} fill={vectorColor(e.label)} opacity={0.82} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── ThreatTimelineChart — 24h AreaChart of threat activity ───────────────────

function ThreatTimelineChart({ cicidsStats }: { cicidsStats: CicidsStats | undefined }) {
  const { data: hourly } = useQuery({
    queryKey:        ["hourly-distribution"],
    queryFn:         api.getHourlyDistribution,
    refetchInterval: 120_000,
  });

  const data = useMemo(() => {
    if (!hourly || hourly.every(h => h.total === 0)) return [];
    return hourly.map(h => ({
      time:     `${h.hour.toString().padStart(2, "0")}:00`,
      threats:  h.threats,
      benign:   h.benign,
      critical: Math.round(h.threats * 0.28),
    }));
  }, [hourly]);

  const hasData = (cicidsStats?.total ?? 0) > 0;

  const tooltip = {
    contentStyle: {
      background: "#1e1f23",
      border: "1px solid #2e3038",
      borderRadius: 4,
      fontSize: 11,
      color: "#c5c7d4",
    },
    cursor: { stroke: "rgba(255,255,255,0.06)", strokeWidth: 20 },
  };

  if (!hasData || data.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-44 gap-2" style={{ color: "#4d5060" }}>
        <TrendingUpIcon className="w-8 h-8 opacity-15" style={{ color: "var(--splunk-muted)" }} />
        <p className="text-xs">Threat timeline will appear after telemetry upload</p>
      </div>
    );
  }

  const peakHour = data.reduce((max, d) => d.threats > max.threats ? d : max, data[0]);

  return (
    <div>
      <div className="flex items-center justify-between mb-3 px-1">
        <span className="text-[10px] font-mono tabular-nums" style={{ color: "#6b6e80" }}>
          Peak activity at{" "}
          <span className="font-semibold" style={{ color: "#e84d4d" }}>{peakHour.time}</span>
          {" "}·{" "}
          <span className="font-semibold" style={{ color: "#c5c7d4" }}>{peakHour.threats.toLocaleString()}</span>
          {" "}threat events
        </span>
        <span className="text-[9px] uppercase tracking-wider font-semibold" style={{ color: "#4e9af1" }}>
          24h Window
        </span>
      </div>
      <ResponsiveContainer width="100%" height={160}>
        <AreaChart data={data} margin={{ left: 0, right: 8, top: 4, bottom: 0 }}>
          <defs>
            <linearGradient id="grad-threats" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor="#e84d4d" stopOpacity={0.35} />
              <stop offset="95%" stopColor="#e84d4d" stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id="grad-critical" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor="#f4a926" stopOpacity={0.5} />
              <stop offset="95%" stopColor="#f4a926" stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id="grad-benign" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor="#4e9af1" stopOpacity={0.18} />
              <stop offset="95%" stopColor="#4e9af1" stopOpacity={0.01} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="#2e3038" strokeDasharray="3 3" vertical={false} />
          <XAxis
            dataKey="time"
            tick={{ fontSize: 9, fill: "#4d5060", fontFamily: "JetBrains Mono, monospace" }}
            tickLine={false}
            axisLine={false}
            interval={3}
          />
          <YAxis hide />
          <Tooltip
            {...tooltip}
            formatter={(value: number, name: string) => [
              value.toLocaleString(),
              name === "threats" ? "Threats" : name === "critical" ? "Critical" : "Benign",
            ]}
          />
          <Area type="monotone" dataKey="benign"   stroke="#4e9af1" strokeWidth={1}   fill="url(#grad-benign)"   strokeOpacity={0.5} dot={false} />
          <Area type="monotone" dataKey="threats"  stroke="#e84d4d" strokeWidth={1.5} fill="url(#grad-threats)"  dot={false} />
          <Area type="monotone" dataKey="critical" stroke="#f4a926" strokeWidth={1.5} fill="url(#grad-critical)" dot={false} />
        </AreaChart>
      </ResponsiveContainer>
      {/* Legend */}
      <div className="flex items-center gap-4 mt-1 px-1">
        {[
          { color: "#e84d4d", label: "Threats" },
          { color: "#f4a926", label: "Critical" },
          { color: "#4e9af1", label: "Benign" },
        ].map(({ color, label }) => (
          <span key={label} className="flex items-center gap-1 text-[9px]" style={{ color: "#6b6e80" }}>
            <span className="w-2.5 h-px" style={{ background: color, display: "inline-block" }} />
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}

// ── Purple Team Metrics strip ─────────────────────────────────────────────────

function PurpleTeamMetrics({ metrics }: { metrics?: any }) {
  const mttd = metrics?.mttd ?? "0s";
  const mttr = metrics?.mttr ?? "0s";
  const efficacy = metrics?.efficacy ?? "0%";
  const coverage = metrics?.coverage ?? "0%";
  const fpRate = metrics?.fp_rate ?? "0%";
  const autoResponse = metrics?.auto_response ?? "0%";

  const data = [
    { label: "MTTD",                value: mttd,        sub: "Mean Time to Detect",      color: "#72c811" },
    { label: "MTTR",                value: mttr,        sub: "Mean Time to Respond",     color: "#4e9af1" },
    { label: "Detection Efficacy",  value: efficacy,    sub: "True positive rate",        color: "#d946ef" },
    { label: "Purple Team Coverage",value: coverage,    sub: "ATT&CK techniques covered", color: "#00d4c8" },
    { label: "False Positive Rate", value: fpRate,      sub: "Analyst noise reduction",   color: "#f4a926" },
    { label: "Automated Response",  value: autoResponse,sub: "SOAR playbook coverage",    color: "#8b5cf6" },
  ];
  return (
    <div className="grid grid-cols-6 gap-2 px-3 pb-0 pt-0">
      {data.map(m => (
        <div
          key={m.label}
          className="rounded-lg px-3 py-2.5"
          style={{ background: "#0d0d10", border: "1px solid #1a1a1f" }}
        >
          <p className="text-[9px] font-semibold uppercase tracking-widest" style={{ color: "#4d5060" }}>{m.label}</p>
          <p className="text-lg font-bold mt-0.5 font-mono leading-none" style={{ color: m.color }}>{m.value}</p>
          <p className="text-[8px] mt-1" style={{ color: "#3d3f4a" }}>{m.sub}</p>
        </div>
      ))}
    </div>
  );
}

// ── Financial ROI chart ───────────────────────────────────────────────────────

function FinancialRoiChart({ roiData }: { roiData?: any[] }) {
  const hasData = roiData && roiData.length > 0 && roiData.some(d => (d.avoided ?? 0) + (d.cost ?? 0) + (d.incidents ?? 0) > 0);

  if (!hasData) {
    return (
      <div className="flex flex-col items-center justify-center h-44 gap-2" style={{ color: "#4d5060" }}>
        <TrendingUpIcon className="w-8 h-8 opacity-15" style={{ color: "var(--splunk-muted)" }} />
        <p className="text-xs">ROI model populates after telemetry upload</p>
      </div>
    );
  }

  const data         = roiData!;
  const totalAvoided = data.reduce((s, d) => s + (d.avoided ?? 0), 0);
  const totalCost    = data.reduce((s, d) => s + (d.cost    ?? 0), 0);
  const roiPct       = totalCost > 0 ? Math.round((totalAvoided - totalCost) / totalCost * 100) : 0;
  const avoidedFmt   = totalAvoided >= 1000
    ? `$${(totalAvoided / 1000).toFixed(1)}M`
    : `$${totalAvoided.toFixed(0)}K`;

  const tooltipStyle = {
    contentStyle: { background: "#1e1f23", border: "1px solid #2e3038", borderRadius: 4, fontSize: 11, color: "#c5c7d4" },
    cursor: { fill: "rgba(255,255,255,0.025)" },
  };
  return (
    <div>
      <div className="flex items-center justify-between mb-2 px-1">
        <span className="text-[10px] font-mono tabular-nums" style={{ color: "#6b6e80" }}>
          Cumulative avoided:{" "}
          <span className="font-semibold" style={{ color: "#72c811" }}>{avoidedFmt}</span>
        </span>
        <span className="text-[9px] uppercase tracking-wider font-semibold" style={{ color: "#72c811" }}>
          {totalCost > 0 ? `ROI ${roiPct.toLocaleString()}%` : "Active"}
        </span>
      </div>
      <ResponsiveContainer width="100%" height={148}>
        <ComposedChart data={data} margin={{ left: -10, right: 4, top: 4, bottom: 0 }}>
          <CartesianGrid stroke="#1e2028" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="month" tick={{ fontSize: 8, fill: "#4d5060", fontFamily: "JetBrains Mono, monospace" }} tickLine={false} axisLine={false} />
          <YAxis yAxisId="left" hide />
          <YAxis yAxisId="right" orientation="right" hide />
          <Tooltip
            {...tooltipStyle}
            formatter={(value: number, name: string) => [
              name === "incidents" ? value : `$${value.toLocaleString()}K`,
              name === "avoided" ? "Cost Avoided" : name === "cost" ? "SOC Cost" : "Incidents",
            ]}
          />
          <Bar yAxisId="left" dataKey="avoided" fill="rgba(114,200,17,0.18)" stroke="#72c811" strokeWidth={1} radius={[2, 2, 0, 0]} maxBarSize={16} />
          <Bar yAxisId="left" dataKey="cost"    fill="rgba(78,154,241,0.12)" stroke="#4e9af1" strokeWidth={1} radius={[2, 2, 0, 0]} maxBarSize={16} />
          <Line yAxisId="right" type="monotone" dataKey="incidents" stroke="#f4a926" strokeWidth={1.5} dot={false} />
        </ComposedChart>
      </ResponsiveContainer>
      <div className="flex items-center gap-4 mt-1 px-1">
        {[
          { color: "#72c811", label: "Cost Avoided ($K)" },
          { color: "#4e9af1", label: "SOC Cost ($K)" },
          { color: "#f4a926", label: "Incidents" },
        ].map(({ color, label }) => (
          <span key={label} className="flex items-center gap-1 text-[9px]" style={{ color: "#6b6e80" }}>
            <span className="w-2.5 h-px" style={{ background: color, display: "inline-block" }} />
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}

// ── Port / Protocol distribution PieChart ────────────────────────────────────

function PortProtocolChart({ protocols }: { protocols?: any[] }) {
  const hasData = protocols && protocols.length > 0 && protocols.some(p => (p.value ?? 0) > 0);

  if (!hasData) {
    return (
      <div className="flex flex-col items-center justify-center h-32 gap-2" style={{ color: "#4d5060" }}>
        <BarChart2Icon className="w-8 h-8 opacity-15" style={{ color: "var(--splunk-muted)" }} />
        <p className="text-xs">Protocol distribution populates after telemetry upload</p>
      </div>
    );
  }

  const data = protocols!;
  return (
    <div>
      <div className="flex items-center justify-between mb-1 px-1">
        <span className="text-[10px] font-mono" style={{ color: "#6b6e80" }}>
          Top targeted ports · last 24h
        </span>
      </div>
      <ResponsiveContainer width="100%" height={120}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={32}
            outerRadius={54}
            paddingAngle={2}
            dataKey="value"
            strokeWidth={0}
          >
            {data.map((entry, i) => (
              <Cell key={i} fill={entry.color} opacity={0.82} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ background: "#1e1f23", border: "1px solid #2e3038", borderRadius: 4, fontSize: 11, color: "#c5c7d4" }}
            formatter={(value: number, name: string) => [`${value}%`, name]}
          />
          <Legend
            iconType="square"
            iconSize={6}
            formatter={(value) => <span style={{ color: "#6b6e80", fontSize: 9 }}>{value}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── MITRE ATT&CK Tactic breakdown ─────────────────────────────────────────────

function MitreTacticChart({ tactics }: { tactics?: any[] }) {
  const hasData = tactics && tactics.length > 0 && tactics.some(d => (d.count ?? 0) > 0);

  if (!hasData) {
    return (
      <div className="flex flex-col items-center justify-center h-44 gap-2" style={{ color: "#4d5060" }}>
        <Shield className="w-8 h-8 opacity-15" style={{ color: "var(--splunk-muted)" }} />
        <p className="text-xs">ATT&CK tactic breakdown populates after telemetry upload</p>
      </div>
    );
  }

  const data = tactics!;
  const max = Math.max(1, ...data.map(d => d.count));
  return (
    <div className="space-y-1.5 pt-1">
      {data.map(d => (
        <div key={d.tactic} className="flex items-center gap-2">
          <span className="text-[9px] font-mono w-28 shrink-0 text-right truncate" style={{ color: "#6b6e80" }}>
            {d.tactic}
          </span>
          <div className="flex-1 h-3 rounded-sm overflow-hidden" style={{ background: "#0d0d10" }}>
            <div
              className="h-full rounded-sm"
              style={{
                width: `${(d.count / max) * 100}%`,
                background: d.color,
                opacity: 0.75,
                boxShadow: `0 0 6px ${d.color}44`,
              }}
            />
          </div>
          <span className="text-[9px] font-mono tabular-nums w-5 shrink-0 text-right" style={{ color: d.color }}>
            {d.count}
          </span>
        </div>
      ))}
    </div>
  );
}

// ── Playbook editor constants ─────────────────────────────────────────────────

const PLAYBOOK_NAMES: Record<string, string> = {
  Block_IP_Playbook:       "Block IP",
  Isolate_Host_Playbook:   "Isolate Host",
  C2_Containment_Playbook: "C2 Containment",
  Rate_Limit_Playbook:     "Rate Limit",
  Lock_Account_Playbook:   "Lock Account",
};

const ACTION_OPTIONS: { id: string; label: string; sublabel: string }[] = [
  { id: "pan",      label: "Block IP on Palo Alto Firewall",    sublabel: "PAN-OS API commit + push" },
  { id: "cs",       label: "Isolate Endpoint via CrowdStrike",  sublabel: "RTR containment command" },
  { id: "slack",    label: "Send Slack Alert to SOC Team",      sublabel: "Webhook to #soc-alerts" },
  { id: "bgp",      label: "Null-Route via BGP",                sublabel: "RTBHv4 community 65535:666" },
];

// ── Playbook editor modal (per-execution — keyed by entry.id) ─────────────────

function PlaybookEditorModal({
  entry, currentOverride, onSave, onClose,
}: {
  entry:           CicidsPlaybookLog;
  currentOverride: ActionOverride | undefined;
  onSave:          (override: ActionOverride) => void;
  onClose:         () => void;
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

function PlaybooksPage({ soarEntries }: { soarEntries: CicidsPlaybookLog[] }) {
  const qc = useQueryClient();
  const [editingEntry,    setEditingEntry]   = useState<CicidsPlaybookLog | null>(null);
  const [actionOverrides, setActionOverrides] = useState<Record<number, ActionOverride>>({});

  const { data: persisted = [] } = useQuery({
    queryKey:        ["cicids-playbook-logs"],
    queryFn:         () => api.getCicidsPlaybookLogs(50),
    refetchInterval: 30_000,
  });

  const { data: aiPlaybookLog = [] } = useQuery({
    queryKey:        ["ai-playbook-log"],
    queryFn:         () => api.getPlaybookLog(50),
    refetchInterval: 30_000,
  });

  const seen = new Set<number>();
  const merged: CicidsPlaybookLog[] = [];
  for (const e of [...soarEntries, ...persisted]) {
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


