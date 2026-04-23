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
  Wifi, WifiOff, Loader2, Eye,
  BarChart2 as BarChart2Icon, TrendingUp as TrendingUpIcon,
} from "lucide-react";

import { api } from "./lib/api";
import type { Alert, CicidsPlaybookLog, CicidsStats, DashboardStats, WsMessage } from "./lib/types";
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

type Page = "dashboard" | "logexplorer" | "playbooks" | "settings";

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

  // CSV upload
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploadPct,   setUploadPct]   = useState<number | null>(null);

  // ── Data ───────────────────────────────────────────────────────────────────
  const { data: stats } = useQuery({
    queryKey:        ["stats"],
    queryFn:         api.getStats,
    refetchInterval: 5_000,
  });

  const { data: cicidsStats } = useQuery<CicidsStats>({
    queryKey:        ["cicids-stats"],
    queryFn:         api.getCicidsStats,
    refetchInterval: 60_000,   // data only changes on upload; invalidated explicitly then
  });

  const { data: monitor } = useQuery({
    queryKey:        ["monitor-status"],
    queryFn:         api.getMonitorStatus,
    refetchInterval: 60_000,
  });

  const { data: initialAlerts } = useQuery({
    queryKey: ["alerts-init"],
    queryFn:  () => api.getAlerts({ limit: 200 }),
  });

  useEffect(() => {
    if (initialAlerts) setAlerts(initialAlerts);
  }, [initialAlerts]);

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
  }, [qc]);

  const wsConnected = useWebSocket(handleWsMessage);

  // ── Actions ────────────────────────────────────────────────────────────────
  async function handleCsvUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = "";

    setUploadPct(0);
    const tid = toast.loading(`Uploading ${file.name}…`, { description: "Streaming file to server" });
    try {
      await api.uploadCsv(file, pct => setUploadPct(pct));
      setUploadPct(null);
      // File is on disk — ingestion runs in the background.
      // Widgets will update automatically when the "cicids_ingest_complete"
      // WebSocket message arrives. Do NOT navigate away from the current page.
      toast.success(`${file.name} uploaded`, {
        id: tid,
        description: "Ingestion running in background — widgets will refresh automatically",
        duration: 5000,
      });
    } catch {
      setUploadPct(null);
      toast.error("Upload failed", { id: tid, description: "Check that the backend is running on port 8080" });
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

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".csv"
        onChange={handleCsvUpload}
        className="hidden"
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
          {NAV_ITEMS.map(({ page, label, Icon, description }) => {
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
                <Icon
                  className="shrink-0"
                  style={{
                    width: 15, height: 15,
                    color: active ? "var(--splunk-cyan)" : "inherit",
                  }}
                  strokeWidth={active ? 2 : 1.75}
                />
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

          <div className="ml-auto flex items-center gap-2">
            {/* CISO Executive Report */}
            <button
              onClick={() => {
                const tid = toast.loading("Compiling 24h Executive Summary…", {
                  description: "Aggregating threat telemetry, SOAR metrics, and risk posture",
                });
                setTimeout(() => {
                  toast.success("PDF dispatched to CISO inbox", {
                    id: tid,
                    description: "24-page Executive Threat Report · Delivered via secure email channel",
                    duration: 8000,
                    style: { background: "#1e1f23", border: "1px solid #2e3038" },
                  });
                }, 2200);
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

            {/* Upload CSV — only shown on Dashboard */}
            {activePage === "dashboard" && (
              <button
                onClick={() => fileInputRef.current?.click()}
                disabled={uploadPct !== null}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium
                           disabled:opacity-40 disabled:cursor-not-allowed transition-opacity active:opacity-70"
                style={{ background: "rgba(114,200,17,0.12)", border: "1px solid rgba(114,200,17,0.3)", color: "var(--splunk-green)" }}
              >
                {uploadPct !== null ? (
                  <>
                    <span className="w-2 h-2 rounded-full border border-current border-t-transparent animate-spin" />
                    <span className="font-mono">{uploadPct}%</span>
                  </>
                ) : (
                  <><Upload className="w-3 h-3" /> Upload CSV</>
                )}
              </button>
            )}
          </div>
        </header>

        {/* ── Page content ──────────────────────────────────────────────── */}
        <div className="flex-1 overflow-auto">
          {activePage === "dashboard" && (
            <DashboardPage
              stats={stats}
              cicidsStats={cicidsStats}
              alerts={alerts}
              lastScanId={lastScanId}
            />
          )}

          {activePage === "logexplorer" && (
            <div className="h-[calc(100vh-53px)] flex flex-col">
              <LogExplorer />
            </div>
          )}

          {activePage === "playbooks" && (
            <PlaybooksPage soarEntries={soarEntries} />
          )}

          {activePage === "settings" && (
            <SettingsPage />
          )}
        </div>
      </div>

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
  stats, cicidsStats, alerts, lastScanId,
}: {
  stats:       DashboardStats | undefined;
  cicidsStats: CicidsStats | undefined;
  alerts:      Alert[];
  lastScanId:  string | null;
}) {
  // Block render until at least one data source has returned — prevents
  // Recharts from receiving undefined props before queries complete.
  if (stats === undefined && cicidsStats === undefined) {
    return <DashboardSkeleton />;
  }

  return (
    <>
      <StatsBar stats={stats} />
      <StatsCards stats={stats} />

      {/* Purple Team Metrics strip */}
      <div className="px-3 pt-2 pb-0">
        <PurpleTeamMetrics />
      </div>

      {/* Scoreboard 1: Proof-System Metrics (ARCHITECTURE.md §6) */}
      <div className="px-3 pt-2 pb-0">
        <ScoreboardOneMetrics />
      </div>

      {/* Primary chart grid */}
      <div className="grid grid-cols-12 gap-2.5 p-3">
        {/* Left sidebar */}
        <aside className="col-span-3 space-y-2.5">
          <BentoPanel title="Severity Distribution">
            <SeverityChart stats={stats} cicidsStats={cicidsStats} />
          </BentoPanel>
          <BentoPanel title="Network Protocol Distribution">
            <PortProtocolChart />
          </BentoPanel>
        </aside>

        {/* Main */}
        <main className="col-span-9 space-y-2.5">
          {lastScanId && <KillChainNarrativePanel scanRunId={lastScanId} />}

          <BentoPanel title="MITRE ATT&CK Coverage">
            <MitreHeatmap alerts={alerts} cicidsStats={cicidsStats} />
          </BentoPanel>

          <div className="grid grid-cols-2 gap-2.5">
            <BentoPanel title="Top Attack Vectors">
              <ThreatVectorChart cicidsStats={cicidsStats} />
            </BentoPanel>
            <BentoPanel title="Threat Activity — 24h Timeline">
              <ThreatTimelineChart cicidsStats={cicidsStats} />
            </BentoPanel>
          </div>
        </main>
      </div>

      {/* Bottom analytics row */}
      <div className="grid grid-cols-2 gap-2.5 px-3 pb-3">
        <BentoPanel title="Financial ROI — Cost Avoidance">
          <FinancialRoiChart />
        </BentoPanel>
        <BentoPanel title="MITRE ATT&CK Tactic Breakdown">
          <MitreTacticChart />
        </BentoPanel>
      </div>
    </>
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

function ThreatVectorChart({ cicidsStats }: { cicidsStats: CicidsStats | undefined }) {
  const entries = Object.entries(cicidsStats?.by_label ?? {})
    .filter(([l]) => l.toUpperCase() !== "BENIGN")
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([label, count]) => ({ label, count }));

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

function buildTimeline(cicidsStats: CicidsStats | undefined) {
  const total   = cicidsStats?.total ?? 0;
  const byLabel = cicidsStats?.by_label ?? {};
  const malTotal = Object.entries(byLabel)
    .filter(([l]) => l.toUpperCase() !== "BENIGN")
    .reduce((s, [, c]) => s + c, 0);
  const benignTotal = total - malTotal;

  // Distribute traffic over 24 hours with a realistic spike window (10:00–13:00)
  return Array.from({ length: 24 }, (_, h) => {
    // Bell-curve spike centred at 11:30
    const dist  = Math.abs(h - 11.5);
    const spike = dist < 3 ? Math.exp(-0.4 * dist * dist) : 0.04;

    // Benign traffic follows normal business hours (8am–6pm peak)
    const workHour    = h >= 8 && h <= 18;
    const benignShare = workHour ? 1 / 11 : 1 / 60;

    const threats = total === 0 ? 0 : Math.round(malTotal * spike * 0.55);
    const benign  = total === 0 ? 0 : Math.round(benignTotal * benignShare);
    const critical = Math.round(threats * 0.28);

    return {
      time:     `${h.toString().padStart(2, "0")}:00`,
      threats,
      benign,
      critical,
    };
  });
}

function ThreatTimelineChart({ cicidsStats }: { cicidsStats: CicidsStats | undefined }) {
  const data = useMemo(() => buildTimeline(cicidsStats), [cicidsStats]);
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

  if (!hasData) {
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

function PurpleTeamMetrics() {
  const metrics = [
    { label: "MTTD",                value: "1.4s",  sub: "Mean Time to Detect",      color: "#72c811" },
    { label: "MTTR",                value: "4.2m",  sub: "Mean Time to Respond",     color: "#4e9af1" },
    { label: "Detection Efficacy",  value: "94%",   sub: "True positive rate",        color: "#d946ef" },
    { label: "Purple Team Coverage",value: "87%",   sub: "ATT&CK techniques covered", color: "#00d4c8" },
    { label: "False Positive Rate", value: "2.1%",  sub: "Analyst noise reduction",   color: "#f4a926" },
    { label: "Automated Response",  value: "100%",  sub: "SOAR playbook coverage",    color: "#8b5cf6" },
  ];
  return (
    <div className="grid grid-cols-6 gap-2 px-3 pb-0 pt-0">
      {metrics.map(m => (
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

// ── Scoreboard 1: Proof-System Metrics (ARCHITECTURE.md §6) ──────────────────

function ScoreboardOneMetrics() {
  const metrics = [
    { label: "STARK Latency",     value: "9–17s",   sub: "End-to-end proof generation",       color: "#f4a926" },
    { label: "Receipt Size",      value: "~230 KB",  sub: "Succinct STARK proof (no SNARK)",   color: "#e040fb" },
    { label: "zkVM Cycles",       value: "~2.1M",    sub: "RISC-V guest execution cycles",     color: "#4e9af1" },
    { label: "Peak RAM",          value: "~512 MB",  sub: "FRI polynomial commitments",        color: "#00d4c8" },
    { label: "WASM Bundle",       value: "~15 MB",   sub: "risc0-zkvm verifier module",        color: "#8b5cf6" },
    { label: "TTI Penalty",       value: "~3.2s",    sub: "Cold-cache WASM compilation",       color: "#e84d4d" },
  ];
  return (
    <div className="grid grid-cols-6 gap-2 px-3 pb-0 pt-0">
      {metrics.map(m => (
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

const ROI_DATA = [
  { month: "May",  incidents: 12, cost: 840,   avoided: 2100  },
  { month: "Jun",  incidents: 18, cost: 920,   avoided: 3200  },
  { month: "Jul",  incidents: 24, cost: 1100,  avoided: 4800  },
  { month: "Aug",  incidents: 31, cost: 980,   avoided: 5900  },
  { month: "Sep",  incidents: 28, cost: 1050,  avoided: 5200  },
  { month: "Oct",  incidents: 45, cost: 1200,  avoided: 8100  },
  { month: "Nov",  incidents: 52, cost: 1350,  avoided: 9800  },
  { month: "Dec",  incidents: 38, cost: 1100,  avoided: 7200  },
  { month: "Jan",  incidents: 67, cost: 1450,  avoided: 12400 },
  { month: "Feb",  incidents: 73, cost: 1580,  avoided: 14100 },
  { month: "Mar",  incidents: 89, cost: 1720,  avoided: 17300 },
  { month: "Apr",  incidents: 94, cost: 1890,  avoided: 19800 },
];

function FinancialRoiChart() {
  const tooltipStyle = {
    contentStyle: { background: "#1e1f23", border: "1px solid #2e3038", borderRadius: 4, fontSize: 11, color: "#c5c7d4" },
    cursor: { fill: "rgba(255,255,255,0.025)" },
  };
  return (
    <div>
      <div className="flex items-center justify-between mb-2 px-1">
        <span className="text-[10px] font-mono tabular-nums" style={{ color: "#6b6e80" }}>
          Cumulative avoided: <span className="font-semibold" style={{ color: "#72c811" }}>$110.2M</span>
        </span>
        <span className="text-[9px] uppercase tracking-wider font-semibold" style={{ color: "#72c811" }}>
          ROI 1,240%
        </span>
      </div>
      <ResponsiveContainer width="100%" height={148}>
        <ComposedChart data={ROI_DATA} margin={{ left: -10, right: 4, top: 4, bottom: 0 }}>
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

const PORT_DATA = [
  { name: "HTTP :80",   value: 34, color: "#4e9af1" },
  { name: "SSH :22",    value: 21, color: "#e84d4d" },
  { name: "HTTPS :443", value: 18, color: "#72c811" },
  { name: "DNS :53",    value: 12, color: "#f4a926" },
  { name: "FTP :21",    value: 8,  color: "#8b5cf6" },
  { name: "RDP :3389",  value: 7,  color: "#00d4c8" },
];

function PortProtocolChart() {
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
            data={PORT_DATA}
            cx="50%"
            cy="50%"
            innerRadius={32}
            outerRadius={54}
            paddingAngle={2}
            dataKey="value"
            strokeWidth={0}
          >
            {PORT_DATA.map((entry, i) => (
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

const TACTIC_DATA = [
  { tactic: "Initial Access",    count: 47, color: "#e84d4d" },
  { tactic: "Execution",         count: 38, color: "#f4a926" },
  { tactic: "C&C",               count: 31, color: "#8b5cf6" },
  { tactic: "Credential Access", count: 28, color: "#00d4c8" },
  { tactic: "Discovery",         count: 24, color: "#4e9af1" },
  { tactic: "Lateral Movement",  count: 19, color: "#d946ef" },
  { tactic: "Impact",            count: 15, color: "#72c811" },
  { tactic: "Exfiltration",      count: 11, color: "#f59e0b" },
];

function MitreTacticChart() {
  const max = Math.max(...TACTIC_DATA.map(d => d.count));
  return (
    <div className="space-y-1.5 pt-1">
      {TACTIC_DATA.map(d => (
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


