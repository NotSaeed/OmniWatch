import { useState, useCallback, useMemo, useEffect, useRef, forwardRef } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Shield, Search, FolderOpen, Brain } from "lucide-react";
import { api } from "../lib/api";
import { LOG_ROW_STYLE, SEVERITY_BADGE } from "../lib/utils";
import { IncidentReportModal } from "./IncidentReportModal";
import { AIAnalysisDrawer } from "./AIAnalysisDrawer";
import { CommandPalette } from "./CommandPalette";
import type { CicidsLog, CicidsStats, CtiEnrichment, IrReport, PipelineAlert, Severity } from "../lib/types";

/** Map a pipeline telemetry_alert row to the CicidsLog shape used by the table. */
function pipelineAlertToLog(a: PipelineAlert): CicidsLog {
  return {
    id:            a.id,
    ingested_at:   a.ingested_at,
    src_ip:        a.source_ip,
    dst_ip:        a.dest_ip,
    dst_port:      a.dest_port,
    protocol:      a.protocol,
    label:         a.label,
    severity:      a.severity,
    category:      a.mitre_name ?? a.label,
    flow_duration: null,
    flow_bytes_s:  a.bytes_total ?? null,
    source_file:   a.dataset_type,
  };
}

const SEVERITY_OPTIONS: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const PAGE_SIZE = 100;

// ── Sub-components ────────────────────────────────────────────────────────────

function SeverityPill({ severity }: { severity: string }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide
                      ${SEVERITY_BADGE[severity] ?? SEVERITY_BADGE.INFO}`}>
      {severity}
    </span>
  );
}

function StatsStrip({ stats }: { stats: CicidsStats | undefined }) {
  if (!stats || stats.total === 0) return null;
  const attacks = Object.entries(stats.by_label)
    .filter(([l]) => l.toUpperCase() !== "BENIGN")
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return (
    <div className="flex flex-wrap items-center gap-3 px-4 py-2 border-b border-white/5 text-xs"
         style={{ background: "rgba(2,8,23,0.60)" }}>
      <span className="font-mono font-bold text-slate-200 tabular-nums">
        {stats.total.toLocaleString()}
        <span className="text-slate-600 font-normal ml-1">flows</span>
      </span>
      <div className="w-px h-3.5 bg-slate-800" />
      {Object.entries(stats.by_severity).map(([sev, cnt]) => (
        <span key={sev} className={`font-mono tabular-nums ${
          sev === "CRITICAL" ? "text-red-400"
          : sev === "HIGH"   ? "text-orange-400"
          : sev === "MEDIUM" ? "text-yellow-400"
          : "text-slate-500"
        }`}>
          {sev} <span className="font-bold">{(cnt as number).toLocaleString()}</span>
        </span>
      ))}
      {attacks.length > 0 && (
        <>
          <div className="w-px h-3.5 bg-slate-800" />
          <span className="text-slate-600 truncate">
            Top: {attacks.map(([l, c]) => `${l} (${(c as number).toLocaleString()})`).join(" · ")}
          </span>
        </>
      )}
    </div>
  );
}

function IrReportPanel({ report, onClose }: { report: IrReport; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto py-8"
         style={{ background: "rgba(0,0,0,0.75)", backdropFilter: "blur(8px)" }}>
      <div className="w-full max-w-3xl mx-4 rounded-xl border border-slate-700/50 shadow-2xl anim-fade-up overflow-hidden"
           style={{ background: "rgba(10,16,30,0.96)", backdropFilter: "blur(16px)" }}>
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800/60"
             style={{ background: "rgba(2,8,23,0.80)" }}>
          <div>
            <div className="flex items-center gap-2 mb-0.5">
              <span className="w-1 h-4 rounded-full bg-violet-500" />
              <h2 className="text-sm font-semibold text-slate-100">Incident Response Report</h2>
            </div>
            <p className="text-xs text-slate-500 font-mono ml-3">
              {report.source_file} · {report.total_events_analyzed.toLocaleString()} events analyzed
            </p>
          </div>
          <button
            onClick={onClose}
            className="w-7 h-7 flex items-center justify-center rounded-lg text-slate-500 hover:text-slate-200
                       bg-slate-800/60 hover:bg-slate-700/60 border border-slate-700/50 active:scale-95 transition-all text-sm"
          >
            ✕
          </button>
        </div>

        <div className="p-6 space-y-5">
          <Section title="Executive Summary">
            <p className="text-sm text-slate-300 leading-relaxed">{report.executive_summary}</p>
          </Section>

          <Section title="Severity Assessment">
            <p className="text-sm text-orange-300 leading-relaxed">{report.severity_assessment}</p>
          </Section>

          {report.attack_details.length > 0 && (
            <Section title="Attack Details">
              <div className="space-y-3">
                {report.attack_details.map((a, i) => (
                  <div key={i} className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-sm font-semibold text-red-400">{a.attack_type}</span>
                      <span className="text-xs text-slate-600 font-mono">{a.count.toLocaleString()} flows</span>
                    </div>
                    <p className="text-xs text-slate-400 mb-3">{a.description}</p>
                    {a.mitre_techniques.length > 0 && (
                      <div className="flex flex-wrap gap-1 mb-3">
                        {a.mitre_techniques.map(t => (
                          <span key={t} className="px-1.5 py-0.5 rounded-md bg-violet-950/60 text-violet-300 text-[10px] font-mono border border-violet-800/40">
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                    <ul className="space-y-1">
                      {a.mitigation_steps.map((step, j) => (
                        <li key={j} className="text-xs text-slate-400 flex gap-2">
                          <span className="text-emerald-600 shrink-0">→</span>{step}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </Section>
          )}

          <Section title="Immediate Actions">
            <ol className="space-y-1">
              {report.immediate_actions.map((a, i) => (
                <li key={i} className="text-xs text-slate-300 flex gap-2">
                  <span className="text-red-500 shrink-0 font-mono font-bold tabular-nums">{i + 1}.</span>{a}
                </li>
              ))}
            </ol>
          </Section>

          <Section title="Long-Term Recommendations">
            <ul className="space-y-1">
              {report.long_term_recommendations.map((r, i) => (
                <li key={i} className="text-xs text-slate-400 flex gap-2">
                  <span className="text-cyan-600 shrink-0">◆</span>{r}
                </li>
              ))}
            </ul>
          </Section>

          {report.affected_systems.length > 0 && (
            <Section title="Affected Systems">
              <div className="flex flex-wrap gap-1.5">
                {report.affected_systems.map((s, i) => (
                  <span key={i} className="px-2 py-0.5 rounded-md bg-slate-800/70 text-slate-300 text-xs font-mono border border-slate-700/50">
                    {s}
                  </span>
                ))}
              </div>
            </Section>
          )}

          <p className="text-[10px] text-slate-700 text-right font-mono">
            Report ID: {report.report_id} · {new Date(report.generated_at).toLocaleString()}
          </p>
        </div>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <div className="flex items-center gap-2 mb-2">
        <span className="w-px h-3.5 bg-cyan-500/50" />
        <h3 className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold">{title}</h3>
      </div>
      {children}
    </section>
  );
}

// ── Facet input + chip ────────────────────────────────────────────────────────

const FacetInput = forwardRef<HTMLInputElement, {
  placeholder: string; value: string;
  onChange: (v: string) => void; onEnter: () => void;
  width?: number; monospace?: boolean;
}>(({ placeholder, value, onChange, onEnter, width = 110, monospace }, ref) => (
  <div
    className="flex items-center gap-1.5 rounded px-2.5 py-1.5 focus-within:ring-1 focus-within:ring-cyan-700/40 transition-all shrink-0"
    style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.07)", width }}
  >
    <input
      ref={ref}
      type="text"
      value={value}
      onChange={e => onChange(e.target.value)}
      onKeyDown={e => e.key === "Enter" && onEnter()}
      placeholder={placeholder}
      className={`w-full bg-transparent text-xs placeholder-slate-600 focus:outline-none ${monospace ? "font-mono text-cyan-300" : "text-slate-200"}`}
    />
    {value && (
      <button onClick={() => onChange("")} className="text-slate-600 hover:text-slate-400 shrink-0 text-[10px]">×</button>
    )}
  </div>
));
FacetInput.displayName = "FacetInput";

function Chip({ label, onRemove }: { label: string; onRemove: () => void }) {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-mono"
          style={{ background: "rgba(6,182,212,0.12)", border: "1px solid rgba(6,182,212,0.25)", color: "#67e8f9" }}>
      {label}
      <button onClick={onRemove} className="opacity-60 hover:opacity-100 ml-0.5">×</button>
    </span>
  );
}

// ── Deep-link filter bag ──────────────────────────────────────────────────────

export interface LogFilters {
  source_ip?:     string;
  dest_ip?:       string;
  dest_port?:     string;
  mitre?:         string;
  severity?:      string;
  label?:         string;
  global_search?: string;
}

// ── Main component ────────────────────────────────────────────────────────────

interface LogExplorerProps {
  /** When set, switches the data source to telemetry_alerts for this session. */
  sessionId?: string | null;
  /** Called when the analyst clicks "Review & Sign" on a pipeline alert. */
  onReviewSign?: (alert: PipelineAlert) => void;
  /** Pre-fill filters and trigger search — used for cross-panel deep linking. */
  initialFilters?: LogFilters | null;
}

export function LogExplorer({ sessionId, onReviewSign, initialFilters }: LogExplorerProps) {
  const qc = useQueryClient();

  // Pipeline-mode faceted filters (server-side, field-specific)
  const [sourceIp,  setSourceIp]  = useState("");
  const [destIp,    setDestIp]    = useState("");
  const [destPort,  setDestPort]  = useState("");
  const [mitre,     setMitre]     = useState("");
  const [severity,  setSeverity]  = useState<Severity | "">("");
  // Legacy-mode unified search + label
  const [globalSearch, setGlobalSearch] = useState("");
  const [label,     setLabel]     = useState("");

  const [offset,       setOffset]       = useState(0);
  const [irReport,     setIrReport]     = useState<IrReport | null>(null);
  const [generating,   setGenerating]   = useState(false);
  const [aiDrawerOpen, setAiDrawerOpen] = useState(false);
  const [expandedId,   setExpandedId]   = useState<number | null>(null);
  const [focusedIdx,   setFocusedIdx]   = useState<number>(-1);
  const [paletteOpen,  setPaletteOpen]  = useState(false);

  const searchInputRef = useRef<HTMLInputElement>(null);

  const [analyzingLog,   setAnalyzingLog]   = useState<CicidsLog | null>(null);
  const [incidentReport, setIncidentReport] = useState<string | null>(null);
  const [ctiData,        setCtiData]        = useState<CtiEnrichment | null>(null);
  const [aiGenerated,    setAiGenerated]    = useState<boolean>(true);

  // Committed (active) filter values — only update on Apply
  const [activeSourceIp,  setActiveSourceIp]  = useState("");
  const [activeDestIp,    setActiveDestIp]    = useState("");
  const [activeDestPort,  setActiveDestPort]  = useState("");
  const [activeMitre,     setActiveMitre]     = useState("");
  const [activeSeverity,  setActiveSeverity]  = useState<Severity | "">("");
  const [activeGlobalSearch, setActiveGlobalSearch] = useState("");
  const [activeLabel,     setActiveLabel]     = useState("");

  // Track which initialFilters object we've already applied to avoid re-applying on re-renders
  const appliedFiltersRef = useRef<LogFilters | null>(null);

  // Apply deep-link filters whenever a new initialFilters object arrives
  useEffect(() => {
    if (!initialFilters || appliedFiltersRef.current === initialFilters) return;
    appliedFiltersRef.current = initialFilters;
    const f = initialFilters;
    
    // Set to new value or reset to empty if undefined
    setSourceIp(f.source_ip ?? ""); setActiveSourceIp(f.source_ip ?? "");
    setDestIp(f.dest_ip ?? ""); setActiveDestIp(f.dest_ip ?? "");
    setDestPort(f.dest_port ?? ""); setActiveDestPort(f.dest_port ?? "");
    setMitre(f.mitre ?? ""); setActiveMitre(f.mitre ?? "");
    setSeverity((f.severity as Severity) ?? ""); setActiveSeverity((f.severity as Severity) ?? "");
    setLabel(f.label ?? ""); setActiveLabel(f.label ?? "");
    setGlobalSearch(f.global_search ?? ""); setActiveGlobalSearch(f.global_search ?? "");
    
    setOffset(0);
  }, [initialFilters]);

  // Reset filters and page when the active session changes
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    let hasParams = false;

    if (params.has("source_ip")) { setSourceIp(params.get("source_ip")!); setActiveSourceIp(params.get("source_ip")!); hasParams = true; }
    if (params.has("dest_ip"))   { setDestIp(params.get("dest_ip")!);     setActiveDestIp(params.get("dest_ip")!);     hasParams = true; }
    if (params.has("dest_port")) { setDestPort(params.get("dest_port")!); setActiveDestPort(params.get("dest_port")!); hasParams = true; }
    if (params.has("mitre_id"))  { setMitre(params.get("mitre_id")!);     setActiveMitre(params.get("mitre_id")!);     hasParams = true; }
    else if (params.has("mitre")){ setMitre(params.get("mitre")!);        setActiveMitre(params.get("mitre")!);        hasParams = true; }
    if (params.has("severity"))  { setSeverity(params.get("severity")! as Severity); setActiveSeverity(params.get("severity")! as Severity); hasParams = true; }
    if (params.has("global_search")){ setGlobalSearch(params.get("global_search")!); setActiveGlobalSearch(params.get("global_search")!); hasParams = true; }
    else if (params.has("search")){ setGlobalSearch(params.get("search")!); setActiveGlobalSearch(params.get("search")!); hasParams = true; }

    if (hasParams) {
      setOffset(0);
    }
  }, []);

  const prevSessionIdRef = useRef<string | null | undefined>(undefined);

  // Reset filters and page when the active session changes
  useEffect(() => {
    if (prevSessionIdRef.current === undefined) {
      prevSessionIdRef.current = sessionId;
      return;
    }
    if (prevSessionIdRef.current === sessionId) {
      return;
    }
    prevSessionIdRef.current = sessionId;

    setOffset(0);
    setSourceIp(""); setDestIp(""); setDestPort(""); setMitre("");
    setSeverity(""); setGlobalSearch(""); setLabel("");
    setActiveSourceIp(""); setActiveDestIp(""); setActiveDestPort(""); setActiveMitre("");
    setActiveSeverity(""); setActiveGlobalSearch(""); setActiveLabel("");
    setAiDrawerOpen(false);
    setFocusedIdx(-1);
    appliedFiltersRef.current = null; // allow next initialFilters to re-apply
    // Eagerly invalidate so the new session data is fetched immediately
    if (sessionId) {
      qc.invalidateQueries({ queryKey: ["logs", sessionId] });
    }
  }, [sessionId, qc]);

  // ── Stats query — session-scoped when a pipeline session is active ──────────
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey:        ["cicids-stats", sessionId ?? "legacy"],
    queryFn:         () => api.getCicidsStats(sessionId),
    refetchInterval: 30_000,
  });

  const { data: actionedIpsRaw = [] } = useQuery({
    queryKey:        ["cicids-actioned-ips"],
    queryFn:         api.getActionedIps,
    refetchInterval: 30_000,
  });
  const actionedIps = useMemo(() => new Set(actionedIpsRaw), [actionedIpsRaw]);

  const { data: botsv3Dashboard } = useQuery({
    queryKey: ["botsv3-dashboard"],
    queryFn: api.getBotsv3Dashboard,
    enabled: !sessionId,
  });

  // ── Pipeline alerts query (active session) ──────────────────────────────────
  const { data: pipelineAlertsResponse, isFetching: pipelineFetching } = useQuery({
    queryKey: ["logs", sessionId, activeSourceIp, activeDestIp, activeDestPort, activeMitre, activeSeverity, activeGlobalSearch, offset],
    queryFn: () => api.getPipelineAlerts({
      session_id: sessionId!,
      source_ip:  activeSourceIp  || undefined,
      dest_ip:    activeDestIp    || undefined,
      dest_port:  activeDestPort  || undefined,
      mitre:      activeMitre     || undefined,
      severity:   activeSeverity  || undefined,
      global_search: activeGlobalSearch || undefined,
      limit:      PAGE_SIZE,
      offset,
    }),
    enabled:         !!sessionId,
    placeholderData: prev => prev,
    staleTime:       30_000,
  });

  const pipelineAlerts = pipelineAlertsResponse?.data ?? [];
  const pipelineFilteredTotal = pipelineAlertsResponse?.total_filtered ?? 0;

  // ── Legacy CIC-IDS / BOTSv3 query ──────────────────────────────────────────
  const isBotsOnly    = !sessionId && (stats?.total === 0 || !stats) && botsv3Dashboard?.has_data;
  const legacyDataset = isBotsOnly ? "botsv3" : "cicids";

  const { data: rawLogs = [], isFetching: legacyFetching } = useQuery({
    queryKey: ["logs", legacyDataset, activeGlobalSearch, activeSeverity, activeLabel, offset],
    queryFn: () => {
      if (legacyDataset === "botsv3") {
        return api.getBotsv3Logs({ search: activeGlobalSearch, limit: PAGE_SIZE, offset });
      }
      return api.getCicidsLogs({
        search: activeGlobalSearch, severity: activeSeverity,
        label: activeLabel, limit: PAGE_SIZE, offset,
      });
    },
    enabled:         !sessionId,
    placeholderData: prev => prev,
  });

  const isFetching = sessionId ? pipelineFetching : legacyFetching;
  const logs: CicidsLog[] = sessionId
    ? pipelineAlerts.map(pipelineAlertToLog)
    : (rawLogs as CicidsLog[]);

  const runSearch = useCallback(() => {
    setActiveSourceIp(sourceIp);
    setActiveDestIp(destIp);
    setActiveDestPort(destPort);
    setActiveMitre(mitre);
    setActiveSeverity(severity);
    setActiveGlobalSearch(globalSearch);
    setActiveLabel(label);
    setOffset(0);
  }, [sourceIp, destIp, destPort, mitre, severity, globalSearch, label]);

  const clearFilters = useCallback(() => {
    setSourceIp(""); setDestIp(""); setDestPort(""); setMitre("");
    setSeverity(""); setGlobalSearch(""); setLabel("");
    setActiveSourceIp(""); setActiveDestIp(""); setActiveDestPort(""); setActiveMitre("");
    setActiveSeverity(""); setActiveGlobalSearch(""); setActiveLabel("");
    setOffset(0);
    appliedFiltersRef.current = null;
  }, []);

  // Keyboard navigation
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      // Don't hijack keys when an input/select is focused
      const tag = (document.activeElement as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA") return;

      const rows = sessionId ? pipelineAlerts : logs;

      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        setFocusedIdx(i => Math.min(i + 1, rows.length - 1));
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        setFocusedIdx(i => Math.max(i - 1, 0));
      } else if (e.key === "Enter" && focusedIdx >= 0) {
        if (sessionId) {
          const row = pipelineAlerts[focusedIdx];
          if (row && onReviewSign) onReviewSign(row as PipelineAlert);
        }
      } else if (e.key === "Escape") {
        setFocusedIdx(-1);
        setPaletteOpen(false);
      } else if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setPaletteOpen(o => !o);
      } else if (e.key === "/" && !e.metaKey && !e.ctrlKey) {
        e.preventDefault();
        searchInputRef.current?.focus();
      } else if (e.key === "r" && !e.metaKey && !e.ctrlKey) {
        if (sessionId) {
          qc.invalidateQueries({ queryKey: ["logs", sessionId] });
        }
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [focusedIdx, sessionId, pipelineAlerts, logs, onReviewSign, qc]);

  async function handleGenerateReport() {
    setGenerating(true);
    try {
      const report = await api.generateIrReport();
      setIrReport(report);
      qc.invalidateQueries({ queryKey: ["cicids-stats"] });
    } catch { /* user can retry */ }
    finally { setGenerating(false); }
  }

  async function handleRowAnalyze(log: CicidsLog) {
    setAnalyzingLog(log);
    setIncidentReport(null);
    setCtiData(null);
    setAiGenerated(true);
    try {
      const { report, ai_generated, cti } = await api.analyzeIncident(log);
      setCtiData(cti ?? null);
      setIncidentReport(report);
      setAiGenerated(ai_generated ?? false);
    } catch {
      setIncidentReport(
        "## Heuristic Analysis Complete\n\n" +
        "Automated AI narrative generation is currently queued or unavailable. " +
        "Relying on deterministic Tier 1 engine heuristics.\n\n" +
        "**Next Step:** Retry in a moment, or verify Ollama is running in Settings."
      );
      setAiGenerated(false);
    }
  }

  const statsReady  = !statsLoading && stats !== undefined;
  const hasCicids   = statsReady && stats.total > 0;
  const hasBots     = !sessionId && botsv3Dashboard?.has_data;
  const isEmpty     = !sessionId && !hasCicids && !hasBots;

  // In session mode, derive total from pipeline alert count when stats are empty
  const displayTotal = sessionId
    ? (stats?.total ?? pipelineAlerts.length)
    : (stats?.total ?? 0);

  // True when the current session has at least one row with a non-null IP.
  // CIC-IDS-2017 feature-extracted CSVs omit IP columns entirely; in that case
  // the UI shows an explanatory notice instead of blank dashes.
  const hasIpData = useMemo(() =>
    pipelineAlerts.some(a => a.source_ip != null || a.dest_ip != null),
    [pipelineAlerts],
  );

  // Pipeline-mode column headers — full 5-tuple + enrichment
  const pipelineHeaders = ["#", "Timestamp", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Severity", "MITRE", "Act"];
  const legacyHeaders   = ["#", "Severity", "Label / Attack", "Src IP", "Dst IP", "Port", "Proto", "Flow (μs)", "Bytes/s", "File", "Act"];
  const colCount        = sessionId ? pipelineHeaders.length : legacyHeaders.length;

  return (
    <div className="flex flex-col h-full">
      {/* Pipeline session info strip */}
      {sessionId ? (
        <div className="flex flex-wrap items-center gap-3 px-4 py-2 border-b border-white/5 text-xs"
             style={{ background: "rgba(2,8,23,0.60)" }}>
          <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "#4e9af1" }} />
          <span className="font-mono font-bold text-slate-200 tabular-nums">
            {displayTotal > 0 ? displayTotal.toLocaleString() : (isFetching ? "…" : pipelineAlerts.length.toLocaleString())}
            <span className="text-slate-600 font-normal ml-1">pipeline alerts</span>
          </span>
          {stats && stats.total > 0 && Object.entries(stats.by_severity).map(([sev, cnt]) => (
            <span key={sev} className={`font-mono tabular-nums ${
              sev === "CRITICAL" ? "text-red-400"
              : sev === "HIGH"   ? "text-orange-400"
              : sev === "MEDIUM" ? "text-yellow-400"
              : "text-slate-500"
            }`}>
              {sev} <span className="font-bold">{(cnt as number).toLocaleString()}</span>
            </span>
          ))}
        </div>
      ) : (
        <StatsStrip stats={stats} />
      )}

      {/* IP-unavailable notice — shown when session data has no IP columns */}
      {sessionId && !hasIpData && pipelineAlerts.length > 0 && (
        <div className="flex items-center gap-2 px-4 py-1.5 border-b border-amber-900/40 text-[11px]"
             style={{ background: "rgba(120,53,15,0.20)" }}>
          <span className="text-amber-500 shrink-0">&#9888;</span>
          <span className="text-amber-400/80">
            IP addresses not available — this dataset uses feature-extracted flows
            without <code className="font-mono text-amber-300/70">Source IP</code> /
            <code className="font-mono text-amber-300/70 ml-1">Destination IP</code> columns
            (standard CIC-IDS-2017 public release). Flow statistics, MITRE mapping, and
            ML detections are fully operational.
          </span>
        </div>
      )}

      {/* ── Filter bar ──────────────────────────────────────────────────── */}
      <div
        className="flex items-center gap-2 px-4 py-2.5 border-b border-white/5 flex-wrap"
        style={{ background: "rgba(5,10,20,0.70)" }}
      >
        {sessionId ? (
          /* ── Pipeline mode: faceted field-specific filters ── */
          <>
            {/* Active-filter chips — show what's currently applied */}
            {(activeSourceIp || activeDestIp || activeDestPort || activeMitre || activeSeverity || activeGlobalSearch) && (
              <div className="flex flex-wrap items-center gap-1 w-full pb-1.5" style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                <span className="text-[9px] uppercase tracking-wider font-semibold mr-1" style={{ color: "#3d3f4a" }}>Active:</span>
                {activeGlobalSearch && <Chip label={`search: ${activeGlobalSearch}`} onRemove={() => { setGlobalSearch(""); setActiveGlobalSearch(""); setOffset(0); }} />}
                {activeSourceIp  && <Chip label={`src: ${activeSourceIp}`}  onRemove={() => { setSourceIp(""); setActiveSourceIp(""); setOffset(0); }} />}
                {activeDestIp    && <Chip label={`dst: ${activeDestIp}`}    onRemove={() => { setDestIp(""); setActiveDestIp(""); setOffset(0); }} />}
                {activeDestPort  && <Chip label={`port: ${activeDestPort}`} onRemove={() => { setDestPort(""); setActiveDestPort(""); setOffset(0); }} />}
                {activeMitre     && <Chip label={`mitre: ${activeMitre}`}   onRemove={() => { setMitre(""); setActiveMitre(""); setOffset(0); }} />}
                {activeSeverity  && <Chip label={`sev: ${activeSeverity}`}  onRemove={() => { setSeverity(""); setActiveSeverity(""); setOffset(0); }} />}
              </div>
            )}
            <FacetInput ref={searchInputRef} placeholder="Global Search… (/)" value={globalSearch}
              onChange={setGlobalSearch} onEnter={runSearch} width={150} />
            <FacetInput placeholder="Src IP…" value={sourceIp}
              onChange={setSourceIp} onEnter={runSearch} width={110} />
            <FacetInput placeholder="Dst IP…" value={destIp}
              onChange={setDestIp} onEnter={runSearch} width={130} />
            <FacetInput placeholder="Port…" value={destPort}
              onChange={setDestPort} onEnter={runSearch} width={72} />
            <FacetInput placeholder="MITRE…" value={mitre}
              onChange={setMitre} onEnter={runSearch} width={100} monospace />
            <select
              value={severity}
              onChange={e => setSeverity(e.target.value as Severity | "")}
              className="rounded text-xs px-2 py-1.5 focus:outline-none cursor-pointer"
              style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.07)", color: "#c5c7d4", minWidth: "130px" }}
            >
              <option value="">Severity: All</option>
              {SEVERITY_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <button onClick={runSearch}
              className="px-3 py-1.5 rounded text-xs font-semibold transition-all active:scale-95"
              style={{ background: "rgba(6,182,212,0.15)", border: "1px solid rgba(6,182,212,0.35)", color: "#67e8f9" }}>
              Hunt
            </button>
            {(activeSourceIp || activeDestIp || activeDestPort || activeMitre || activeSeverity || activeGlobalSearch) && (
              <button onClick={clearFilters}
                className="px-2.5 py-1.5 rounded text-xs transition-all active:opacity-70"
                style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)", color: "#6b6e80" }}>
                ✕ Clear
              </button>
            )}
          </>
        ) : (
          /* ── Legacy mode: unified search + label + severity ── */
          <>
            <div
              className="flex items-center gap-2 rounded px-3 py-1.5 flex-1 min-w-[180px]
                         focus-within:ring-1 focus-within:ring-cyan-700/40 transition-all"
              style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.07)" }}
            >
              <Search className="w-3 h-3 text-slate-600 shrink-0" />
              <input
                ref={searchInputRef}
                type="text"
                value={globalSearch}
                onChange={e => setGlobalSearch(e.target.value)}
                onKeyDown={e => e.key === "Enter" && runSearch()}
                placeholder="Search by IP, label… (press / to focus)"
                className="flex-1 bg-transparent text-xs text-slate-200 placeholder-slate-600 focus:outline-none font-mono"
              />
            </div>
            <select
              value={label}
              onChange={e => { setLabel(e.target.value); setActiveLabel(e.target.value); setOffset(0); }}
              className="rounded text-xs px-2 py-1.5 focus:outline-none cursor-pointer transition-all"
              style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.07)", color: "#c5c7d4", minWidth: "160px" }}
            >
              <option value="">Threat Type: All</option>
              {Object.keys(stats?.by_label ?? {}).sort().map(l => (
                <option key={l} value={l}>{l}</option>
              ))}
            </select>
            <select
              value={severity}
              onChange={e => { setSeverity(e.target.value as Severity | ""); setActiveSeverity(e.target.value as Severity | ""); setOffset(0); }}
              className="rounded text-xs px-2 py-1.5 focus:outline-none cursor-pointer transition-all"
              style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.07)", color: "#c5c7d4", minWidth: "140px" }}
            >
              <option value="">Severity: All</option>
              {SEVERITY_OPTIONS.map(s => <option key={s} value={s}>Severity: {s}</option>)}
            </select>
            <button onClick={runSearch}
              className="px-4 py-1.5 rounded text-xs font-semibold transition-all active:scale-95"
              style={{ background: "rgba(6,182,212,0.15)", border: "1px solid rgba(6,182,212,0.35)", color: "#67e8f9" }}>
              Apply
            </button>
            {(activeGlobalSearch || activeLabel || activeSeverity) && (
              <button onClick={clearFilters}
                className="px-3 py-1.5 rounded text-xs transition-all active:opacity-70"
                style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)", color: "#6b6e80" }}>
                ✕ Clear
              </button>
            )}
          </>
        )}

        <div className="flex-1" />

        {/* IR Report — only for legacy datasets */}
        {!sessionId && (
          <button
            onClick={handleGenerateReport}
            disabled={generating || isEmpty}
            title="Generate Tier 2 Incident Response Report"
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold transition-all ${
              generating || isEmpty
                ? "opacity-30 cursor-not-allowed"
                : "active:scale-95"
            }`}
            style={generating || isEmpty
              ? { background: "rgba(255,255,255,0.03)", border: "1px solid #2e3038", color: "#4d5060" }
              : { background: "rgba(139,92,246,0.12)", border: "1px solid rgba(139,92,246,0.40)", color: "#a78bfa" }
            }
          >
            {generating
              ? <><span className="w-2.5 h-2.5 rounded-full border border-current border-t-transparent animate-spin" /> Generating…</>
              : <>⚡ IR Report</>
            }
          </button>
        )}

        {/* Generate AI Analysis — pipeline sessions only */}
        {sessionId && (
          <button
            onClick={() => setAiDrawerOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold transition-all active:scale-95"
            style={{ background: "rgba(217,70,239,0.12)", border: "1px solid rgba(217,70,239,0.35)", color: "#d946ef" }}
          >
            <Brain className="w-3 h-3" /> Generate AI Analysis
          </button>
        )}
      </div>

      {/* ── Loading / Empty / Table ──────────────────────────────────────── */}
      {statsLoading && !stats && !sessionId ? (
        <div className="flex-1 flex items-center justify-center gap-3" style={{ color: "#4d5060" }}>
          <span className="w-4 h-4 rounded-full border-2 border-cyan-600 border-t-transparent animate-spin" />
          <span className="text-sm">Loading flow data…</span>
        </div>
      ) : isEmpty ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-3"
             style={{ color: "#334155" }}>
          <FolderOpen className="w-10 h-10 opacity-20 text-slate-500" />
          <p className="text-sm text-slate-600">No telemetry data loaded yet.</p>
          <p className="text-xs text-slate-700">
            Upload a network flow CSV from the{" "}
            <span className="text-cyan-600 font-medium">Dashboard</span> or drop a file in{" "}
            <code className="text-slate-500 font-mono">data/monitor/</code>
          </p>
        </div>
      ) : (
        <>
          {/* ── Log table ──────────────────────────────────────────────── */}
          <div className="flex-1 overflow-auto">
            <table className="w-full text-xs border-collapse">
              <thead className="sticky top-0 z-10">
                <tr style={{ background: "rgba(2,8,23,0.98)", backdropFilter: "blur(12px)" }}
                    className="border-b border-white/5">
                  {(sessionId ? pipelineHeaders : legacyHeaders).map((h, i) => (
                    <th key={i}
                        className={`px-3 py-2.5 text-[10px] uppercase tracking-wider text-slate-600 font-medium
                                    ${i === 0 ? "text-left w-8"
                                      : sessionId
                                        ? (i === 3 || i === 5 ? "text-right" : i === 9 ? "text-center" : "text-left")
                                        : (i >= 9 ? "text-center" : i >= 5 ? "text-right" : "text-left")
                                    }`}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {isFetching && (sessionId ? pipelineAlerts.length : logs.length) === 0 ? (
                  <tr>
                    <td colSpan={colCount} className="px-4 py-8 text-center">
                      <div className="flex items-center justify-center gap-2 text-slate-600">
                        <span className="w-3 h-3 rounded-full border-2 border-cyan-600 border-t-transparent animate-spin" />
                        Loading…
                      </div>
                    </td>
                  </tr>
                ) : (sessionId ? pipelineAlerts : logs).length === 0 ? (
                  <tr>
                    <td colSpan={colCount} className="px-4 py-8 text-center text-slate-600 text-xs">
                      No results match your search.
                    </td>
                  </tr>
                ) : sessionId ? (
                  // ── Pipeline mode rows ────────────────────────────────
                  pipelineAlerts.map((alert, i) => (
                    <PipelineLogRow
                      key={alert.id}
                      alert={alert}
                      index={offset + i + 1}
                      expanded={expandedId === alert.id}
                      focused={i === focusedIdx}
                      onToggle={() => { setExpandedId(prev => prev === alert.id ? null : alert.id); setFocusedIdx(i); }}
                      onAnalyze={handleRowAnalyze}
                      onReviewSign={onReviewSign}
                    />
                  ))
                ) : (
                  // ── Legacy mode rows ──────────────────────────────────
                  logs.map((log, i) => (
                    <LogRow
                      key={log.id}
                      log={log}
                      index={offset + i + 1}
                      onAnalyze={handleRowAnalyze}
                      isAnalyzing={analyzingLog?.id === log.id && incidentReport === null}
                      isActioned={log.src_ip != null && actionedIps.has(log.src_ip)}
                      onReviewSign={onReviewSign}
                    />
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* ── Pagination ─────────────────────────────────────────────── */}
          <div className="flex items-center justify-between px-4 py-2.5 border-t border-white/5 text-xs"
               style={{ background: "rgba(2,8,23,0.70)" }}>
            <span className="text-slate-600 font-mono">
              {isFetching
                ? <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full border border-cyan-600 border-t-transparent animate-spin" />Fetching…</span>
                : (sessionId ? pipelineAlerts : logs).length === 0
                  ? "No results"
                  : `Rows ${offset + 1}–${offset + (sessionId ? pipelineAlerts : logs).length}${
                      sessionId 
                        ? (pipelineFilteredTotal > 0 ? ` of ${pipelineFilteredTotal.toLocaleString()}` : "")
                        : (displayTotal > 0 ? ` of ${displayTotal.toLocaleString()}` : "")
                    }`}
            </span>
            <div className="flex gap-1.5">
              <PaginationBtn
                label="← Prev"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              />
              <PaginationBtn
                label="Next →"
                disabled={(sessionId ? pipelineAlerts : logs).length < PAGE_SIZE}
                onClick={() => setOffset(offset + PAGE_SIZE)}
              />
            </div>
          </div>
        </>
      )}

      {/* Batch IR Report */}
      {irReport && <IrReportPanel report={irReport} onClose={() => setIrReport(null)} />}

      {/* Per-row Incident Report slide-over */}
      {analyzingLog && (
        <IncidentReportModal
          log={analyzingLog}
          report={incidentReport}
          cti={ctiData}
          aiGenerated={aiGenerated}
          onClose={() => { setAnalyzingLog(null); setIncidentReport(null); setCtiData(null); }}
        />
      )}

      {/* AI Analysis Drawer */}
      <AIAnalysisDrawer
        sessionId={sessionId ?? null}
        isOpen={aiDrawerOpen}
        onClose={() => setAiDrawerOpen(false)}
        activeFilters={{
          source_ip: activeSourceIp || undefined,
          dest_ip:   activeDestIp || undefined,
          dest_port: activeDestPort || undefined,
          mitre:     activeMitre || undefined,
          severity:  activeSeverity || undefined,
          global_search: activeGlobalSearch || undefined,
        }}
      />

      {/* Command Palette — Cmd+K */}
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onFilter={(sev) => {
          setSeverity(sev as Severity);
          setActiveSeverity(sev as Severity);
          setOffset(0);
          setPaletteOpen(false);
        }}
        onClear={() => {
          setGlobalSearch(""); setLabel(""); setSeverity("");
          setActiveGlobalSearch(""); setActiveLabel(""); setActiveSeverity("");
          setOffset(0);
          setPaletteOpen(false);
        }}
      />
    </div>
  );
}

function PaginationBtn({ label, disabled, onClick }: { label: string; disabled: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="px-3 py-1 rounded-md text-xs border border-white/8 bg-white/4
                 text-slate-500 hover:text-slate-200 hover:bg-white/8
                 active:scale-95 disabled:opacity-25 disabled:cursor-not-allowed transition-all"
    >
      {label}
    </button>
  );
}

// ── Pipeline log row — session mode ───────────────────────────────────────────

function PipelineLogRow({
  alert, index, expanded, focused, onToggle, onAnalyze, onReviewSign,
}: {
  alert:         PipelineAlert;
  index:         number;
  expanded:      boolean;
  focused:       boolean;
  onToggle:      () => void;
  onAnalyze:     (log: CicidsLog) => void;
  onReviewSign?: (alert: PipelineAlert) => void;
}) {
  const style = LOG_ROW_STYLE[alert.severity] ?? LOG_ROW_STYLE["INFO"];
  const ts = new Date(alert.ingested_at).toLocaleString(undefined, {
    month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false,
  });

  const rawFeatures = useMemo(() => {
    try { return alert.raw_features ? JSON.parse(alert.raw_features) as Record<string, string> : {}; }
    catch { return {} as Record<string, string>; }
  }, [alert.raw_features]);

  const COL_SPAN = 10;

  return (
    <>
      {/* ── Main data row — click to expand ─────────────────────────────── */}
      <tr
        onClick={onToggle}
        title="Click to expand event detail  |  j/k to navigate  |  Enter to review"
        className={`group transition-colors duration-100 cursor-pointer select-none ${style} ${
          expanded
            ? "brightness-110 shadow-[inset_3px_0_0_#0891b2]"
            : focused
              ? "row-kbd-focus shadow-[inset_3px_0_0_rgba(6,182,212,0.55)]"
              : "hover:brightness-110 hover:shadow-[inset_3px_0_0_rgba(6,182,212,0.35)]"
        }`}
      >
        {/* # + expand chevron */}
        <td className="px-3 py-1.5 font-mono text-slate-600 tabular-nums">
          <span className="flex items-center gap-1.5">
            <span className={`text-[9px] transition-transform duration-150 shrink-0 ${
              expanded ? "rotate-90 text-cyan-500" : "text-slate-700 group-hover:text-slate-500"
            }`}>▶</span>
            {index}
          </span>
        </td>

        <td className="px-3 py-1.5 font-mono text-[10px] text-slate-500 tabular-nums whitespace-nowrap">{ts}</td>

        {/* Src IP */}
        <td className="px-3 py-1.5 font-mono text-[11px] text-slate-300 group-hover:text-slate-100 transition-colors duration-100">
          {alert.source_ip ?? <span className="text-slate-700">—</span>}
        </td>

        {/* Src Port */}
        <td className="px-3 py-1.5 text-right font-mono text-[11px] tabular-nums text-slate-500 group-hover:text-slate-400 transition-colors duration-100">
          {alert.src_port ?? <span className="text-slate-700">—</span>}
        </td>

        {/* Dst IP */}
        <td className="px-3 py-1.5 font-mono text-[11px] text-slate-300 group-hover:text-slate-100 transition-colors duration-100">
          {alert.dest_ip ?? <span className="text-slate-700">—</span>}
        </td>

        {/* Dst Port */}
        <td className="px-3 py-1.5 text-right font-mono text-[11px] tabular-nums text-slate-400 group-hover:text-slate-200 transition-colors duration-100">
          {alert.dest_port ?? <span className="text-slate-700">—</span>}
        </td>

        {/* Protocol */}
        <td className="px-3 py-1.5 font-mono text-[11px] text-slate-400">
          {alert.protocol
            ? <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide"
                    style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.08)" }}>
                {alert.protocol}
              </span>
            : <span className="text-slate-700">—</span>
          }
        </td>

        {/* Severity */}
        <td className="px-3 py-1.5">
          <SeverityPill severity={alert.severity} />
        </td>

        {/* MITRE */}
        <td className="px-3 py-1.5 text-[10px]">
          {alert.mitre_name ? (
            <span className="px-1.5 py-0.5 rounded bg-violet-950/60 text-violet-300 border border-violet-800/40 font-mono whitespace-nowrap
                             group-hover:bg-violet-900/60 group-hover:border-violet-700/60 transition-colors duration-100">
              {alert.mitre_name}
            </span>
          ) : (
            <span className="text-slate-700">—</span>
          )}
        </td>

        {/* Act */}
        <td className="px-3 py-1.5 text-center">
          {onReviewSign && (
            <button
              onClick={e => { e.stopPropagation(); onReviewSign(alert); }}
              className="px-2 py-1 rounded text-[10px] font-semibold transition-all duration-100 active:scale-95 whitespace-nowrap
                         opacity-0 group-hover:opacity-100"
              style={{ background: "rgba(217,70,239,0.12)", border: "1px solid rgba(217,70,239,0.35)", color: "#d946ef" }}
            >
              Review & Sign
            </button>
          )}
        </td>
      </tr>

      {/* ── Expanded detail panel (Splunk-style event view) ─────────────── */}
      {expanded && (
        <tr>
          <td colSpan={COL_SPAN} className="p-0">
            <div
              className="px-5 py-4 border-y"
              style={{
                background:   "rgba(0,5,15,0.80)",
                borderColor:  "rgba(6,182,212,0.18)",
                borderLeftWidth: "3px",
                borderLeftColor: "#0891b2",
              }}
            >
              {/* Header: id pill + chain hash + AI button */}
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className="text-[10px] uppercase tracking-widest font-semibold text-slate-500">
                    Event Detail
                  </span>
                  <code className="font-mono text-[9px] px-1.5 py-0.5 rounded text-slate-600"
                        style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.06)" }}>
                    id:{alert.id}
                  </code>
                  {alert.chain_hash && (
                    <code
                      className="font-mono text-[9px] px-1.5 py-0.5 rounded truncate max-w-[200px] cursor-default"
                      style={{ background: "rgba(6,182,212,0.06)", border: "1px solid rgba(6,182,212,0.18)", color: "#0e7490" }}
                      title={alert.chain_hash}
                    >
                      chain:{alert.chain_hash.slice(0, 16)}…
                    </code>
                  )}
                  {alert.z_score_bytes != null && (
                    <span className={`font-mono text-[10px] tabular-nums ${alert.z_score_bytes > 3 ? "text-orange-400" : "text-slate-500"}`}>
                      σ={alert.z_score_bytes.toFixed(2)}
                    </span>
                  )}
                </div>

                <button
                  onClick={e => { e.stopPropagation(); onAnalyze(pipelineAlertToLog(alert)); }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[11px] font-semibold
                             transition-all duration-150 active:scale-95 hover:brightness-115"
                  style={{
                    background: "rgba(217,70,239,0.10)",
                    border:     "1px solid rgba(217,70,239,0.30)",
                    color:      "#d946ef",
                    boxShadow:  "0 0 14px rgba(217,70,239,0.10)",
                  }}
                >
                  <Brain className="w-3 h-3" />
                  Analyze with AI
                </button>
              </div>

              {/* Two-column: alert fields (left) | raw feature snapshot (right) */}
              <div className="grid grid-cols-2 gap-6">
                <div>
                  <p className="text-[9px] uppercase tracking-wider text-slate-700 font-semibold mb-2">
                    Alert Fields <span className="normal-case tracking-normal font-normal ml-1 text-slate-800">(sent to AI)</span>
                  </p>
                  <div className="space-y-1">
                    {([
                      ["Source IP",    alert.source_ip],
                      ["Src Port",     alert.src_port],
                      ["Dest IP",      alert.dest_ip],
                      ["Dest Port",    alert.dest_port],
                      ["Protocol",     alert.protocol],
                      ["Label",        alert.label],
                      ["MITRE ID",     alert.mitre_technique],
                      ["MITRE Name",   alert.mitre_name],
                      ["Bytes Total",  alert.bytes_total != null ? alert.bytes_total.toLocaleString() + " B" : null],
                      ["Z-Bytes",      alert.z_score_bytes?.toFixed(4)],
                      ["Z-Pkts",       alert.z_score_pkts?.toFixed(4)],
                      ["Dataset",      alert.dataset_type],
                      ["Session",      alert.session_id.slice(0, 8) + "…"],
                    ] as [string, string | number | null | undefined][])
                      .filter(([, v]) => v != null && v !== "")
                      .map(([k, v]) => (
                        <div key={k} className="flex gap-2 font-mono text-[10px] group/field hover:bg-white/[0.02] rounded px-1 -mx-1 transition-colors">
                          <span className="text-slate-600 w-20 shrink-0">{k}</span>
                          <span className="text-slate-300 truncate">{String(v)}</span>
                        </div>
                      ))
                    }
                  </div>
                </div>

                <div>
                  <p className="text-[9px] uppercase tracking-wider text-slate-700 font-semibold mb-2">
                    Raw Feature Snapshot
                  </p>
                  {Object.keys(rawFeatures).length > 0 ? (
                    <div className="space-y-1">
                      {Object.entries(rawFeatures).map(([k, v]) => (
                        <div key={k} className="flex gap-2 font-mono text-[10px] hover:bg-white/[0.02] rounded px-1 -mx-1 transition-colors">
                          <span className="text-slate-600 w-20 shrink-0">{k}</span>
                          <span className="text-slate-400 truncate">{String(v)}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[10px] font-mono text-slate-700">No raw snapshot stored for this alert.</p>
                  )}
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Legacy log row ────────────────────────────────────────────────────────────

function LogRow({
  log, index, onAnalyze, isAnalyzing, isActioned, onReviewSign,
}: {
  log:           CicidsLog;
  index:         number;
  onAnalyze:     (log: CicidsLog) => void;
  isAnalyzing:   boolean;
  isActioned:    boolean;
  onReviewSign?: (alert: PipelineAlert) => void;
}) {
  const style     = LOG_ROW_STYLE[log.severity] ?? LOG_ROW_STYLE["INFO"];
  const isBots    = log.source_file === "botsv3_export";
  const isAttack  = log.severity !== "INFO";
  const canAnalyze = isBots || isAttack;

  function handleVerify(e: React.MouseEvent) {
    e.stopPropagation(); // don't trigger the row-click AI analysis
    if (!onReviewSign) return;
    // Construct a PipelineAlert-shaped object from the legacy CicidsLog fields.
    // chain_hash is null for CIC-IDS / BOTSv3 rows (they don't go through the
    // hash-chain pipeline) — the Trust Chain will show "—" for that field.
    onReviewSign({
      id:              typeof log.id === "number" ? log.id : 0,
      session_id:      "",
      ingested_at:     log.ingested_at,
      dataset_type:    log.source_file,
      source_ip:       log.src_ip,
      dest_ip:         log.dst_ip,
      src_port:        null,
      dest_port:       log.dst_port,
      protocol:        String(log.protocol ?? ""),
      label:           log.label,
      severity:        log.severity,
      mitre_technique: null,
      mitre_name:      log.category ?? null,
      bytes_total:     log.flow_bytes_s != null ? Math.round(log.flow_bytes_s) : null,
      chain_hash:      null,
      z_score_bytes:   null,
      z_score_pkts:    null,
      raw_features:    null,
    });
  }

  return (
    <tr
      onClick={() => canAnalyze && onAnalyze(log)}
      title={canAnalyze ? "Click to open AI Incident Report" : undefined}
      className={`transition-all ${style} ${
        canAnalyze
          ? "cursor-pointer hover:brightness-125 hover:scale-[1.001]"
          : "opacity-40 cursor-default"
      }`}
    >
      <td className="px-3 py-1.5 font-mono text-slate-600 tabular-nums">{index}</td>
      <td className="px-3 py-1.5">
        <SeverityPill severity={log.severity} />
      </td>
      <td className="px-3 py-1.5 font-semibold text-[11px]">
        <span className="flex items-center gap-1.5">
          {isAnalyzing && (
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping shrink-0" />
          )}
          {log.label}
        </span>
      </td>
      <td className="px-3 py-1.5 font-mono text-[11px]">{log.src_ip ?? <span className="text-slate-700">—</span>}</td>
      <td className="px-3 py-1.5 font-mono text-[11px]">{log.dst_ip ?? <span className="text-slate-700">—</span>}</td>
      <td className="px-3 py-1.5 text-right font-mono text-[11px] tabular-nums">{log.dst_port ?? "—"}</td>
      <td className="px-3 py-1.5 text-right font-mono text-[11px] tabular-nums">{log.protocol ?? "—"}</td>
      <td className="px-3 py-1.5 text-right font-mono text-[11px] tabular-nums">
        {log.flow_duration != null ? log.flow_duration.toLocaleString() : "—"}
      </td>
      <td className="px-3 py-1.5 text-right font-mono text-[11px] tabular-nums">
        {log.flow_bytes_s != null ? log.flow_bytes_s.toFixed(1) : "—"}
      </td>
      <td className="px-3 py-1.5 text-slate-600 truncate max-w-[100px] text-[10px]">{log.source_file}</td>
      <td className="px-3 py-1.5 text-center">
        <div className="flex items-center justify-center gap-1.5">
          {isActioned && (
            <span title="Playbook executed against this IP">
              <Shield
                className="w-3.5 h-3.5 text-emerald-400"
                style={{ filter: "drop-shadow(0 0 4px rgba(34,197,94,0.55))" }}
              />
            </span>
          )}
          {onReviewSign && canAnalyze && (
            <button
              onClick={handleVerify}
              title="Send to Trust Chain for cryptographic verification"
              className="px-2 py-0.5 rounded text-[9px] font-semibold transition-all active:scale-95 whitespace-nowrap"
              style={{
                background: "rgba(217,70,239,0.10)",
                border:     "1px solid rgba(217,70,239,0.28)",
                color:      "#d946ef",
              }}
            >
              Verify
            </button>
          )}
        </div>
      </td>
    </tr>
  );
}
