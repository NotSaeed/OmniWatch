import { useState, useCallback, useMemo, useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Shield, Search, FolderOpen } from "lucide-react";
import { api } from "../lib/api";
import { LOG_ROW_STYLE, SEVERITY_BADGE } from "../lib/utils";
import { IncidentReportModal } from "./IncidentReportModal";
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

// ── Main component ────────────────────────────────────────────────────────────

interface LogExplorerProps {
  /** When set, switches the data source to telemetry_alerts for this session. */
  sessionId?: string | null;
  /** Called when the analyst clicks "Review & Sign" on a pipeline alert. */
  onReviewSign?: (alert: PipelineAlert) => void;
}

export function LogExplorer({ sessionId, onReviewSign }: LogExplorerProps) {
  const qc = useQueryClient();

  const [search,      setSearch]      = useState("");
  const [severity,    setSeverity]    = useState<Severity | "">("");
  const [label,       setLabel]       = useState("");
  const [offset,      setOffset]      = useState(0);
  const [irReport,    setIrReport]    = useState<IrReport | null>(null);
  const [generating,  setGenerating]  = useState(false);

  const [analyzingLog,   setAnalyzingLog]   = useState<CicidsLog | null>(null);
  const [incidentReport, setIncidentReport] = useState<string | null>(null);
  const [ctiData,        setCtiData]        = useState<CtiEnrichment | null>(null);
  const [aiGenerated,    setAiGenerated]    = useState<boolean>(true);

  const [activeSearch,   setActiveSearch]   = useState("");
  const [activeSeverity, setActiveSeverity] = useState<Severity | "">("");
  const [activeLabel,    setActiveLabel]    = useState("");

  // Reset filters and page when the active session changes
  useEffect(() => {
    setOffset(0);
    setSearch(""); setSeverity(""); setLabel("");
    setActiveSearch(""); setActiveSeverity(""); setActiveLabel("");
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
  const { data: pipelineAlerts = [], isFetching: pipelineFetching } = useQuery({
    queryKey: ["logs", sessionId, activeSearch, activeSeverity, offset],
    queryFn: () => api.getPipelineAlerts({
      session_id: sessionId!,
      search:     activeSearch || undefined,
      severity:   activeSeverity || undefined,
      limit:      PAGE_SIZE,
      offset,
    }),
    enabled:         !!sessionId,
    placeholderData: prev => prev,
    staleTime:       0,
  });

  // ── Legacy CIC-IDS / BOTSv3 query ──────────────────────────────────────────
  const isBotsOnly    = !sessionId && (stats?.total === 0 || !stats) && botsv3Dashboard?.has_data;
  const legacyDataset = isBotsOnly ? "botsv3" : "cicids";

  const { data: rawLogs = [], isFetching: legacyFetching } = useQuery({
    queryKey: ["logs", legacyDataset, activeSearch, activeSeverity, activeLabel, offset],
    queryFn: () => {
      if (legacyDataset === "botsv3") {
        return api.getBotsv3Logs({ search: activeSearch, limit: PAGE_SIZE, offset });
      }
      return api.getCicidsLogs({
        search: activeSearch, severity: activeSeverity,
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
    setActiveSearch(search);
    setActiveSeverity(severity);
    setActiveLabel(label);
    setOffset(0);
  }, [search, severity, label]);

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

  // Pipeline-mode column headers
  const pipelineHeaders = ["#", "Timestamp", "Severity", "Label / Attack", "Src IP", "Dst IP", "Port", "MITRE Tactic", "Act"];
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

      {/* ── Filter bar ──────────────────────────────────────────────────── */}
      <div
        className="flex items-center gap-2 px-4 py-2.5 border-b border-white/5 flex-wrap"
        style={{ background: "rgba(5,10,20,0.70)" }}
      >
        {/* Search */}
        <div
          className="flex items-center gap-2 rounded px-3 py-1.5 flex-1 min-w-[180px]
                     focus-within:ring-1 focus-within:ring-cyan-700/40 transition-all"
          style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.07)" }}
        >
          <Search className="w-3 h-3 text-slate-600 shrink-0" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            onKeyDown={e => e.key === "Enter" && runSearch()}
            placeholder="Search by IP address…"
            className="flex-1 bg-transparent text-xs text-slate-200 placeholder-slate-600 focus:outline-none font-mono"
          />
        </div>

        {/* Threat Type dropdown — hidden in pipeline mode (label filter not supported) */}
        {!sessionId && (
          <select
            value={label}
            onChange={e => { setLabel(e.target.value); setActiveLabel(e.target.value); setOffset(0); }}
            className="rounded text-xs px-2 py-1.5 focus:outline-none cursor-pointer transition-all"
            style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.07)", color: "#c5c7d4", minWidth: "160px" }}
          >
            <option value="">Threat Type: All</option>
            {Object.keys(stats?.by_label ?? {})
              .sort()
              .map(l => (
                <option key={l} value={l}>{l}</option>
              ))}
          </select>
        )}

        {/* Severity dropdown */}
        <select
          value={severity}
          onChange={e => { setSeverity(e.target.value as Severity | ""); setActiveSeverity(e.target.value as Severity | ""); setOffset(0); }}
          className="rounded text-xs px-2 py-1.5 focus:outline-none cursor-pointer transition-all"
          style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.07)", color: "#c5c7d4", minWidth: "140px" }}
        >
          <option value="">Severity: All</option>
          {SEVERITY_OPTIONS.map(s => <option key={s} value={s}>Severity: {s}</option>)}
        </select>

        <button
          onClick={runSearch}
          className="px-4 py-1.5 rounded text-xs font-semibold transition-all active:scale-95"
          style={{ background: "rgba(6,182,212,0.15)", border: "1px solid rgba(6,182,212,0.35)", color: "#67e8f9" }}
        >
          Apply
        </button>

        {(activeSearch || activeLabel || activeSeverity) && (
          <button
            onClick={() => {
              setSearch(""); setLabel(""); setSeverity("");
              setActiveSearch(""); setActiveLabel(""); setActiveSeverity(""); setOffset(0);
            }}
            className="px-3 py-1.5 rounded text-xs transition-all active:opacity-70"
            style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)", color: "#6b6e80" }}
          >
            ✕ Clear
          </button>
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
                                    ${i === 0 ? "text-left w-8" : i >= (sessionId ? 7 : 9) ? "text-center" : i >= (sessionId ? 5 : 5) ? "text-right" : "text-left"}`}>
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
                  : `Rows ${offset + 1}–${offset + (sessionId ? pipelineAlerts : logs).length}${displayTotal > 0 ? ` of ${displayTotal.toLocaleString()}` : ""}`}
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
  alert, index, onReviewSign,
}: {
  alert:         PipelineAlert;
  index:         number;
  onReviewSign?: (alert: PipelineAlert) => void;
}) {
  const style = LOG_ROW_STYLE[alert.severity] ?? LOG_ROW_STYLE["INFO"];
  const ts = new Date(alert.ingested_at).toLocaleString(undefined, {
    month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false,
  });

  return (
    <tr className={`transition-all ${style}`}>
      <td className="px-3 py-1.5 font-mono text-slate-600 tabular-nums">{index}</td>
      <td className="px-3 py-1.5 font-mono text-[10px] text-slate-500 tabular-nums whitespace-nowrap">{ts}</td>
      <td className="px-3 py-1.5">
        <SeverityPill severity={alert.severity} />
      </td>
      <td className="px-3 py-1.5 font-semibold text-[11px]">{alert.label}</td>
      <td className="px-3 py-1.5 font-mono text-[11px]">
        {alert.source_ip ?? <span className="text-slate-700">—</span>}
      </td>
      <td className="px-3 py-1.5 font-mono text-[11px]">
        {alert.dest_ip ?? <span className="text-slate-700">—</span>}
      </td>
      <td className="px-3 py-1.5 text-right font-mono text-[11px] tabular-nums">
        {alert.dest_port ?? "—"}
      </td>
      <td className="px-3 py-1.5 text-[10px]">
        {alert.mitre_name ? (
          <span className="px-1.5 py-0.5 rounded bg-violet-950/60 text-violet-300 border border-violet-800/40 font-mono whitespace-nowrap">
            {alert.mitre_name}
          </span>
        ) : (
          <span className="text-slate-700">—</span>
        )}
      </td>
      <td className="px-3 py-1.5 text-center">
        {onReviewSign ? (
          <button
            onClick={() => onReviewSign(alert)}
            className="px-2 py-1 rounded text-[10px] font-semibold transition-all active:scale-95 whitespace-nowrap"
            style={{
              background: "rgba(217,70,239,0.12)",
              border: "1px solid rgba(217,70,239,0.35)",
              color: "#d946ef",
            }}
          >
            Review & Sign
          </button>
        ) : null}
      </td>
    </tr>
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
      dest_port:       log.dst_port,
      protocol:        String(log.protocol ?? ""),
      label:           log.label,
      severity:        log.severity,
      mitre_technique: null,
      mitre_name:      log.category ?? null,
      bytes_total:     log.flow_bytes_s != null ? Math.round(log.flow_bytes_s) : null,
      chain_hash:      null,
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
