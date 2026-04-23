import { useState, useCallback, useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Shield, Search, FolderOpen, BarChart2, TrendingUp } from "lucide-react";
import { api } from "../lib/api";
import { LOG_ROW_STYLE, SEVERITY_BADGE } from "../lib/utils";
import { IncidentReportModal } from "./IncidentReportModal";
import type { CicidsLog, CicidsStats, CtiEnrichment, IrReport, Severity } from "../lib/types";

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

export function LogExplorer() {
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

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey:        ["cicids-stats"],
    queryFn:         api.getCicidsStats,
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
    queryFn: api.getBotsv3Dashboard 
  });

  // Determine which dataset to show
  const isBotsOnly = (stats?.total === 0 || !stats) && (botsv3Dashboard?.has_data);
  const activeDataset = isBotsOnly ? "botsv3" : "cicids";

  const { data: logs = [], isFetching } = useQuery({
    queryKey: ["logs", activeDataset, activeSearch, activeSeverity, activeLabel, offset],
    queryFn: () => {
      if (activeDataset === "botsv3") {
        return api.getBotsv3Logs({ search: activeSearch, limit: PAGE_SIZE, offset });
      }
      return api.getCicidsLogs({
        search: activeSearch, severity: activeSeverity,
        label: activeLabel, limit: PAGE_SIZE, offset,
      });
    },
    placeholderData: prev => prev,
  });

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

  // Distinguish "still fetching on first load" from "data loaded but empty"
  const statsReady = !statsLoading && stats !== undefined;
  const hasCicids  = statsReady && stats.total > 0;
  const hasBots    = botsv3Dashboard?.has_data;
  const isEmpty    = !hasCicids && !hasBots;

  return (
    <div className="flex flex-col h-full">
      <StatsStrip stats={stats} />

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

        {/* Threat Type dropdown — populated from loaded stats, auto-applies */}
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

        {/* Severity dropdown — auto-applies */}
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

        {/* IR Report */}
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
      </div>

      {/* ── Loading / Empty / Table ──────────────────────────────────────── */}
      {statsLoading && !stats ? (
        /* Initial load — stats not fetched yet */
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
                  {["#", "Severity", "Label / Attack", "Src IP", "Dst IP", "Port", "Proto", "Flow (μs)", "Bytes/s", "File", "Act"].map((h, i) => (
                    <th key={i}
                        className={`px-3 py-2.5 text-[10px] uppercase tracking-wider text-slate-600 font-medium
                                    ${i === 0 ? "text-left w-8" : i >= 9 ? "text-center" : i >= 5 ? "text-right" : "text-left"}`}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {isFetching && logs.length === 0 ? (
                  <tr>
                    <td colSpan={11} className="px-4 py-8 text-center">
                      <div className="flex items-center justify-center gap-2 text-slate-600">
                        <span className="w-3 h-3 rounded-full border-2 border-cyan-600 border-t-transparent animate-spin" />
                        Loading…
                      </div>
                    </td>
                  </tr>
                ) : logs.length === 0 ? (
                  <tr>
                    <td colSpan={11} className="px-4 py-8 text-center text-slate-600 text-xs">
                      No results match your search.
                    </td>
                  </tr>
                ) : (
                  logs.map((log, i) => (
                    <LogRow
                      key={log.id}
                      log={log}
                      index={offset + i + 1}
                      onAnalyze={handleRowAnalyze}
                      isAnalyzing={analyzingLog?.id === log.id && incidentReport === null}
                      isActioned={log.src_ip != null && actionedIps.has(log.src_ip)}
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
                : `Rows ${offset + 1}–${offset + logs.length} of ${stats?.total.toLocaleString() ?? "?"}`}
            </span>
            <div className="flex gap-1.5">
              <PaginationBtn
                label="← Prev"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              />
              <PaginationBtn
                label="Next →"
                disabled={logs.length < PAGE_SIZE}
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

// ── Log row ───────────────────────────────────────────────────────────────────

function LogRow({
  log, index, onAnalyze, isAnalyzing, isActioned,
}: {
  log:         CicidsLog;
  index:       number;
  onAnalyze:   (log: CicidsLog) => void;
  isAnalyzing: boolean;
  isActioned:  boolean;
}) {
  const style    = LOG_ROW_STYLE[log.severity] ?? LOG_ROW_STYLE["INFO"];
  // For BOTSv3, we allow analyzing any row to help understand the raw text.
  // For CIC-IDS, we stick to attacks only to reduce noise.
  const isBots    = log.source_file === "botsv3_export";
  const isAttack  = log.severity !== "INFO";
  const canAnalyze = isBots || isAttack;

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
        {isActioned && (
          <Shield
            title="Playbook executed against this IP"
            className="w-3.5 h-3.5 mx-auto text-emerald-400"
            style={{ filter: "drop-shadow(0 0 4px rgba(34,197,94,0.55))" }}
          />
        )}
      </td>
    </tr>
  );
}
