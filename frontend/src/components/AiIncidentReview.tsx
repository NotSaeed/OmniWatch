import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, Shield, Brain, Zap } from "lucide-react";
import { api } from "../lib/api";
import { SEVERITY_BADGE } from "../lib/utils";
import type { CicidsLog, CtiEnrichment, PipelineAlert } from "../lib/types";

// Bit labels for the 14-bit triggered_rules field (low-order → high-order)
const RULE_BIT_LABELS: Record<number, string> = {
  0: "DDSketch",
  1: "LODA",
  2: "CUSUM",
  3: "Port",
  4: "Volume",
  5: "Label-KW",
  6: "Time-Win",
};

function decodeBits(rules: number): string[] {
  const active: string[] = [];
  for (let bit = 0; bit < 14; bit++) {
    if (rules & (1 << bit)) {
      active.push(RULE_BIT_LABELS[bit] ?? `Bit${bit}`);
    }
  }
  return active;
}

function formatBytes(bytes: number | null): string {
  if (bytes == null) return "—";
  if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
  if (bytes >= 1_024) return `${(bytes / 1_024).toFixed(1)} KB`;
  return `${bytes} B`;
}

interface AiIncidentReviewProps {
  alert: PipelineAlert | null;
  onClose: () => void;
  onReviewSign?: (alert: PipelineAlert) => void;
}

export function AiIncidentReview({ alert, onClose, onReviewSign }: AiIncidentReviewProps) {
  // Cache AI reports per alert ID so re-opening doesn't re-fetch
  const reportCache = useRef<Map<number, { report: string; cti: CtiEnrichment | null }>>(new Map());

  const [aiReport,   setAiReport]   = useState<string | null>(null);
  const [ctiData,    setCtiData]    = useState<CtiEnrichment | null>(null);
  const [analyzing,  setAnalyzing]  = useState(false);
  const [aiGenerated, setAiGenerated] = useState(true);

  // Reset state when alert changes
  useEffect(() => {
    if (!alert) { setAiReport(null); setCtiData(null); return; }
    const cached = reportCache.current.get(alert.id);
    if (cached) {
      setAiReport(cached.report);
      setCtiData(cached.cti);
    } else {
      setAiReport(null);
      setCtiData(null);
    }
  }, [alert?.id]);

  // Close on Escape
  useEffect(() => {
    if (!alert) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [alert, onClose]);

  async function handleAnalyze() {
    if (!alert || analyzing) return;
    setAnalyzing(true);
    const log: CicidsLog = {
      id:            alert.id,
      ingested_at:   alert.ingested_at,
      src_ip:        alert.source_ip,
      dst_ip:        alert.dest_ip,
      dst_port:      alert.dest_port,
      protocol:      alert.protocol,
      label:         alert.label,
      severity:      alert.severity,
      category:      alert.mitre_name ?? alert.label,
      flow_duration: null,
      flow_bytes_s:  alert.bytes_total,
      source_file:   alert.dataset_type,
    };
    try {
      const { report, ai_generated, cti } = await api.analyzeIncident(log);
      setAiReport(report);
      setCtiData(cti ?? null);
      setAiGenerated(ai_generated ?? true);
      reportCache.current.set(alert.id, { report, cti: cti ?? null });
    } catch {
      const fallback =
        "## Heuristic Analysis\n\n" +
        "AI narrative unavailable — verify Ollama is running.\n\n" +
        "Relying on deterministic Tier 1 engine results shown in the stats above.";
      setAiReport(fallback);
      setAiGenerated(false);
      reportCache.current.set(alert.id, { report: fallback, cti: null });
    } finally {
      setAnalyzing(false);
    }
  }

  const rawRules = alert?.raw_features
    ? (() => {
        try {
          if (alert.raw_features.includes("MOCK_DEV_RECEIPT") || alert.raw_features.includes("DEV_MOCK_RECEIPT")) {
            return 0;
          }
          const f = JSON.parse(alert.raw_features) as Record<string, string>;
          const v = parseInt(f["triggered_rules"] ?? "0", 10);
          return isNaN(v) ? 0 : v;
        } catch { return 0; }
      })()
    : 0;
  const ruleBits = decodeBits(rawRules);

  return (
    <AnimatePresence>
      {alert && (
        <>
          {/* Transparent click-through backdrop — keeps grid visible */}
          <div
            className="fixed inset-0 z-[39] pointer-events-none"
            style={{ background: "rgba(0,0,0,0.18)" }}
          />

          {/* Slide-over panel */}
          <motion.div
            key="ai-incident-review"
            initial={{ x: "100%", opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: "100%", opacity: 0 }}
            transition={{ type: "spring", stiffness: 300, damping: 30 }}
            className="fixed right-0 top-0 h-screen w-[480px] z-40 flex flex-col overflow-hidden"
            style={{
              background:   "var(--slideover-bg, rgba(7,14,26,0.97))",
              borderLeft:   "1px solid var(--slideover-border, rgba(21,33,48,0.90))",
              backdropFilter: "blur(20px)",
            }}
          >
            {/* ── Header ─────────────────────────────────────────────────────── */}
            <div
              className="flex items-center justify-between px-5 py-3.5 shrink-0 border-b border-white/5"
              style={{ background: "rgba(2,8,23,0.80)" }}
            >
              <div className="flex items-center gap-2.5">
                <Shield className="w-4 h-4 text-cyan-500 shrink-0" />
                <span className="text-sm font-semibold text-slate-100">Alert #{alert.id}</span>
                <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide
                                  ${SEVERITY_BADGE[alert.severity] ?? SEVERITY_BADGE.INFO}`}>
                  {alert.severity}
                </span>
              </div>
              <button
                onClick={onClose}
                title="Close (Escape)"
                className="w-7 h-7 flex items-center justify-center rounded-lg text-slate-500
                           hover:text-slate-200 bg-slate-800/60 hover:bg-slate-700/60
                           border border-slate-700/50 active:scale-95 transition-all text-sm"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* ── Scrollable body ─────────────────────────────────────────────── */}
            <div className="flex-1 overflow-y-auto">
              <div className="p-5 space-y-4">

                {/* 5-tuple block */}
                <div
                  className="rounded-lg p-4"
                  style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)" }}
                >
                  <p className="text-[10px] uppercase tracking-widest text-slate-600 mb-2.5 font-semibold">
                    Network 5-Tuple
                  </p>
                  <p className="font-mono text-[12px] text-slate-200 leading-relaxed">
                    <span className="text-cyan-400">{alert.source_ip ?? "?"}</span>
                    <span className="text-slate-600">:</span>
                    <span className="text-slate-400">{alert.src_port ?? "?"}</span>
                    <span className="text-slate-600 mx-2">→</span>
                    <span className="text-orange-300">{alert.dest_ip ?? "?"}</span>
                    <span className="text-slate-600">:</span>
                    <span className="text-slate-400">{alert.dest_port ?? "?"}</span>
                    <span className="text-slate-600 mx-2">|</span>
                    <span className="text-slate-400">{alert.protocol ?? "?"}</span>
                  </p>
                  <p className="font-mono text-[10px] text-slate-600 mt-1.5">
                    {new Date(alert.ingested_at).toLocaleString()}
                  </p>
                </div>

                {/* MITRE card */}
                {(alert.mitre_technique || alert.mitre_name) && (
                  <div
                    className="rounded-lg p-4"
                    style={{ background: "rgba(139,92,246,0.08)", border: "1px solid rgba(139,92,246,0.20)" }}
                  >
                    <p className="text-[10px] uppercase tracking-widest text-violet-500 mb-2 font-semibold">
                      MITRE ATT&CK
                    </p>
                    <div className="flex items-center gap-2">
                      {alert.mitre_technique && (
                        <span className="px-1.5 py-0.5 rounded font-mono text-[11px] text-violet-300 bg-violet-900/40 border border-violet-700/40">
                          {alert.mitre_technique}
                        </span>
                      )}
                      {alert.mitre_name && (
                        <span className="text-[12px] text-violet-200 font-medium">{alert.mitre_name}</span>
                      )}
                    </div>
                  </div>
                )}

                {/* Stats row */}
                <div className="grid grid-cols-3 gap-2">
                  <StatCell label="Bytes" value={formatBytes(alert.bytes_total)} />
                  <StatCell label="Z-Score" value={alert.z_score_bytes != null ? alert.z_score_bytes.toFixed(2) : "—"} />
                  <StatCell label="Dataset" value={alert.dataset_type} />
                </div>

                {/* Triggered rules */}
                {ruleBits.length > 0 && (
                  <div>
                    <p className="text-[10px] uppercase tracking-widest text-slate-600 mb-1.5 font-semibold">
                      Triggered Detectors
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {ruleBits.map(bit => (
                        <span
                          key={bit}
                          className="px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold
                                     bg-cyan-900/30 text-cyan-300 border border-cyan-700/40"
                        >
                          {bit}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Chain hash */}
                {alert.chain_hash && (
                  <div>
                    <p className="text-[10px] uppercase tracking-widest text-slate-600 mb-1 font-semibold">
                      Chain Hash
                    </p>
                    <p className="font-mono text-[10px] text-slate-600 break-all">{alert.chain_hash}</p>
                  </div>
                )}

                {/* AI Analysis */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-[10px] uppercase tracking-widest text-slate-600 font-semibold">
                      AI Analysis
                    </p>
                    {!aiReport && (
                      <button
                        onClick={handleAnalyze}
                        disabled={analyzing}
                        className="flex items-center gap-1.5 px-3 py-1 rounded text-xs font-semibold
                                   transition-all active:scale-95 disabled:opacity-50"
                        style={{
                          background: "rgba(217,70,239,0.12)",
                          border: "1px solid rgba(217,70,239,0.35)",
                          color: "#d946ef",
                        }}
                      >
                        {analyzing
                          ? <><span className="w-2.5 h-2.5 rounded-full border border-current border-t-transparent animate-spin" /> Analyzing…</>
                          : <><Brain className="w-3 h-3" /> Generate</>
                        }
                      </button>
                    )}
                  </div>

                  {aiReport && (
                    <div
                      className="rounded-lg p-4 max-h-64 overflow-y-auto"
                      style={{ background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.06)" }}
                    >
                      {!aiGenerated && (
                        <div className="flex items-center gap-1.5 mb-2">
                          <span className="text-[9px] uppercase tracking-widest text-amber-600 font-semibold">
                            Heuristic (no LLM)
                          </span>
                        </div>
                      )}
                      <pre className="whitespace-pre-wrap text-[11px] text-slate-300 font-sans leading-relaxed">
                        {aiReport}
                      </pre>
                    </div>
                  )}

                  {/* CTI enrichment */}
                  {ctiData && (
                    <div className="mt-2 space-y-1">
                      {ctiData.abuseipdb?.abuse_confidence_score != null && (
                        <p className="text-[10px] text-slate-500 font-mono">
                          AbuseIPDB: {ctiData.abuseipdb.abuse_confidence_score}% confidence
                          {ctiData.abuseipdb.country_code ? ` · ${ctiData.abuseipdb.country_code}` : ""}
                          {ctiData.abuseipdb.isp ? ` · ${ctiData.abuseipdb.isp}` : ""}
                        </p>
                      )}
                      {ctiData.virustotal?.malicious != null && (
                        <p className="text-[10px] text-slate-500 font-mono">
                          VirusTotal: {ctiData.virustotal.malicious}/{ctiData.virustotal.total_engines ?? "?"} engines
                          {ctiData.virustotal.threat_label ? ` · ${ctiData.virustotal.threat_label}` : ""}
                        </p>
                      )}
                    </div>
                  )}
                </div>

              </div>
            </div>

            {/* ── Footer CTA ──────────────────────────────────────────────────── */}
            <div
              className="px-5 py-4 shrink-0 border-t border-white/5"
              style={{ background: "rgba(2,8,23,0.80)" }}
            >
              <button
                onClick={() => onReviewSign?.(alert)}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg
                           text-sm font-semibold transition-all active:scale-[0.98]"
                style={{
                  background: "rgba(6,182,212,0.12)",
                  border: "1px solid rgba(6,182,212,0.40)",
                  color: "#67e8f9",
                }}
              >
                <Zap className="w-3.5 h-3.5" />
                Review &amp; Sign (STARK + FIDO2)
              </button>
              <p className="text-center text-[10px] text-slate-700 mt-1.5 font-mono">
                Generates zk-STARK receipt · then FIDO2 sign-off
              </p>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}

function StatCell({ label, value }: { label: string; value: string }) {
  return (
    <div
      className="rounded-lg p-3"
      style={{ background: "rgba(255,255,255,0.025)", border: "1px solid rgba(255,255,255,0.06)" }}
    >
      <p className="text-[9px] uppercase tracking-widest text-slate-600 mb-1">{label}</p>
      <p className="font-mono text-[11px] text-slate-300 truncate">{value}</p>
    </div>
  );
}
