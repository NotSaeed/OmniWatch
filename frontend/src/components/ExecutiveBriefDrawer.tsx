import { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, FileText } from "lucide-react";
import type { CicidsStats, CisoPipelineSummary } from "../lib/types";

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#e84d4d",
  HIGH:     "#f4a926",
  MEDIUM:   "#facc15",
  LOW:      "#72c811",
  INFO:     "#4e9af1",
};

export function ExecutiveBriefDrawer({
  open, onClose, pipelineCiso, cicidsStats,
}: {
  open:          boolean;
  onClose:       () => void;
  pipelineCiso?: CisoPipelineSummary;
  cicidsStats?:  CicidsStats;
}) {
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) { if (e.key === "Escape") onClose(); }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const bySev = pipelineCiso?.by_severity ?? cicidsStats?.by_severity ?? {};
  const sevEntries = Object.entries(bySev)
    .filter(([, v]) => (v as number) > 0)
    .sort((a, b) => (b[1] as number) - (a[1] as number));
  const total  = pipelineCiso?.total_alerts ?? cicidsStats?.total ?? 0;
  const maxSev = Math.max(1, ...sevEntries.map(([, v]) => v as number));

  const techniques = pipelineCiso?.top_techniques ?? [];
  const labels     = pipelineCiso?.top_labels     ?? [];
  const hours      = pipelineCiso?.analyst_hours_saved ?? 0;

  return (
    <AnimatePresence>
      {open && (
        <>
          <div
            className="fixed inset-0 z-[39] pointer-events-none"
            style={{ background: "rgba(0,0,0,0.18)" }}
          />
          <motion.div
            key="exec-brief-drawer"
            initial={{ x: "100%", opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: "100%", opacity: 0 }}
            transition={{ type: "spring", stiffness: 300, damping: 30 }}
            className="fixed right-0 top-0 h-screen w-[420px] z-40 flex flex-col overflow-hidden"
            style={{
              background:     "var(--slideover-bg, rgba(7,14,26,0.97))",
              borderLeft:     "1px solid var(--slideover-border, rgba(21,33,48,0.90))",
              backdropFilter: "blur(20px)",
            }}
          >
            {/* Header */}
            <div
              className="flex items-center justify-between px-5 py-3.5 shrink-0 border-b border-white/5"
              style={{ background: "rgba(2,8,23,0.80)" }}
            >
              <div className="flex items-center gap-2.5">
                <FileText className="w-4 h-4 text-fuchsia-400 shrink-0" />
                <span className="text-sm font-semibold text-slate-100">AI Executive Brief</span>
              </div>
              <button
                onClick={onClose}
                title="Close (Escape)"
                className="w-7 h-7 flex items-center justify-center rounded-lg text-slate-500
                           hover:text-slate-200 bg-slate-800/60 hover:bg-slate-700/60
                           border border-slate-700/50 active:scale-95 transition-all"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto">
              <div className="p-5 space-y-5">

                {/* Total events KPI */}
                <div
                  className="rounded-lg p-4"
                  style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)" }}
                >
                  <p className="text-[10px] uppercase tracking-widest text-slate-600 mb-1 font-semibold">
                    Session Total
                  </p>
                  <p className="text-3xl font-bold font-mono tabular-nums" style={{ color: "#4e9af1" }}>
                    {total.toLocaleString()}
                  </p>
                  <p className="text-[10px] text-slate-600 mt-1">threat events detected</p>
                </div>

                {/* Severity breakdown */}
                {sevEntries.length > 0 && (
                  <div>
                    <p className="text-[10px] uppercase tracking-widest text-slate-600 mb-2.5 font-semibold">
                      Severity Breakdown
                    </p>
                    <div className="space-y-2">
                      {sevEntries.map(([sev, cnt]) => {
                        const color = SEV_COLORS[sev] ?? "#6b6e80";
                        const pct   = Math.round(((cnt as number) / maxSev) * 100);
                        return (
                          <div key={sev} className="flex items-center gap-2">
                            <span className="font-mono text-[10px] w-16 shrink-0" style={{ color }}>{sev}</span>
                            <div className="flex-1 h-1.5 rounded-full bg-slate-800">
                              <div
                                className="h-full rounded-full transition-all"
                                style={{ width: `${pct}%`, background: color }}
                              />
                            </div>
                            <span className="font-mono text-[10px] text-slate-500 tabular-nums w-14 text-right">
                              {(cnt as number).toLocaleString()}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Top MITRE techniques */}
                {techniques.length > 0 && (
                  <div>
                    <p className="text-[10px] uppercase tracking-widest text-slate-600 mb-2 font-semibold">
                      Top MITRE Techniques
                    </p>
                    <div className="space-y-0">
                      {techniques.slice(0, 6).map(t => (
                        <div key={t.id ?? t.name} className="flex items-center gap-2 py-1.5 border-b border-white/5">
                          <span className="font-mono text-[10px] text-violet-400 shrink-0 w-16 truncate">{t.id ?? "—"}</span>
                          <span className="text-[11px] text-slate-300 flex-1 truncate">{t.name}</span>
                          <span className="font-mono text-[10px] text-slate-600 tabular-nums shrink-0">
                            {t.count.toLocaleString()}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Top attack labels */}
                {labels.length > 0 && (
                  <div>
                    <p className="text-[10px] uppercase tracking-widest text-slate-600 mb-2 font-semibold">
                      Top Attack Labels
                    </p>
                    <div className="space-y-0">
                      {labels.slice(0, 6).map(l => (
                        <div key={l.label} className="flex items-center justify-between py-1.5 border-b border-white/5">
                          <span className="text-[11px] font-mono text-slate-300 truncate flex-1">{l.label}</span>
                          <span className="font-mono text-[10px] text-slate-600 tabular-nums ml-3 shrink-0">
                            {l.count.toLocaleString()}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Analyst time saved */}
                {hours > 0 && (
                  <div
                    className="rounded-lg p-4"
                    style={{ background: "rgba(114,200,17,0.06)", border: "1px solid rgba(114,200,17,0.20)" }}
                  >
                    <p
                      className="text-[10px] uppercase tracking-widest font-semibold mb-1"
                      style={{ color: "rgba(114,200,17,0.5)" }}
                    >
                      Analyst Time Saved
                    </p>
                    <p className="text-2xl font-bold font-mono" style={{ color: "#72c811" }}>
                      {hours.toFixed(1)}h
                    </p>
                    <p className="text-[10px] mt-1" style={{ color: "#4d5060" }}>
                      estimated from alert severity weighting
                    </p>
                  </div>
                )}

                {/* Empty state */}
                {total === 0 && (
                  <div className="flex flex-col items-center justify-center py-12 gap-2" style={{ color: "#4d5060" }}>
                    <FileText className="w-8 h-8 opacity-20" />
                    <p className="text-xs">No pipeline data — upload a CSV first</p>
                  </div>
                )}

              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
