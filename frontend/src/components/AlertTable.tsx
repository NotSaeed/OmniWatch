import { useState } from "react";
import type { Alert } from "../lib/types";
import { CATEGORY_LABELS, SEVERITY_BG, formatConfidence, formatTime } from "../lib/utils";

interface Props {
  alerts:          Alert[];
  onSelectAlert:   (alert: Alert) => void;
  selectedAlertId: string | null;
}

type SortKey = "timestamp" | "severity" | "confidence";
const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
};

const ROW_GLOW: Record<string, string> = {
  CRITICAL: "hover:shadow-[inset_0_0_20px_rgba(239,68,68,0.06)]",
  HIGH:     "hover:shadow-[inset_0_0_20px_rgba(249,115,22,0.05)]",
  MEDIUM:   "",
  LOW:      "",
  INFO:     "",
};

export function AlertTable({ alerts, onSelectAlert, selectedAlertId }: Props) {
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [sortAsc, setSortAsc] = useState(false);

  function toggleSort(key: SortKey) {
    if (sortKey === key) setSortAsc(v => !v);
    else { setSortKey(key); setSortAsc(false); }
  }

  const sorted = [...alerts].sort((a, b) => {
    let cmp = 0;
    if (sortKey === "timestamp")  cmp = a.timestamp.localeCompare(b.timestamp);
    if (sortKey === "severity")   cmp = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sortKey === "confidence") cmp = a.confidence - b.confidence;
    return sortAsc ? cmp : -cmp;
  });

  return (
    <div className="overflow-auto rounded-xl border border-slate-800/50"
         style={{ background: "rgba(2,8,23,0.40)" }}>
      <table className="w-full text-xs text-left border-collapse">
        <thead className="sticky top-0 z-10">
          <tr className="border-b border-slate-800/60"
              style={{ background: "rgba(10,16,30,0.95)", backdropFilter: "blur(8px)" }}>
            <Th label="Time"       sortKey="timestamp"  current={sortKey} asc={sortAsc} onSort={toggleSort} />
            <Th label="Severity"   sortKey="severity"   current={sortKey} asc={sortAsc} onSort={toggleSort} />
            <th className="px-3 py-2.5 text-[10px] uppercase tracking-wider text-slate-500 font-medium">Category</th>
            <th className="px-3 py-2.5 text-[10px] uppercase tracking-wider text-slate-500 font-medium">Source IP</th>
            <th className="px-3 py-2.5 text-[10px] uppercase tracking-wider text-slate-500 font-medium">Asset</th>
            <th className="px-3 py-2.5 text-[10px] uppercase tracking-wider text-slate-500 font-medium">MITRE</th>
            <Th label="Conf."      sortKey="confidence" current={sortKey} asc={sortAsc} onSort={toggleSort} />
            <th className="px-3 py-2.5 text-[10px] uppercase tracking-wider text-slate-500 font-medium">Playbook</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((alert, i) => {
            const isSelected = selectedAlertId === alert.alert_id;
            const rowGlow    = ROW_GLOW[alert.severity] ?? "";
            return (
              <tr
                key={alert.alert_id}
                onClick={() => onSelectAlert(alert)}
                className={`border-t border-slate-800/40 cursor-pointer transition-all duration-150 ${rowGlow} ${
                  isSelected
                    ? "bg-cyan-900/20 border-l-2 border-l-cyan-500"
                    : "hover:bg-slate-800/30"
                } ${i % 2 === 0 ? "" : "bg-slate-950/20"}`}
              >
                <td className="px-3 py-2 font-mono text-slate-500 text-[11px] whitespace-nowrap">
                  {formatTime(alert.timestamp)}
                </td>
                <td className="px-3 py-2">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide ${SEVERITY_BG[alert.severity]}`}>
                    {alert.severity}
                  </span>
                </td>
                <td className="px-3 py-2 text-slate-300 text-[11px]">
                  {CATEGORY_LABELS[alert.category] ?? alert.category}
                </td>
                <td className="px-3 py-2 font-mono text-cyan-400 text-[11px]">
                  {alert.source_ip ?? <span className="text-slate-700">—</span>}
                </td>
                <td className="px-3 py-2 text-slate-400 text-[11px] max-w-[120px] truncate">
                  {alert.affected_asset ?? <span className="text-slate-700">—</span>}
                </td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap gap-1">
                    {(alert.mitre_techniques ?? []).slice(0, 2).map(t => (
                      <span
                        key={t}
                        className="px-1.5 py-0.5 rounded bg-violet-950/60 text-violet-300 font-mono text-[9px] border border-violet-800/40"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-3 py-2 font-mono text-[11px] text-slate-400 tabular-nums">
                  {formatConfidence(alert.confidence)}
                </td>
                <td className="px-3 py-2">
                  {alert.playbook_triggered ? (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-950/50 text-emerald-400 text-[10px] border border-emerald-800/40">
                      <span className="w-1 h-1 rounded-full bg-emerald-400 shrink-0" />
                      {alert.playbook_triggered.replace("_Playbook", "")}
                    </span>
                  ) : <span className="text-slate-700">—</span>}
                </td>
              </tr>
            );
          })}
          {sorted.length === 0 && (
            <tr>
              <td colSpan={8} className="px-4 py-12 text-center">
                <div className="flex flex-col items-center gap-2 text-slate-600">
                  <span className="text-3xl">📡</span>
                  <p className="text-sm">No alerts yet — run a scan to populate the feed</p>
                </div>
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function Th({
  label, sortKey, current, asc, onSort,
}: {
  label: string; sortKey: SortKey; current: SortKey; asc: boolean;
  onSort: (k: SortKey) => void;
}) {
  const active = sortKey === current;
  return (
    <th
      className={`px-3 py-2.5 text-[10px] uppercase tracking-wider font-medium cursor-pointer select-none
                  transition-colors hover:text-slate-300
                  ${active ? "text-cyan-400" : "text-slate-500"}`}
      onClick={() => onSort(sortKey)}
    >
      {label}{active && <span className="ml-1 opacity-70">{asc ? "↑" : "↓"}</span>}
    </th>
  );
}
