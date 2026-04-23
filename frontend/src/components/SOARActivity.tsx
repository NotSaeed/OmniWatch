/**
 * SOARActivity — compact live event stream.
 *
 * Renders each CIC-IDS-2017 playbook execution as a single dense row.
 * Merges live WebSocket entries with DB-persisted history (deduplicated).
 * Designed to sit below PlaybookTimeline as a scrollable audit log.
 */

import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { CicidsPlaybookLog } from "../lib/types";

// ── Playbook metadata ─────────────────────────────────────────────────────────

interface PbMeta { color: string; abbrev: string; }

const PLAYBOOK_META: Record<string, PbMeta> = {
  Block_IP_Playbook:       { color: "#e84d4d", abbrev: "BLOCK"   },
  Isolate_Host_Playbook:   { color: "#f4a926", abbrev: "ISOLATE" },
  C2_Containment_Playbook: { color: "#e040fb", abbrev: "C2-CTN"  },
  Rate_Limit_Playbook:     { color: "#4e9af1", abbrev: "RLIMIT"  },
  Lock_Account_Playbook:   { color: "#00d4c8", abbrev: "LOCKACT" },
};
const DEFAULT_META: PbMeta = { color: "#6b6e80", abbrev: "PLAYBOOK" };

function meta(name: string): PbMeta {
  return PLAYBOOK_META[name] ?? DEFAULT_META;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function timeAgo(iso: string): string {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60)  return `${s}s`;
  const m = Math.floor(s / 60);
  return m < 60 ? `${m}m` : `${Math.floor(m / 60)}h`;
}

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#e84d4d", HIGH: "#f4a926", MEDIUM: "#e0c020",
  LOW: "#72c811", INFO: "#6b6e80",
};

// ── Row ───────────────────────────────────────────────────────────────────────

function EventRow({ entry, index }: { entry: CicidsPlaybookLog; index: number }) {
  const m        = meta(entry.playbook_name);
  const sevColor = SEV_COLOR[entry.severity] ?? "#6b6e80";

  return (
    <div
      className="node-appear flex items-center gap-3 px-3 py-2 group transition-colors"
      style={{
        animationDelay: `${index * 25}ms`,
        borderBottom: "1px solid #2e3038",
        background: index % 2 === 0 ? "transparent" : "rgba(255,255,255,0.008)",
      }}
    >
      {/* Accent dot */}
      <div
        className="w-1.5 h-1.5 rounded-full shrink-0 anim-glow"
        style={{ background: m.color }}
      />

      {/* Playbook abbrev badge */}
      <span
        className="shrink-0 font-mono text-[9px] font-bold tracking-wider px-1.5 py-0.5 rounded"
        style={{
          background: `${m.color}15`,
          border: `1px solid ${m.color}35`,
          color: m.color,
          minWidth: "54px",
          textAlign: "center",
        }}
      >
        {m.abbrev}
      </span>

      {/* Target IP */}
      <span
        className="font-mono text-[11px] shrink-0 tabular-nums"
        style={{ color: entry.target_ip ? "#c5c7d4" : "#4d5060", minWidth: "100px" }}
      >
        {entry.target_ip ?? "—"}
      </span>

      {/* Severity */}
      <span
        className="shrink-0 text-[9px] font-bold uppercase px-1 py-0.5 rounded"
        style={{ background: `${sevColor}12`, color: sevColor, minWidth: "52px", textAlign: "center" }}
      >
        {entry.severity}
      </span>

      {/* Label */}
      <span
        className="flex-1 text-[11px] font-mono truncate"
        style={{ color: "#8b8fa8" }}
        title={entry.label}
      >
        {entry.label}
      </span>

      {/* Action summary */}
      <span
        className="shrink-0 text-[10px] truncate max-w-[160px]"
        style={{ color: "#6b6e80" }}
        title={entry.action}
      >
        {entry.action}
      </span>

      {/* Status badge */}
      <span
        className="shrink-0 text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
        style={
          entry.status === "PENDING_AUTHORIZATION"
            ? { background: "rgba(245,158,11,0.10)", border: "1px solid rgba(245,158,11,0.35)", color: "#f59e0b" }
            : entry.status === "SUCCESS"
            ? { background: "rgba(16,185,129,0.10)", border: "1px solid rgba(16,185,129,0.35)", color: "#10b981" }
            : entry.status === "FAILED"
            ? { background: "rgba(239,68,68,0.10)", border: "1px solid rgba(239,68,68,0.35)", color: "#ef4444" }
            : { background: "rgba(107,110,128,0.10)", border: "1px solid rgba(107,110,128,0.25)", color: "#6b6e80" }
        }
      >
        {entry.status === "PENDING_AUTHORIZATION" ? "PENDING" : entry.status}
      </span>

      {/* Time */}
      <span className="font-mono text-[10px] shrink-0 tabular-nums" style={{ color: "#4d5060" }}>
        {timeAgo(entry.executed_at)}
      </span>
    </div>
  );
}

// ── Header row ────────────────────────────────────────────────────────────────

function TableHeader() {
  const cols = ["", "Playbook", "Target IP", "Severity", "Attack Label", "Action", "Enforcement", "Age"];
  return (
    <div
      className="sticky top-0 z-10 flex items-center gap-3 px-3 py-1.5"
      style={{ background: "#1a1b1f", borderBottom: "1px solid #2e3038" }}
    >
      <div className="w-1.5 shrink-0" />
      {cols.slice(1).map((col, i) => (
        <span
          key={i}
          className={`text-[9px] uppercase tracking-wider font-semibold ${
            i === 0 ? "min-w-[54px]" :
            i === 1 ? "min-w-[100px]" :
            i === 2 ? "min-w-[52px]" :
            i === 3 ? "flex-1" :
            i === 4 ? "max-w-[200px] shrink-0" :
            i === 5 ? "shrink-0" :
            "shrink-0"
          }`}
          style={{ color: "#4d5060" }}
        >
          {col}
        </span>
      ))}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

interface Props { liveEntries: CicidsPlaybookLog[] }

export function SOARActivity({ liveEntries }: Props) {
  const { data: persisted = [] } = useQuery({
    queryKey:        ["cicids-playbook-logs"],
    queryFn:         () => api.getCicidsPlaybookLogs(50),
    refetchInterval: 30_000,
  });

  // Deduplicate by id — live WS entries take precedence (listed first)
  const seen = new Set<number>();
  const merged: CicidsPlaybookLog[] = [];
  for (const e of [...liveEntries, ...persisted]) {
    if (!seen.has(e.id)) { seen.add(e.id); merged.push(e); }
  }
  const entries = merged.slice(0, 100);

  if (entries.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-center" style={{ color: "#4d5060" }}>
        <p className="text-xs font-semibold" style={{ color: "#6b6e80" }}>Audit log is empty</p>
        <p className="text-[11px] mt-1">SOAR actions will appear here as they execute</p>
      </div>
    );
  }

  return (
    <div>
      {/* Summary strip */}
      <div
        className="flex items-center gap-4 px-3 py-2"
        style={{ background: "#222429", borderBottom: "1px solid #2e3038" }}
      >
        <span className="text-[10px] font-mono tabular-nums" style={{ color: "#6b6e80" }}>
          <span className="text-white font-semibold">{entries.length}</span> executions logged
        </span>
        {/* Per-playbook counts */}
        {Object.entries(PLAYBOOK_META).map(([name, m]) => {
          const count = entries.filter(e => e.playbook_name === name).length;
          if (!count) return null;
          return (
            <span key={name} className="flex items-center gap-1 text-[9px]" style={{ color: m.color }}>
              <span className="w-1.5 h-1.5 rounded-full" style={{ background: m.color }} />
              {m.abbrev} <span className="font-bold tabular-nums">{count}</span>
            </span>
          );
        })}
        <span className="ml-auto text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
              style={{ background: "rgba(114,200,17,0.08)", border: "1px solid rgba(114,200,17,0.25)", color: "#72c811" }}>
          Live · PAN-OS
        </span>
      </div>

      <TableHeader />

      <div className="max-h-56 overflow-y-auto">
        {entries.map((e, i) => <EventRow key={e.id} entry={e} index={i} />)}
      </div>
    </div>
  );
}
