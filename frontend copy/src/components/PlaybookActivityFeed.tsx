import type { PlaybookLogEntry } from "../lib/types";
import { formatTime } from "../lib/utils";

interface Props { entries: PlaybookLogEntry[] }

const STATUS_COLOR: Record<string, string> = {
  SIMULATED: "#72c811",
  ESCALATED: "#f4a926",
  SKIPPED:   "#6b6e80",
};

export function PlaybookActivityFeed({ entries }: Props) {
  if (entries.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-center" style={{ color: "#4d5060" }}>
        <p className="text-xs">No AI playbooks fired yet</p>
        <p className="text-[11px] mt-1">Trigger a scan to generate AI-triage alerts</p>
      </div>
    );
  }

  return (
    <div className="max-h-64 overflow-y-auto">
      {entries.map(entry => {
        const color = STATUS_COLOR[entry.status] ?? STATUS_COLOR.SKIPPED;
        return (
          <div
            key={entry.id}
            className="flex items-center gap-3 px-3 py-2"
            style={{ borderBottom: "1px solid #2e3038" }}
          >
            <div className="w-0.5 h-8 rounded-full shrink-0" style={{ background: color }} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[11px] font-medium text-white truncate">
                  {entry.playbook_name.replace("_", " ")}
                </span>
              </div>
              <p className="text-[10px] truncate" style={{ color: "#6b6e80" }}>{entry.simulated_action}</p>
            </div>
            <div className="flex flex-col items-end gap-0.5 shrink-0">
              <span
                className="text-[9px] px-1.5 py-0.5 rounded font-bold uppercase"
                style={{ background: `${color}18`, border: `1px solid ${color}40`, color }}
              >
                {entry.status}
              </span>
              <span className="font-mono text-[10px]" style={{ color: "#4d5060" }}>
                {formatTime(entry.executed_at)}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
