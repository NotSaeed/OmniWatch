import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { CisoPipelineSummary } from "../lib/types";

const DETECTOR_COLORS: Record<string, string> = {
  "LODA":      "bg-violet-900/40 text-violet-300 border-violet-700/40",
  "DDSketch":  "bg-cyan-900/40 text-cyan-300 border-cyan-700/40",
  "CUSUM":     "bg-emerald-900/40 text-emerald-300 border-emerald-700/40",
  "Port":      "bg-orange-900/40 text-orange-300 border-orange-700/40",
  "Volume":    "bg-red-900/40 text-red-300 border-red-700/40",
  "Label-KW":  "bg-yellow-900/40 text-yellow-300 border-yellow-700/40",
  "Time-Win":  "bg-blue-900/40 text-blue-300 border-blue-700/40",
  "Heuristic": "bg-slate-800/60 text-slate-400 border-slate-700/40",
};

export function TopThreatSourcesPanel({
  sessionId,
  pipelineCiso,
  onIpClick,
}: {
  sessionId?:    string;
  pipelineCiso?: CisoPipelineSummary;
  onIpClick?:    (ip: string) => void;
}) {
  const { data: liveTopIps } = useQuery({
    queryKey:        ["pipeline-top-ips", sessionId],
    queryFn:         () => api.getTopIps(sessionId!),
    enabled:         !!sessionId,
    staleTime:       60_000,
    refetchInterval: 60_000,
  });

  const ips = (liveTopIps && liveTopIps.length > 0)
    ? liveTopIps
    : (pipelineCiso?.top_attacker_ips ?? []);

  if (ips.length === 0) {
    return (
      <div
        className="flex items-center justify-center h-full text-xs px-4 text-center"
        style={{ color: "#4d5060" }}
      >
        No threat sources — upload a CSV to populate
      </div>
    );
  }

  const max = Math.max(1, ...ips.map(d => d.count));

  return (
    <div className="py-1">
      {ips.map((d) => {
        const pct  = Math.round((d.count / max) * 100);
        const rule = d.dominant_rule ?? "Heuristic";
        const colorClass = DETECTOR_COLORS[rule] ?? DETECTOR_COLORS["Heuristic"];
        return (
          <div
            key={d.ip}
            className="flex items-center gap-2 px-3 py-1.5 border-b border-white/5 hover:bg-white/[0.02]"
          >
            <span
              className={`font-mono text-[11px] flex-1 truncate ${onIpClick ? "cursor-pointer text-cyan-400 hover:text-cyan-300 hover:underline underline-offset-2" : "text-slate-300"}`}
              title={onIpClick ? `Hunt logs for ${d.ip}` : d.ip}
              onClick={() => onIpClick?.(d.ip)}
            >{d.ip}</span>
            <div className="w-20 h-1 rounded-full bg-slate-800 shrink-0">
              <div className="h-full rounded-full bg-cyan-500" style={{ width: `${pct}%` }} />
            </div>
            <span className="font-mono text-[10px] text-slate-500 tabular-nums w-10 text-right shrink-0">
              {d.count.toLocaleString()}
            </span>
            <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold border shrink-0 ${colorClass}`}>
              {rule}
            </span>
          </div>
        );
      })}
    </div>
  );
}
