import type { DashboardStats } from "../lib/types";
import { formatTime } from "../lib/utils";

interface Props {
  stats: DashboardStats | undefined;
}

export function StatsBar({ stats }: Props) {
  const critical = stats?.by_severity?.CRITICAL ?? 0;
  const high     = stats?.by_severity?.HIGH     ?? 0;

  return (
    <div
      className="flex flex-wrap items-center gap-2 px-4 py-2"
      style={{ background: "#1a1b1f", borderBottom: "1px solid #2e3038" }}
    >
      <Kpi label="AI Alerts"   value={stats?.total_alerts ?? 0} />
      <Kpi label="Critical"    value={critical} colour={critical > 0 ? "#e84d4d" : undefined} />
      <Kpi label="High"        value={high}     colour={high > 0 ? "#f4a926" : undefined} />
      <Kpi label="Scans"       value={stats?.total_scans ?? 0} />
      {stats?.last_scan_at && (
        <Kpi label="Last Scan" value={formatTime(stats.last_scan_at)} />
      )}
    </div>
  );
}

function Kpi({ label, value, colour }: {
  label: string; value: number | string; colour?: string;
}) {
  return (
    <div
      className="flex items-center gap-2 px-2.5 py-1 rounded"
      style={{ background: "#222429", border: "1px solid #2e3038" }}
    >
      <span
        className="text-sm font-bold font-mono tabular-nums"
        style={{ color: colour ?? "#c5c7d4" }}
      >
        {value}
      </span>
      <span className="text-[10px] uppercase tracking-wider" style={{ color: "#6b6e80" }}>
        {label}
      </span>
    </div>
  );
}
