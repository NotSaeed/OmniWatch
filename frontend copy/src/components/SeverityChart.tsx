import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { CicidsStats, DashboardStats, Severity } from "../lib/types";
import { SEVERITY_COLORS } from "../lib/utils";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

interface Props {
  stats: DashboardStats | undefined;
  cicidsStats: CicidsStats | undefined;
}

export function SeverityChart({ stats, cicidsStats }: Props) {
  // Prefer AI alert counts; fall back to CIC-IDS severity counts
  const aiTotal = SEVERITIES.reduce((s, k) => s + (stats?.by_severity?.[k] ?? 0), 0);
  const source  = aiTotal > 0 ? "ai" : "cicids";

  const data = SEVERITIES
    .map(s => ({
      name:  s,
      value: source === "ai"
        ? (stats?.by_severity?.[s] ?? 0)
        : (cicidsStats?.by_severity?.[s] ?? 0),
    }))
    .filter(d => d.value > 0);

  const subtitle = source === "cicids" && data.length > 0 ? "Network telemetry" : "AI alerts";

  if (data.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-40 gap-2">
        <div className="text-2xl opacity-20">◯</div>
        <p className="text-xs" style={{ color: "#4d5060" }}>No data yet</p>
      </div>
    );
  }

  const total = data.reduce((s, d) => s + d.value, 0);

  return (
    <div className="relative">
      <ResponsiveContainer width="100%" height={180}>
        <PieChart>
          <Pie
            data={data}
            cx="50%" cy="50%"
            innerRadius={52} outerRadius={78}
            paddingAngle={3}
            dataKey="value"
            strokeWidth={0}
          >
            {data.map(entry => (
              <Cell
                key={entry.name}
                fill={SEVERITY_COLORS[entry.name as Severity]}
                opacity={0.85}
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: "#1e1f23",
              border: "1px solid #2e3038",
              borderRadius: 4,
              fontSize: 11,
              color: "#c5c7d4",
            }}
            formatter={(value: number, name: string) => [
              value.toLocaleString(),
              name,
            ]}
          />
        </PieChart>
      </ResponsiveContainer>

      {/* Center label */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className="text-xl font-bold font-mono tabular-nums" style={{ color: "#c5c7d4" }}>
          {total.toLocaleString()}
        </span>
        <span className="text-[9px] uppercase tracking-widest mt-0.5" style={{ color: "#4d5060" }}>
          {subtitle}
        </span>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap justify-center gap-x-3 gap-y-1 mt-1">
        {data.map(entry => (
          <div key={entry.name} className="flex items-center gap-1">
            <span
              className="w-2 h-2 rounded-full shrink-0"
              style={{ background: SEVERITY_COLORS[entry.name as Severity] }}
            />
            <span className="text-[10px]" style={{ color: "#6b6e80" }}>{entry.name}</span>
            <span className="text-[10px] font-mono tabular-nums" style={{ color: "#8b8fa8" }}>
              {entry.value.toLocaleString()}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
