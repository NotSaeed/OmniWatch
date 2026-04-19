import { useQuery } from "@tanstack/react-query";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../lib/api";

const SOURCE_COLORS: Record<string, string> = {
  suricata:       "#ef4444",
  sysmon:         "#f97316",
  xmlwineventlog: "#eab308",
  wineventlog:    "#eab308",
  "pan:traffic":  "#8b5cf6",
  "pan:threat":   "#a78bfa",
  "stream:http":  "#06b6d4",
  "bro:conn":     "#10b981",
  "zeek:conn":    "#10b981",
  osquery:        "#6366f1",
};

export function DatasetSourceBreakdown() {
  const { data } = useQuery({
    queryKey:        ["dataset-stats"],
    queryFn:         api.getDatasetStats,
    refetchInterval: 30_000,
  });

  const chartData = Object.entries(data?.by_sourcetype ?? {})
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));

  if (chartData.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-2 h-24">
        <span className="text-2xl opacity-20">📊</span>
        <p className="text-xs text-slate-600">No dataset loaded</p>
        <p className="text-[10px] text-slate-700">Use /api/ingest to load BOTSv3</p>
      </div>
    );
  }

  return (
    <div>
      <div className="text-[10px] text-slate-600 font-mono mb-2 tabular-nums">
        {data?.total_events?.toLocaleString() ?? 0} total events across {chartData.length} sources
      </div>
      <ResponsiveContainer width="100%" height={140}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 4, right: 4 }}>
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="name"
            tick={{ fontSize: 10, fill: "#64748b", fontFamily: "JetBrains Mono, monospace" }}
            width={88}
          />
          <Tooltip
            contentStyle={{
              background: "rgba(10,16,30,0.96)",
              border: "1px solid rgba(51,65,85,0.5)",
              borderRadius: 8,
              backdropFilter: "blur(12px)",
              fontSize: 11,
              color: "#cbd5e1",
            }}
            cursor={{ fill: "rgba(51,65,85,0.2)" }}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={14}>
            {chartData.map(entry => (
              <Cell
                key={entry.name}
                fill={SOURCE_COLORS[entry.name] ?? "#475569"}
                opacity={0.8}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
