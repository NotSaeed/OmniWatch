import type { CisoPipelineSummary, DashboardStats } from "../lib/types";

interface Props {
  stats:        DashboardStats | undefined;
  pipelineCiso: CisoPipelineSummary | undefined;
}

type Theme = "neutral" | "red" | "amber" | "green" | "cyan";

const THEME: Record<Theme, { accent: string; value: string; label: string }> = {
  neutral: { accent: "#6b6e80", value: "#c5c7d4", label: "#6b6e80" },
  red:     { accent: "#e84d4d", value: "#e84d4d", label: "#a33535" },
  amber:   { accent: "#f4a926", value: "#f4a926", label: "#a0700a" },
  green:   { accent: "#72c811", value: "#72c811", label: "#4a8510" },
  cyan:    { accent: "#00d4c8", value: "#00d4c8", label: "#008c86" },
};

function MetricCard({
  label, value, sub, theme, loading = false, maxValue, prefix = "", suffix = "",
}: {
  label: string; value: number; sub: string; theme: Theme;
  loading?: boolean; maxValue?: number; prefix?: string; suffix?: string;
}) {
  const t   = THEME[theme];
  const pct = maxValue && maxValue > 0 ? Math.min(100, (value / maxValue) * 100) : 0;

  return (
    <div
      className="relative overflow-hidden"
      style={{
        background: "#222429",
        border: `1px solid #2e3038`,
        borderTop: `2px solid ${t.accent}`,
        borderRadius: "4px",
        padding: "14px 16px 12px",
      }}
    >
      {/* Label */}
      <p className="text-[10px] uppercase tracking-widest mb-2 font-semibold" style={{ color: t.label }}>
        {label}
      </p>

      {/* Value */}
      {loading ? (
        <div className="h-9 w-24 rounded animate-pulse" style={{ background: "#2e3038" }} />
      ) : (
        <p
          className="text-3xl font-bold leading-none font-mono tabular-nums"
          style={{ color: t.value, letterSpacing: "-0.02em" }}
        >
          {prefix}{value.toLocaleString()}{suffix}
        </p>
      )}

      {/* Progress bar */}
      {!loading && maxValue && maxValue > 0 && (
        <div className="mt-3 h-0.5 rounded-full" style={{ background: "#2e3038" }}>
          <div
            className="h-full rounded-full transition-all duration-700"
            style={{ width: `${pct}%`, background: t.accent, opacity: 0.7 }}
          />
        </div>
      )}

      {/* Sub-text */}
      <p className="text-[11px] mt-2 truncate" style={{ color: "#6b6e80" }}>{sub}</p>
    </div>
  );
}

export function StatsCards({ stats, pipelineCiso }: Props) {
  const loading = !stats;

  const total      = stats?.total_events      ?? 0;
  const critical   = stats?.critical_events   ?? 0;
  const suspicious = stats?.suspicious_events ?? 0;
  const benign     = stats?.benign_events     ?? 0;

  // Merge pipeline CISO values: pipeline and CIC-IDS cover different datasets,
  // so the totals are additive.  Pipeline values dominate when they are non-zero.
  const hours = (stats?.hours_saved    ?? 0) + (pipelineCiso?.analyst_hours_saved ?? 0);
  const cost  = (stats?.cost_saved     ?? 0) + (pipelineCiso?.cost_avoided_usd    ?? 0);

  const pipelineFlows   = 0;  // rows_processed lives in PipelineCompletion, not ciso
  const pipelineCrit    = pipelineCiso?.by_severity?.CRITICAL ?? 0;
  const combinedTotal   = total + pipelineFlows;
  const combinedCrit    = critical + pipelineCrit;
  const combinedSusp    = suspicious + (pipelineCiso?.by_severity?.HIGH ?? 0);

  const attackPct = total > 0 ? ((combinedCrit + combinedSusp) / (total || 1) * 100).toFixed(1) : "0.0";
  const benignPct = total > 0 ? (benign / total * 100).toFixed(1) : "0.0";

  const hoursSub = pipelineCiso
    ? `${pipelineCiso.analyst_hours_saved.toFixed(1)} h pipeline + ${(stats?.hours_saved ?? 0)} h CIC-IDS`
    : `${stats?.by_severity?.CRITICAL ?? 0} critical × 0.75 h`;

  const costSub = pipelineCiso
    ? `$${pipelineCiso.cost_avoided_usd.toLocaleString()} pipeline avoided`
    : "@ $50/hr SOC analyst rate";

  return (
    <div className="px-3 py-2.5" style={{ background: "#1a1b1f", borderBottom: "1px solid #2e3038" }}>
      <div className="grid grid-cols-5 gap-2.5">
        <MetricCard
          label="Flows Processed"
          value={combinedTotal || total}
          sub={`${benignPct}% benign · ${benign.toLocaleString()} clean`}
          theme="neutral"
          loading={loading}
        />
        <MetricCard
          label="Critical Threats"
          value={combinedCrit}
          sub={`${attackPct}% of all traffic`}
          theme="red"
          maxValue={combinedTotal || total || 1}
          loading={loading}
        />
        <MetricCard
          label="Suspicious Activity"
          value={combinedSusp}
          sub="HIGH + MEDIUM severity"
          theme="amber"
          maxValue={combinedTotal || total || 1}
          loading={loading}
        />
        <MetricCard
          label="Analyst Hours Saved"
          value={Math.round(hours)}
          suffix=" hrs"
          sub={hoursSub}
          theme="green"
          loading={loading}
        />
        <MetricCard
          label="Cost Avoided"
          value={cost}
          prefix="$"
          sub={costSub}
          theme="cyan"
          loading={loading}
        />
      </div>
    </div>
  );
}
