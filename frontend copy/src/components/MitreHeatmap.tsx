import type { Alert, CicidsStats } from "../lib/types";

// CIC-IDS-2017 label → MITRE technique IDs
const LABEL_MITRE: Record<string, string[]> = {
  "DoS Hulk":                           ["T1498", "T1499"],
  "DoS GoldenEye":                      ["T1498", "T1499"],
  "DoS slowloris":                      ["T1498.001", "T1499.001"],
  "DoS Slowhttptest":                   ["T1498.001", "T1499.001"],
  "DDoS":                               ["T1498", "T1499.002"],
  "PortScan":                           ["T1046"],
  "FTP-Patator":                        ["T1110.001"],
  "SSH-Patator":                        ["T1110.001", "T1021.004"],
  "Bot":                                ["T1071.001", "T1543", "T1041"],
  "Web Attack \u2013 Brute Force":      ["T1110.001", "T1078"],
  "Web Attack - Brute Force":           ["T1110.001", "T1078"],
  "Web Attack \u2013 XSS":             ["T1059.007", "T1189"],
  "Web Attack - XSS":                   ["T1059.007", "T1189"],
  "Web Attack \u2013 Sql Injection":    ["T1190", "T1059.004"],
  "Web Attack - Sql Injection":         ["T1190", "T1059.004"],
  "Infiltration":                       ["T1041", "T1048", "T1071"],
  "Heartbleed":                         ["T1190", "T1552"],
};

interface Props {
  alerts: Alert[];
  cicidsStats?: CicidsStats;
}

export function MitreHeatmap({ alerts, cicidsStats }: Props) {
  const freq = new Map<string, number>();

  // Primary: count from AI alerts
  for (const a of alerts) {
    for (const t of a.mitre_techniques ?? []) {
      freq.set(t, (freq.get(t) ?? 0) + 1);
    }
  }

  // Fallback: derive from CIC-IDS label counts when no AI alerts have MITRE data
  if (freq.size === 0 && cicidsStats?.by_label) {
    for (const [label, count] of Object.entries(cicidsStats.by_label)) {
      const techniques = LABEL_MITRE[label];
      if (!techniques) continue;
      for (const tid of techniques) {
        freq.set(tid, (freq.get(tid) ?? 0) + count);
      }
    }
  }

  const entries = [...freq.entries()].sort((a, b) => b[1] - a[1]).slice(0, 24);

  if (entries.length === 0) {
    return (
      <div className="flex items-center justify-center h-24 text-sm" style={{ color: "#4d5060" }}>
        No MITRE data yet
      </div>
    );
  }

  const maxCount = entries[0][1];
  const isCicids = alerts.every(a => (a.mitre_techniques ?? []).length === 0) && freq.size > 0;

  return (
    <div>
      {isCicids && (
        <p className="text-[10px] mb-2" style={{ color: "#4d5060" }}>
          Derived from ingested telemetry · {entries.length} techniques mapped
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        {entries.map(([tid, count]) => {
          const intensity = count / maxCount;
          const bg = `rgba(239,68,68,${0.12 + intensity * 0.55})`;
          return (
            <div
              key={tid}
              title={`${tid} — ${count.toLocaleString()} event${count !== 1 ? "s" : ""}`}
              className="px-2 py-1 rounded text-xs font-mono cursor-default"
              style={{
                background:  bg,
                border:      "1px solid rgba(239,68,68,0.2)",
                color:       intensity > 0.5 ? "#fecaca" : "#fca5a5",
              }}
            >
              {tid}
              <span className="ml-1 opacity-60">×{count.toLocaleString()}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
