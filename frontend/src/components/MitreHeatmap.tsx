import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Alert, CicidsStats } from "../lib/types";

// CIC-IDS-2017 label → MITRE technique IDs (static fallback when no session is active)
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
  "Web Attack – Brute Force":      ["T1110.001", "T1078"],
  "Web Attack - Brute Force":           ["T1110.001", "T1078"],
  "Web Attack – XSS":             ["T1059.007", "T1189"],
  "Web Attack - XSS":                   ["T1059.007", "T1189"],
  "Web Attack – Sql Injection":    ["T1190", "T1059.004"],
  "Web Attack - Sql Injection":         ["T1190", "T1059.004"],
  "Infiltration":                       ["T1041", "T1048", "T1071"],
  "Heartbleed":                         ["T1190", "T1552"],
};

interface Props {
  alerts:        Alert[];
  cicidsStats?:  CicidsStats;
  botsTactics?:  any[];
  sessionId?:    string;
  onMitreClick?: (techniqueId: string) => void;
}

export function MitreHeatmap({ alerts, cicidsStats, botsTactics, sessionId, onMitreClick }: Props) {
  const { data: liveData } = useQuery({
    queryKey:  ["pipeline-mitre-stats", sessionId],
    queryFn:   () => api.getMitreStats(sessionId!),
    enabled:   !!sessionId,
    staleTime: 60_000,
  });

  // Source resolution: live DB → AI alert set → CIC-IDS label inference → BOTS fallback
  let entries: [string, number, string][] = []; // [id, count, name]
  let source: "live" | "ai" | "cicids" | "bots" = "ai";

  if (liveData && liveData.length > 0) {
    source = "live";
    entries = liveData.map(d => [d.technique_id, d.count, d.name]);
    // sort desc already from API, preserve order
  } else {
    const freq = new Map<string, number>();

    for (const a of alerts) {
      for (const t of a.mitre_techniques ?? []) {
        freq.set(t, (freq.get(t) ?? 0) + 1);
      }
    }

    if (freq.size === 0 && cicidsStats?.by_label) {
      source = "cicids";
      for (const [label, count] of Object.entries(cicidsStats.by_label)) {
        const techniques = LABEL_MITRE[label];
        if (!techniques) continue;
        for (const tid of techniques) {
          freq.set(tid, (freq.get(tid) ?? 0) + count);
        }
      }
    }

    if (freq.size === 0 && botsTactics) {
      source = "bots";
      const TACTIC_MAP: Record<string, string> = {
        "Initial Access":       "T1190",
        "Execution":            "T1059",
        "Discovery":            "T1046",
        "Command and Control":  "T1071",
        "Credential Access":    "T1110",
        "Lateral Movement":     "T1021",
      };
      for (const bt of botsTactics) {
        const tid = TACTIC_MAP[bt.tactic] || "T1000";
        freq.set(tid, (freq.get(tid) ?? 0) + bt.count);
      }
    }

    entries = [...freq.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([id, cnt]) => [id, cnt, id]);
  }

  if (entries.length === 0) {
    return (
      <div className="flex items-center justify-center h-24 text-sm" style={{ color: "#4d5060" }}>
        No MITRE data yet
      </div>
    );
  }

  const maxCount = entries[0][1];

  return (
    <div>
      <p className="text-[10px] mb-2" style={{ color: "#4d5060" }}>
        {source === "live"  && `Live DB · ${entries.length} technique${entries.length !== 1 ? "s" : ""} mapped`}
        {source === "cicids" && `Derived from ingested telemetry · ${entries.length} technique${entries.length !== 1 ? "s" : ""} mapped`}
        {source === "bots"   && `BOTSv3 tactics · ${entries.length} techniques`}
        {source === "ai"     && `AI alert correlation · ${entries.length} techniques`}
      </p>
      <div className="flex flex-wrap gap-2">
        {entries.map(([tid, count, name]) => {
          const intensity = count / maxCount;
          const bg = `rgba(239,68,68,${0.12 + intensity * 0.55})`;
          const label = name !== tid ? `${tid} · ${name}` : tid;
          return (
            <div
              key={tid}
              title={onMitreClick
                ? `Hunt logs for ${label} — ${count.toLocaleString()} event${count !== 1 ? "s" : ""}`
                : `${label} — ${count.toLocaleString()} event${count !== 1 ? "s" : ""}`
              }
              className={`px-2 py-1 rounded text-xs font-mono transition-opacity ${onMitreClick ? "cursor-pointer hover:opacity-80 active:opacity-60" : "cursor-default"}`}
              style={{
                background: bg,
                border:     `1px solid ${onMitreClick ? "rgba(239,68,68,0.4)" : "rgba(239,68,68,0.2)"}`,
                color:      intensity > 0.5 ? "#fecaca" : "#fca5a5",
              }}
              onClick={() => onMitreClick?.(tid)}
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
