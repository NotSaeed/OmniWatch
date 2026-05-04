import type { CisoPipelineSummary } from "../lib/types";

// Per-technique remediation rules — deterministic, no LLM required
const TECHNIQUE_REMEDIATIONS: Record<string, { title: string; steps: string[] }> = {
  T1498:    { title: "Network DoS",           steps: ["Enable rate-limiting on edge routers", "Activate upstream scrubbing / null-route origin", "Alert ISP for upstream mitigation"] },
  T1499:    { title: "Endpoint DoS",          steps: ["Scale out affected service horizontally", "Enable WAF challenge pages", "Increase connection-queue limits"] },
  T1046:    { title: "Network Scan",          steps: ["Block scanner IP at perimeter firewall", "Audit exposed service ports", "Enable port-scan detection alerts"] },
  T1110:    { title: "Brute Force",           steps: ["Enforce account lockout after 5 failures", "Require MFA on affected service", "Block source IPs via firewall rule"] },
  T1190:    { title: "Exploit Public App",    steps: ["Patch CVE immediately or take service offline", "Enable WAF virtual patch rule", "Rotate service credentials"] },
  T1071:    { title: "C2 over App Protocol",  steps: ["Block suspicious outbound port 443/80 to flagged IPs", "Inspect TLS SNI for anomalies", "Quarantine affected host"] },
  T1041:    { title: "Exfiltration over C2",  steps: ["Isolate host from network immediately", "Capture memory for forensics", "Rotate all credentials on affected system"] },
  T1059:    { title: "Command Interpreter",   steps: ["Kill suspicious process tree", "Enable script-block logging", "Review and tighten AppLocker/WDAC policy"] },
  T1021:    { title: "Lateral Movement",      steps: ["Segment affected VLAN", "Reset service account passwords", "Enable SMB signing enforcement"] },
  T1543:    { title: "Persistence Service",   steps: ["Remove unauthorized service/task", "Audit startup entries", "Deploy endpoint detection rule for service creation"] },
  T1552:    { title: "Unsecured Credentials", steps: ["Rotate all credentials found in logs", "Enable secrets scanning in CI/CD", "Audit environment variables and config files"] },
  T1048:    { title: "Exfil via Alt Protocol", steps: ["Block non-standard outbound protocols", "Enable DLP on sensitive file paths", "Review DNS for data-exfil tunneling"] },
  T1189:    { title: "Drive-by Compromise",   steps: ["Block malicious domain at DNS/proxy", "Scan endpoint for staged payloads", "Enable safe-browsing enforcement"] },
};

// Label-based fallback rules
const LABEL_REMEDIATIONS: Record<string, string[]> = {
  "DoS":         ["Rate-limit inbound connections", "Activate upstream DDoS mitigation"],
  "PortScan":    ["Block scanning source at firewall", "Audit external attack surface"],
  "Bot":         ["Block C2 IPs at egress", "Quarantine infected host", "Run full AV scan"],
  "Brute Force": ["Enable account lockout policy", "Require MFA", "Rotate affected credentials"],
  "Heartbleed":  ["Patch OpenSSL immediately", "Revoke & reissue TLS certificates", "Audit memory disclosure"],
  "Infiltration":["Isolate affected host", "Perform memory forensics", "Review all outbound connections"],
};

function matchLabel(label: string): string[] {
  for (const [key, steps] of Object.entries(LABEL_REMEDIATIONS)) {
    if (label.toLowerCase().includes(key.toLowerCase())) return steps;
  }
  return ["Investigate alert context", "Block source IP at perimeter", "Escalate to SOC Tier 2"];
}

interface Props {
  pipelineCiso?: CisoPipelineSummary;
}

export function RemediationPlanPanel({ pipelineCiso }: Props) {
  if (!pipelineCiso || pipelineCiso.total_alerts === 0) {
    return (
      <div className="flex items-center justify-center h-24 text-xs" style={{ color: "#4d5060" }}>
        No active session — upload telemetry to generate a remediation plan
      </div>
    );
  }

  const crit = pipelineCiso.by_severity?.CRITICAL ?? 0;
  const high = pipelineCiso.by_severity?.HIGH ?? 0;
  const med  = pipelineCiso.by_severity?.MEDIUM ?? 0;

  // Build immediate actions from severity
  const immediateActions: string[] = [];
  if (crit > 0) immediateActions.push(`Triage ${crit.toLocaleString()} CRITICAL alerts — initiate P0 incident response`);
  if (high > 0) immediateActions.push(`Review ${high.toLocaleString()} HIGH severity flows — validate and escalate`);
  if (med > 0)  immediateActions.push(`Monitor ${med.toLocaleString()} MEDIUM alerts — queue for analyst review`);

  // Technique-specific steps from top techniques
  const techSteps: { id: string; title: string; steps: string[] }[] = [];
  for (const t of (pipelineCiso.top_techniques ?? []).slice(0, 4)) {
    const baseId = t.id.split(".")[0]; // e.g. "T1498.001" → "T1498"
    const rule   = TECHNIQUE_REMEDIATIONS[t.id] ?? TECHNIQUE_REMEDIATIONS[baseId];
    if (rule) techSteps.push({ id: t.id, title: rule.title, steps: rule.steps });
  }

  // Label-based steps for top attack labels
  const labelSteps: { label: string; steps: string[] }[] = [];
  for (const { label } of (pipelineCiso.top_labels ?? []).slice(0, 2)) {
    if (label.toLowerCase() === "benign") continue;
    const steps = matchLabel(label);
    labelSteps.push({ label, steps });
  }

  return (
    <div className="space-y-3 text-[11px]">
      {/* Immediate actions */}
      {immediateActions.length > 0 && (
        <div>
          <p className="text-[9px] uppercase tracking-widest font-semibold mb-1.5" style={{ color: "#e84d4d" }}>
            Immediate Actions
          </p>
          <ul className="space-y-1">
            {immediateActions.map((a, i) => (
              <li key={i} className="flex items-start gap-2 px-2 py-1.5 rounded"
                  style={{ background: "rgba(239,68,68,0.07)", border: "1px solid rgba(239,68,68,0.15)" }}>
                <span className="mt-0.5 shrink-0 font-bold" style={{ color: "#e84d4d" }}>!</span>
                <span style={{ color: "#c5c7d4" }}>{a}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Technique-driven steps */}
      {techSteps.length > 0 && (
        <div>
          <p className="text-[9px] uppercase tracking-widest font-semibold mb-1.5" style={{ color: "#f59e0b" }}>
            Technique Containment
          </p>
          <div className="space-y-2">
            {techSteps.map(({ id, title, steps }) => (
              <div key={id} className="px-2 py-1.5 rounded"
                   style={{ background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.15)" }}>
                <p className="font-mono font-semibold text-[10px] mb-1" style={{ color: "#f59e0b" }}>
                  {id} · {title}
                </p>
                <ul className="space-y-0.5">
                  {steps.map((s, i) => (
                    <li key={i} className="flex items-start gap-1.5" style={{ color: "#9ba3b8" }}>
                      <span className="mt-0.5 shrink-0 text-[9px]" style={{ color: "#f59e0b99" }}>›</span>
                      {s}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Label-based steps */}
      {labelSteps.length > 0 && (
        <div>
          <p className="text-[9px] uppercase tracking-widest font-semibold mb-1.5" style={{ color: "#22c55e" }}>
            Attack Pattern Response
          </p>
          <div className="space-y-2">
            {labelSteps.map(({ label, steps }) => (
              <div key={label} className="px-2 py-1.5 rounded"
                   style={{ background: "rgba(34,197,94,0.06)", border: "1px solid rgba(34,197,94,0.15)" }}>
                <p className="font-semibold text-[10px] mb-1 truncate" style={{ color: "#22c55e" }}>{label}</p>
                <ul className="space-y-0.5">
                  {steps.map((s, i) => (
                    <li key={i} className="flex items-start gap-1.5" style={{ color: "#9ba3b8" }}>
                      <span className="mt-0.5 shrink-0 text-[9px]" style={{ color: "#22c55e99" }}>›</span>
                      {s}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      )}

      {techSteps.length === 0 && labelSteps.length === 0 && (
        <div className="px-2 py-1.5 rounded text-[10px]"
             style={{ background: "rgba(78,154,241,0.06)", border: "1px solid rgba(78,154,241,0.15)", color: "#9ba3b8" }}>
          No specific MITRE techniques mapped — investigate raw flows in Log Explorer
        </div>
      )}
    </div>
  );
}
