import { X } from "lucide-react";
import type { Alert } from "../lib/types";
import {
  CATEGORY_LABELS, SEVERITY_BG, formatConfidence, formatTime,
} from "../lib/utils";

interface Props { alert: Alert | null; onClose: () => void }

export function AIExplanationPanel({ alert, onClose }: Props) {
  if (!alert) return null;

  return (
    <div className="fixed inset-y-0 right-0 w-[480px] max-w-full bg-[#0d1320] border-l border-gray-800 shadow-2xl z-50 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-3 px-5 py-4 border-b border-gray-800 bg-[#111827]">
        <span className={`px-2 py-0.5 rounded text-xs font-semibold ${SEVERITY_BG[alert.severity]}`}>
          {alert.severity}
        </span>
        <span className="text-sm font-medium text-gray-200 flex-1 truncate">
          {CATEGORY_LABELS[alert.category]} — {alert.source_ip ?? "N/A"}
        </span>
        <button onClick={onClose} className="text-gray-500 hover:text-white transition-colors">
          <X size={18} />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-5 text-sm">
        {/* Metadata row */}
        <div className="grid grid-cols-2 gap-3 text-xs">
          <Meta label="Alert ID"   value={alert.alert_id.slice(0, 16) + "…"} mono />
          <Meta label="Timestamp"  value={formatTime(alert.timestamp)} mono />
          <Meta label="Confidence" value={formatConfidence(alert.confidence)} />
          <Meta label="FP Risk"    value={alert.false_positive_risk} />
          <Meta label="Source"     value={alert.source_type} />
          <Meta label="Log Type"   value={alert.log_type} />
        </div>

        {/* MITRE techniques */}
        {alert.mitre_techniques?.length > 0 && (
          <Section title="MITRE ATT&CK Techniques">
            <div className="flex flex-wrap gap-2">
              {alert.mitre_techniques.map(t => (
                <a
                  key={t}
                  href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}`}
                  target="_blank" rel="noreferrer"
                  className="px-2 py-1 rounded bg-purple-900/40 text-purple-300 font-mono text-xs border border-purple-800/40 hover:bg-purple-900/70 transition-colors"
                >
                  {t} ↗
                </a>
              ))}
            </div>
          </Section>
        )}

        {/* Raw log */}
        <Section title="Raw Log Excerpt">
          <pre className="text-[11px] text-green-400 bg-gray-900 rounded p-3 overflow-x-auto whitespace-pre-wrap break-all font-mono leading-relaxed">
            {alert.raw_log_excerpt}
          </pre>
        </Section>

        {/* AI Reasoning */}
        <Section title="AI Reasoning">
          <p className="text-gray-300 leading-relaxed">{alert.ai_reasoning}</p>
        </Section>

        {/* Recommendations */}
        {alert.recommendations?.length > 0 && (
          <Section title="Recommended Actions">
            <ol className="space-y-2">
              {[...alert.recommendations]
                .sort((a, b) => a.priority - b.priority)
                .map((r, i) => (
                  <li key={i} className="flex gap-2 text-gray-300">
                    <span className="shrink-0 w-5 h-5 rounded-full bg-blue-900/50 border border-blue-700 text-blue-300 text-[10px] flex items-center justify-center">
                      {r.priority}
                    </span>
                    {r.action}
                  </li>
                ))}
            </ol>
          </Section>
        )}

        {/* Playbook */}
        {alert.playbook_triggered && (
          <Section title="Automated Response">
            <div className="flex items-center gap-2 px-3 py-2 rounded bg-green-900/20 border border-green-800/40">
              <span className="text-green-400 text-xs">⚡ EXECUTED</span>
              <span className="text-green-300 text-xs">{alert.playbook_triggered}</span>
            </div>
          </Section>
        )}
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h4 className="text-[11px] uppercase tracking-widest text-gray-500 mb-2">{title}</h4>
      {children}
    </div>
  );
}

function Meta({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-gray-600">{label}</div>
      <div className={`text-gray-300 mt-0.5 ${mono ? "font-mono" : ""}`}>{value}</div>
    </div>
  );
}
