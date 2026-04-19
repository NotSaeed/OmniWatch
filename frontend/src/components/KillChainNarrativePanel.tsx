import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { SEVERITY_BG } from "../lib/utils";

interface Props { scanRunId: string | null }

const STAGES = [
  "Reconnaissance", "Weaponization", "Delivery",
  "Exploitation", "Installation", "Command & Control", "Exfiltration",
];

export function KillChainNarrativePanel({ scanRunId }: Props) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["narrative", scanRunId],
    queryFn:  () => api.getNarrative(scanRunId!),
    enabled:  !!scanRunId,
    retry:    false,
  });

  if (!scanRunId) return null;

  if (isLoading) {
    return (
      <div className="p-5 rounded border border-gray-800 bg-[#111827] animate-pulse">
        <div className="h-4 bg-gray-700 rounded w-1/3 mb-3" />
        <div className="space-y-2">
          {[1, 2, 3].map(i => <div key={i} className="h-3 bg-gray-800 rounded" />)}
        </div>
      </div>
    );
  }

  if (isError || !data) return null;

  return (
    <div className="rounded border border-gray-700 bg-[#0d1320] overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-3 px-5 py-3 bg-[#111827] border-b border-gray-800">
        <span className="text-xs text-gray-500 uppercase tracking-widest">Kill Chain Narrative</span>
        <span className={`ml-auto px-2 py-0.5 rounded text-[11px] font-semibold ${SEVERITY_BG[data.recommended_priority]}`}>
          {data.recommended_priority}
        </span>
        <span className="text-xs text-gray-600">{data.tlp_classification}</span>
      </div>

      {/* Kill chain progress bar */}
      <div className="px-5 py-3 border-b border-gray-800">
        <div className="flex gap-1">
          {STAGES.map((stage, i) => {
            const reached  = i <= data.kill_chain_index;
            const current  = i === data.kill_chain_index;
            return (
              <div
                key={stage}
                title={stage}
                className={`flex-1 h-2 rounded transition-all ${
                  current  ? "bg-red-500" :
                  reached  ? "bg-orange-600" :
                             "bg-gray-800"
                }`}
              />
            );
          })}
        </div>
        <div className="flex justify-between text-[9px] text-gray-700 mt-1">
          <span>{STAGES[0]}</span>
          <span className="text-orange-500 text-[10px]">{data.kill_chain_stage}</span>
          <span>{STAGES[STAGES.length - 1]}</span>
        </div>
      </div>

      {/* Narrative text */}
      <div className="px-5 py-4">
        <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap font-sans">
          {data.narrative_text}
        </p>
      </div>

      {/* Footer stats */}
      <div className="flex flex-wrap gap-4 px-5 py-3 border-t border-gray-800 text-xs text-gray-500">
        <span>{data.total_alerts} alerts</span>
        <span>{data.unique_attackers.length} unique attacker{data.unique_attackers.length !== 1 ? "s" : ""}</span>
        <span>{data.mitre_techniques.length} MITRE techniques</span>
        {data.playbooks_fired.length > 0 && (
          <span>{data.playbooks_fired.length} playbook{data.playbooks_fired.length !== 1 ? "s" : ""} fired</span>
        )}
      </div>
    </div>
  );
}
