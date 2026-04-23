/**
 * Sprint 5 — Firewall History Panel
 *
 * Displays the persistent audit trail of remediated threats (src_ip blocks).
 * Fetches data from /api/firewall/status.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import axios from "axios";
import { ShieldCheck, History, ExternalLink, ShieldAlert, Cpu, Bot } from "lucide-react";
import { ProofModal } from "./ProofModal";

const http = axios.create({ baseURL: "/api" });

interface FirewallRule {
  id: number;
  src_ip: string;
  action: string;
  reason: string;
  category: string;
  confidence_pct: number;
  blocked_at: string;
  auto_blocked?: boolean;
}

export function FirewallHistoryPanel() {
  const [selectedRuleId, setSelectedRuleId] = useState<number | null>(null);

  const { data: history } = useQuery<FirewallRule[]>({
    queryKey: ["firewall-status"],
    queryFn: () => http.get("/firewall/status").then(r => r.data),
    refetchInterval: 5000,
  });

  return (
    <div
      className="rounded-xl overflow-hidden h-full flex flex-col"
      style={{ background: "#0d0d10", border: "1px solid #1a1a1f" }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-3"
        style={{ borderBottom: "1px solid #1a1a1f" }}
      >
        <div className="flex items-center gap-2.5">
          <History style={{ width: 14, height: 14, color: "#16a34a" }} />
          <span className="text-xs font-bold text-white/90 tracking-wide">
            Remediation Ledger
          </span>
          <span className="text-[10px] font-mono" style={{ color: "#6b6e80" }}>
            Audit Trail · firewall_status
          </span>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto">
        {!history || history.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 gap-2 opacity-30">
            <ShieldCheck style={{ width: 32, height: 32, color: "#2e3038" }} />
            <p className="text-[10px] uppercase tracking-widest font-bold" style={{ color: "#4d5060" }}>
              No Active Blocks
            </p>
          </div>
        ) : (
          <div className="space-y-px">
            {history.map((rule) => (
              <div
                key={rule.id}
                className="group flex items-center gap-4 px-4 py-3 transition-colors hover:bg-white/[0.02]"
                style={{ borderBottom: "1px solid #1a1a1f" }}
              >
                {/* Status Icon */}
                <div className="relative">
                  <div className="absolute inset-0 bg-green-500/20 blur-md rounded-full" />
                  <ShieldAlert style={{ width: 16, height: 16, color: "#22c55e", position: "relative" }} />
                </div>

                {/* Details */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-white/90 font-mono tracking-tight">
                      {rule.src_ip}
                    </span>
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-green-500/10 text-green-500 font-bold border border-green-500/20">
                      {rule.action}
                    </span>
                    {rule.auto_blocked && (
                      <span className="flex items-center gap-0.5 text-[9px] px-1.5 py-0.5 rounded font-bold"
                            style={{ background: "#06b6d415", color: "#06b6d4", border: "1px solid #06b6d430" }}>
                        <Bot style={{ width: 8, height: 8 }} />ABC
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5 mt-0.5 mt-1">
                    <Cpu style={{ width: 10, height: 10, color: "#6b6e80" }} />
                    <span className="text-[10px] text-gray-500 truncate">
                      {rule.reason}
                    </span>
                  </div>
                </div>

                {/* Metadata */}
                <div className="text-right">
                  <div className="text-[10px] font-bold text-white/60">
                    {rule.confidence_pct}% Conf.
                  </div>
                  <div className="text-[9px] text-gray-600 mt-0.5">
                    {new Date(rule.blocked_at).toLocaleTimeString()}
                  </div>
                </div>

                {/* Action */}
                <button
                  onClick={() => setSelectedRuleId(rule.id)}
                  className="opacity-0 group-hover:opacity-100 transition-opacity p-1.5 rounded bg-white/5 hover:bg-white/10"
                  title="View Cryptographic Proof"
                >
                  <ExternalLink style={{ width: 12, height: 12, color: "#6b6e80" }} />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {selectedRuleId !== null && (
        <ProofModal ruleId={selectedRuleId} onClose={() => setSelectedRuleId(null)} />
      )}
    </div>
  );
}
