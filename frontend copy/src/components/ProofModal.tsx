/**
 * Phase 7 — Proof of Integrity Modal
 *
 * High-assurance cryptographic audit record viewer.
 * Fetches /api/firewall/proof/{ruleId} and displays the full STARK verdict
 * journal so an auditor can verify every block decision was machine-proven.
 */

import { useQuery } from "@tanstack/react-query";
import axios from "axios";
import { X, Bot, User } from "lucide-react";

const http = axios.create({ baseURL: "/api" });

// ── Types ─────────────────────────────────────────────────────────────────────

interface ProofData {
  rule_id: number;
  src_ip: string;
  action: string;
  category: string;
  confidence_pct: number;
  blocked_at: string;
  nonce: string;
  auto_blocked: boolean;
  edge_record_id: number | null;
  verdict: {
    valid?: boolean;
    input_hash?: string;
    is_threat?: boolean;
    category?: number;
    category_name?: string;
    confidence_pct?: number;
    triggered_rules?: number;
  };
  guest_program: string;
  proof_system: string;
  integrity_guarantees: string[];
}

// ── Seal of Computational Integrity ──────────────────────────────────────────

function SealOfIntegrity({ loading }: { loading: boolean }) {
  return (
    <div className="relative flex items-center justify-center mx-auto" style={{ width: 96, height: 96 }}>
      {/* Layered pulsing glow rings */}
      <div
        className="absolute rounded-full animate-pulse"
        style={{
          inset: -12,
          background: "radial-gradient(circle, rgba(34,197,94,0.22) 0%, transparent 65%)",
          animationDuration: "2.4s",
        }}
      />
      <div
        className="absolute rounded-full animate-pulse"
        style={{
          inset: -4,
          background: "radial-gradient(circle, rgba(34,197,94,0.10) 0%, transparent 60%)",
          animationDuration: "3.6s",
          animationDelay: "0.8s",
        }}
      />

      {loading ? (
        /* Spinner while fetching */
        <div
          className="relative rounded-full border-2 border-transparent"
          style={{
            width: 80, height: 80,
            borderTopColor: "#22c55e",
            borderRightColor: "#22c55e40",
            animation: "spin 1s linear infinite",
          }}
        />
      ) : (
        <svg viewBox="0 0 100 100" width="96" height="96" style={{ position: "relative" }}>
          <defs>
            <filter id="proof-glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="1.8" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Outer measurement ring — tick marks every 10° */}
          {Array.from({ length: 36 }, (_, i) => {
            const θ = (i * 10 * Math.PI) / 180;
            const major = i % 9 === 0;
            const r1 = major ? 40 : 43.5;
            return (
              <line
                key={i}
                x1={50 + Math.cos(θ) * r1} y1={50 + Math.sin(θ) * r1}
                x2={50 + Math.cos(θ) * 47} y2={50 + Math.sin(θ) * 47}
                stroke={major ? "#22c55e" : "#22c55e40"}
                strokeWidth={major ? 1.5 : 0.8}
              />
            );
          })}

          {/* Outer arc */}
          <circle cx="50" cy="50" r="47" fill="none" stroke="#22c55e20" strokeWidth="0.5" />

          {/* Middle decorative ring */}
          <circle cx="50" cy="50" r="37" fill="none" stroke="#22c55e35" strokeWidth="1"
            strokeDasharray="4 2" />

          {/* Inner panel */}
          <circle cx="50" cy="50" r="32" fill="#0a0a0e" stroke="#22c55e25" strokeWidth="0.5" />

          {/* Shield */}
          <path
            d="M50 22 L67 31 L67 47 C67 58 60 65 50 69 C40 65 33 58 33 47 L33 31 Z"
            fill="rgba(34,197,94,0.06)"
            stroke="#22c55e"
            strokeWidth="1.3"
            filter="url(#proof-glow)"
          />

          {/* Checkmark */}
          <path
            d="M41 47 L48 55 L60 37"
            fill="none"
            stroke="#22c55e"
            strokeWidth="2.8"
            strokeLinecap="round"
            strokeLinejoin="round"
            filter="url(#proof-glow)"
          />

          {/* "VERIFIED" label */}
          <text
            x="50" y="89"
            textAnchor="middle"
            fontSize="5"
            fill="#22c55e70"
            fontFamily="JetBrains Mono, monospace"
            letterSpacing="3.5"
          >
            VERIFIED
          </text>
        </svg>
      )}
    </div>
  );
}

// ── JSON syntax highlighter ───────────────────────────────────────────────────

type TokenType = "key" | "string" | "number" | "bool" | "null" | "punct";

const TOKEN_COLORS: Record<TokenType, string> = {
  key:    "#06b6d4",
  string: "#f97316",
  number: "#22d3ee",
  bool:   "#a78bfa",
  null:   "#6b6e80",
  punct:  "#4d5060",
};

function Tok({ t, v }: { t: TokenType; v: string }) {
  return <span style={{ color: TOKEN_COLORS[t] }}>{v}</span>;
}

function renderValue(value: unknown): React.ReactNode {
  if (value === null || value === undefined) return <Tok t="null" v="null" />;
  if (typeof value === "boolean")  return <Tok t="bool" v={String(value)} />;
  if (typeof value === "number")   return <Tok t="number" v={String(value)} />;
  if (typeof value === "string")   return <Tok t="string" v={`"${value}"`} />;
  return <Tok t="null" v={JSON.stringify(value)} />;
}

function JsonView({ data }: { data: Record<string, unknown> }) {
  const entries = Object.entries(data);
  return (
    <pre
      className="text-[10px] leading-[1.7] overflow-x-auto select-text"
      style={{ fontFamily: "JetBrains Mono, monospace", whiteSpace: "pre-wrap", wordBreak: "break-all" }}
    >
      <Tok t="punct" v="{\n" />
      {entries.map(([k, v], i) => (
        <span key={k}>
          {"  "}
          <Tok t="key" v={`"${k}"`} />
          <Tok t="punct" v=": " />
          {renderValue(v)}
          {i < entries.length - 1 && <Tok t="punct" v="," />}
          {"\n"}
        </span>
      ))}
      <Tok t="punct" v="}" />
    </pre>
  );
}

// ── Section label ─────────────────────────────────────────────────────────────

function SectionLabel({ color, children }: { color: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 mb-2">
      <div className="h-px flex-1" style={{ background: `linear-gradient(90deg, ${color}60, transparent)` }} />
      <span
        className="text-[8.5px] uppercase tracking-[0.2em] font-bold shrink-0"
        style={{ color }}
      >
        {children}
      </span>
      <div className="h-px flex-1" style={{ background: `linear-gradient(270deg, ${color}60, transparent)` }} />
    </div>
  );
}

// ── Main Modal ────────────────────────────────────────────────────────────────

export function ProofModal({ ruleId, onClose }: { ruleId: number; onClose: () => void }) {
  const { data: proof, isLoading, isError } = useQuery<ProofData>({
    queryKey: ["firewall-proof", ruleId],
    queryFn: () => http.get(`/firewall/proof/${ruleId}`).then(r => r.data),
    staleTime: Infinity,
  });

  const hasVerdict = proof && Object.keys(proof.verdict).length > 0;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(0,0,0,0.82)", backdropFilter: "blur(8px) saturate(120%)" }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        className="w-full flex flex-col rounded-2xl overflow-hidden"
        style={{
          maxWidth: 580,
          maxHeight: "92vh",
          background: "linear-gradient(180deg, rgba(34,197,94,0.05) 0%, #0d0d11 120px)",
          border: "1px solid rgba(34,197,94,0.28)",
          boxShadow:
            "0 0 80px rgba(34,197,94,0.10), 0 0 160px rgba(34,197,94,0.05), 0 32px 64px rgba(0,0,0,0.9)",
        }}
      >
        {/* ── Close button ── */}
        <div className="flex justify-end px-4 pt-4 shrink-0">
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg transition-colors hover:bg-white/10"
            style={{ color: "#4d5060" }}
          >
            <X style={{ width: 14, height: 14 }} />
          </button>
        </div>

        {/* ── Header — seal + title ── */}
        <div className="flex flex-col items-center gap-3 px-6 pb-5 shrink-0">
          <SealOfIntegrity loading={isLoading} />

          <div className="text-center space-y-1">
            <h2
              className="text-[11px] font-bold uppercase tracking-[0.25em]"
              style={{ color: "#22c55e" }}
            >
              Proof of Computational Integrity
            </h2>
            <p className="text-[10px] font-mono" style={{ color: "#4d5060" }}>
              RISC Zero STARK Receipt · Audit Record #{ruleId}
            </p>
          </div>
        </div>

        {/* ── Divider ── */}
        <div style={{ height: 1, background: "linear-gradient(90deg, transparent, #22c55e30, transparent)" }} />

        {/* ── Scrollable body ── */}
        <div className="overflow-auto flex-1 px-5 py-5 space-y-5">

          {isLoading && (
            <p className="text-center text-[10px] py-10 animate-pulse" style={{ color: "#4d5060" }}>
              Retrieving cryptographic audit record…
            </p>
          )}

          {isError && (
            <div
              className="text-center py-8 rounded-lg"
              style={{ background: "rgba(239,68,68,0.05)", border: "1px solid rgba(239,68,68,0.2)" }}
            >
              <p className="text-[11px]" style={{ color: "#ef4444" }}>
                No verdict data found for rule #{ruleId}
              </p>
              <p className="text-[10px] mt-1" style={{ color: "#4d5060" }}>
                Re-run PROVE to generate a verifiable receipt.
              </p>
            </div>
          )}

          {proof && (
            <>
              {/* ── Attacker Source ── */}
              <section>
                <SectionLabel color="#ef4444">Attacker Source</SectionLabel>
                <div
                  className="rounded-xl p-4"
                  style={{
                    background: "linear-gradient(135deg, rgba(239,68,68,0.07) 0%, rgba(0,0,0,0) 100%)",
                    border: "1px solid rgba(239,68,68,0.2)",
                    borderLeft: "3px solid #ef4444",
                  }}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <p className="text-[9px] uppercase tracking-widest mb-1" style={{ color: "#ef444470" }}>
                        Source IP Address
                      </p>
                      <p
                        className="font-mono font-bold tracking-tight"
                        style={{ fontSize: 22, color: "#ef4444", letterSpacing: "0.04em",
                                 textShadow: "0 0 20px rgba(239,68,68,0.4)" }}
                      >
                        {proof.src_ip}
                      </p>
                    </div>
                    <div className="text-right shrink-0">
                      <span
                        className="inline-block text-[9px] font-bold px-2 py-0.5 rounded-full"
                        style={{ background: "rgba(239,68,68,0.15)", color: "#ef4444",
                                 border: "1px solid rgba(239,68,68,0.3)" }}
                      >
                        {proof.action}
                      </span>
                      {proof.auto_blocked
                        ? <div className="flex items-center justify-end gap-1 mt-1.5">
                            <Bot style={{ width: 9, height: 9, color: "#06b6d4" }} />
                            <span className="text-[9px]" style={{ color: "#06b6d4" }}>ABC Autonomous</span>
                          </div>
                        : <div className="flex items-center justify-end gap-1 mt-1.5">
                            <User style={{ width: 9, height: 9, color: "#d946ef" }} />
                            <span className="text-[9px]" style={{ color: "#d946ef" }}>FIDO2 Authorised</span>
                          </div>
                      }
                    </div>
                  </div>

                  <div className="mt-3 pt-3 grid grid-cols-3 gap-2" style={{ borderTop: "1px solid rgba(239,68,68,0.15)" }}>
                    {[
                      { label: "Category",   value: proof.category },
                      { label: "Confidence", value: `${proof.confidence_pct}%` },
                      { label: "Timestamp",  value: new Date(proof.blocked_at).toLocaleTimeString() },
                    ].map(({ label, value }) => (
                      <div key={label}>
                        <p className="text-[8px] uppercase tracking-widest" style={{ color: "#4d5060" }}>{label}</p>
                        <p className="text-[10px] font-mono font-semibold mt-0.5" style={{ color: "#c5c7d4" }}>{value}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              {/* ── Decision Logic — STARK Journal ── */}
              <section>
                <SectionLabel color="#06b6d4">Decision Logic · STARK Verdict Journal</SectionLabel>
                {!hasVerdict ? (
                  <p className="text-[10px] italic px-1" style={{ color: "#3d3f4a" }}>
                    No journal stored — only blocks from Phase 7 onward include embedded verdict data.
                  </p>
                ) : (
                  <div
                    className="rounded-xl overflow-hidden"
                    style={{
                      background: "#08080d",
                      border: "1px solid rgba(6,182,212,0.2)",
                    }}
                  >
                    {/* Terminal title bar */}
                    <div
                      className="flex items-center gap-1.5 px-3 py-2"
                      style={{ borderBottom: "1px solid rgba(6,182,212,0.15)", background: "rgba(6,182,212,0.04)" }}
                    >
                      <div className="w-2 h-2 rounded-full" style={{ background: "#ef4444" }} />
                      <div className="w-2 h-2 rounded-full" style={{ background: "#f97316" }} />
                      <div className="w-2 h-2 rounded-full" style={{ background: "#22c55e" }} />
                      <span className="ml-2 text-[9px] font-mono" style={{ color: "#4d5060" }}>
                        risc0_zkvm::Journal → ThreatVerdict
                      </span>
                    </div>
                    <div className="p-4">
                      <JsonView data={proof.verdict as Record<string, unknown>} />
                    </div>

                    {/* Full nonce display */}
                    {proof.verdict.input_hash && (
                      <div
                        className="px-4 py-3"
                        style={{ borderTop: "1px solid rgba(6,182,212,0.12)", background: "rgba(6,182,212,0.03)" }}
                      >
                        <p className="text-[8px] uppercase tracking-widest mb-1" style={{ color: "#4d5060" }}>
                          Full Replay-Prevention Nonce (input_hash)
                        </p>
                        <p
                          className="font-mono text-[9px] break-all"
                          style={{ color: "#06b6d4", letterSpacing: "0.05em" }}
                        >
                          {proof.verdict.input_hash}
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </section>

              {/* ── Security Guarantees ── */}
              <section>
                <SectionLabel color="#22c55e">Security Guarantees</SectionLabel>
                <div
                  className="rounded-xl p-4 space-y-2.5"
                  style={{
                    background: "rgba(34,197,94,0.03)",
                    border: "1px solid rgba(34,197,94,0.15)",
                  }}
                >
                  {proof.integrity_guarantees.map((g, i) => (
                    <div key={i} className="flex items-start gap-3">
                      <div
                        className="shrink-0 w-4 h-4 rounded-full flex items-center justify-center mt-0.5"
                        style={{ background: "rgba(34,197,94,0.15)", border: "1px solid rgba(34,197,94,0.4)" }}
                      >
                        <svg viewBox="0 0 10 10" width="8" height="8">
                          <path d="M2 5 L4.5 7.5 L8 3" fill="none" stroke="#22c55e"
                                strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                      </div>
                      <span className="text-[10px] leading-relaxed" style={{ color: "#8b8e9e" }}>{g}</span>
                    </div>
                  ))}
                </div>
              </section>
            </>
          )}
        </div>

        {/* ── Footer — RISC Zero badge ── */}
        <div className="shrink-0 px-5 pb-5 pt-3">
          <div
            className="rounded-xl py-3 px-4 flex items-center justify-center gap-3"
            style={{
              background: "rgba(34,197,94,0.04)",
              border: "1px solid rgba(34,197,94,0.25)",
              boxShadow: "0 0 30px rgba(34,197,94,0.08), inset 0 0 20px rgba(34,197,94,0.03)",
            }}
          >
            <div className="h-px flex-1" style={{ background: "linear-gradient(90deg, transparent, #22c55e50)" }} />
            <div className="flex items-center gap-2">
              <div
                className="w-1.5 h-1.5 rounded-full animate-pulse"
                style={{ background: "#22c55e", boxShadow: "0 0 8px #22c55e" }}
              />
              <span className="text-[9px] font-mono font-bold tracking-[0.2em] uppercase" style={{ color: "#22c55e" }}>
                Verified by RISC Zero zkVM
              </span>
              <div
                className="w-1.5 h-1.5 rounded-full animate-pulse"
                style={{ background: "#22c55e", boxShadow: "0 0 8px #22c55e", animationDelay: "0.5s" }}
              />
            </div>
            <div className="h-px flex-1" style={{ background: "linear-gradient(270deg, transparent, #22c55e50)" }} />
          </div>
        </div>
      </div>
    </div>
  );
}
