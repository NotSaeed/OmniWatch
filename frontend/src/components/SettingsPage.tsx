import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Trash2, AlertTriangle, CheckCircle2, Loader2, Key } from "lucide-react";
import { api } from "../lib/api";
import { startRegistration } from "@simplewebauthn/browser";

const KEY_DEFS = [
  {
    id: "OLLAMA_API_URL",
    name: "Ollama",
    description: "Local RAG edge intelligence for facility triage",
    placeholder: "http://127.0.0.1:11434",
    statusKey: "ollama" as const,
    modelKey: "ollama_model" as const,
  },
  {
    id: "ABUSEIPDB_API_KEY",
    name: "AbuseIPDB",
    description: "Real-time IP reputation lookups in CTI enrichment",
    placeholder: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    statusKey: "abuseipdb" as const,
  },
  {
    id: "VIRUSTOTAL_API_KEY",
    name: "VirusTotal",
    description: "File/IP threat intelligence",
    placeholder: "0000000000000000000000000000000000000000000000000000000000000000",
    statusKey: "virustotal" as const,
  },
] as const;

function loadStored(id: string) {
  return localStorage.getItem(`omniwatch_${id}`) ?? "";
}

export function SettingsPage() {
  const qc = useQueryClient();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["config-status"],
    queryFn: api.getConfigStatus,
    refetchInterval: 60_000,
  });

  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(KEY_DEFS.map(k => [k.id, loadStored(k.id)])),
  );
  const [saved, setSaved] = useState<Record<string, boolean>>({});
  const [testing, setTesting] = useState<string | null>(null);
  const [tested, setTested] = useState<Record<string, boolean>>({});
  const [wiping, setWiping] = useState(false);
  const [confirm, setConfirm] = useState(false);

  async function handleTest(id: string) {
    setTesting(id);
    try {
      const status = await api.getConfigStatus();
      const keyMap: Record<string, string> = {
        OLLAMA_API_URL: "ollama",
        ABUSEIPDB_API_KEY: "abuseipdb",
        VIRUSTOTAL_API_KEY: "virustotal",
      };
      const isConnected = status[keyMap[id] as keyof typeof status] ?? false;
      setTested(t => ({ ...t, [id]: !!isConnected }));
      setTimeout(() => setTested(t => ({ ...t, [id]: false })), 4000);
      if (isConnected) {
        toast.success(`${id} — connection verified`, {
          description: "Backend confirmed the service is reachable.",
        });
      } else {
        toast.error(`${id} — not connected`, {
          description: "Service is unreachable or key is not configured in .env.",
        });
      }
    } catch {
      toast.error(`${id} — backend unreachable`, {
        description: "Could not reach the OmniWatch server on port 8080.",
      });
    } finally {
      setTesting(null);
    }
  }

  function handleSave(id: string) {
    localStorage.setItem(`omniwatch_${id}`, values[id]);
    setSaved(s => ({ ...s, [id]: true }));
    setTimeout(() => setSaved(s => ({ ...s, [id]: false })), 2500);
    toast.success(`${id} saved locally`, {
      description: "Restart the backend and set the value in your .env to apply.",
    });
  }

  async function handleWipe() {
    if (!confirm) {
      setConfirm(true);
      setTimeout(() => setConfirm(false), 5000);   // auto-cancel after 5 s
      return;
    }
    setConfirm(false);
    setWiping(true);
    try {
      const result = await api.resetSystem();
      // Invalidate every cached query so all widgets instantly show zero
      await qc.invalidateQueries();
      toast.success("Database wiped. System ready for new telemetry.", {
        description: `${result.rows_deleted.toLocaleString()} rows deleted across all tables.`,
        duration: 6000,
        style: { background: "#1e1f23", border: "1px solid #2e3038" },
      });
    } catch {
      toast.error("Reset failed — check backend logs.");
    } finally {
      setWiping(false);
    }
  }

  const [ingesting, setIngesting] = useState(false);
  async function handleIngestBotsV3() {
    setIngesting(true);
    toast.info("Starting BOTSv3 Ingestion...");
    try {
      const res = await api.ingestDataset("data/botsv3/botsv3_excerpt.json");
      toast.success("BOTSv3 Ingestion Complete", {
        description: `${res.inserted?.toLocaleString()} rows inserted.`,
      });
      await qc.invalidateQueries();
    } catch(e: any) {
      toast.error(`Ingestion failed: ${e.response?.data?.detail || e.message}`);
    } finally {
      setIngesting(false);
    }
  }

  async function handleRegisterKey() {
    try {
      const username = prompt("Enter your username for FIDO2 enrollment:", "admin");
      if (!username) return;

        const options = await api.webauthn.registerOptions(username);
        const authResp = await startRegistration({ optionsJSON: options });
        
        const verifyData = await api.webauthn.registerVerify(username, authResp);
      }
    } catch(e) {
      toast.error(`FIDO2 error: ${e}`);
    }
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6 p-6">
      {/* Header */}
      <div>
        <h2 className="text-base font-semibold text-slate-100">Integrations Hub</h2>
        <p className="text-xs text-slate-500 mt-1">
          Manage third-party API connections. Keys are stored in{" "}
          <code className="text-cyan-500 font-mono">localStorage</code> — set them in{" "}
          <code className="text-cyan-500 font-mono">.env</code> and restart the backend to activate.
        </p>
      </div>

      {/* API Key cards */}
      <section>
        <SectionLabel>API Connections</SectionLabel>
        {isLoading && (
          <div className="flex items-center gap-2 text-xs text-slate-600 py-4">
            <Loader2 className="w-3 h-3 animate-spin text-cyan-600" />
            Checking…
          </div>
        )}
        {isError && (
          <div className="rounded-lg border border-red-800/40 bg-red-950/30 px-4 py-3 text-xs text-red-400">
            Could not reach backend. Is the server running on port 8080?
          </div>
        )}
        <div className="space-y-3">
          {KEY_DEFS.map(def => {
            const connected = data?.[def.statusKey] ?? false;
            const isSaved = saved[def.id] ?? false;
            const model = "modelKey" in def ? data?.[def.modelKey] : undefined;

            return (
              <div
                key={def.id}
                className={`rounded-xl border p-4 transition-all ${connected
                    ? "border-emerald-800/40 bg-emerald-950/20"
                    : "border-slate-800/50 bg-slate-900/40"
                  }`}
              >
                {/* Name + status row */}
                <div className="flex items-start justify-between gap-3 mb-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${connected ? "bg-emerald-400" : "bg-slate-600"}`} />
                      <span className="text-sm font-medium text-slate-200">{def.name}</span>
                      {model && (
                        <span className="text-[10px] font-mono text-cyan-500 bg-cyan-950/40 border border-cyan-800/30 px-1.5 py-0.5 rounded">
                          {model}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-500 ml-3.5">{def.description}</p>
                    <p className="text-[10px] font-mono text-slate-700 ml-3.5 mt-0.5">{def.id}</p>
                  </div>
                  <StatusBadge active={connected} activeLabel="Connected" inactiveLabel="Not set" />
                </div>

                {/* Editable input + action buttons */}
                <div className="flex items-center gap-2">
                  <input
                    type="password"
                    value={values[def.id]}
                    onChange={e => setValues(v => ({ ...v, [def.id]: e.target.value }))}
                    placeholder={def.placeholder}
                    className="flex-1 min-w-0 px-3 py-1.5 rounded text-xs font-mono
                               bg-slate-950/60 border border-slate-700/50 text-slate-300
                               placeholder:text-slate-700 focus:outline-none
                               focus:border-cyan-700/60 focus:ring-1 focus:ring-cyan-700/30
                               transition-all"
                    spellCheck={false}
                    autoComplete="off"
                  />
                  {/* Test Connection */}
                  <button
                    onClick={() => handleTest(def.id)}
                    disabled={testing === def.id}
                    className="shrink-0 px-3 py-1.5 rounded text-xs font-medium transition-all
                               disabled:cursor-not-allowed active:scale-95"
                    style={
                      tested[def.id]
                        ? { background: "rgba(52,211,153,0.12)", border: "1px solid rgba(52,211,153,0.35)", color: "#34d399" }
                        : { background: "rgba(139,92,246,0.10)", border: "1px solid rgba(139,92,246,0.30)", color: "#a78bfa" }
                    }
                  >
                    {testing === def.id ? (
                      <Loader2 className="w-3 h-3 animate-spin inline" />
                    ) : tested[def.id] ? (
                      <><CheckCircle2 className="w-3 h-3 inline mr-1" />Verified</>
                    ) : (
                      "Test Connection"
                    )}
                  </button>
                  {/* Save */}
                  <button
                    onClick={() => handleSave(def.id)}
                    disabled={!values[def.id]}
                    className={`shrink-0 px-3 py-1.5 rounded text-xs font-medium transition-all
                                disabled:opacity-30 disabled:cursor-not-allowed active:scale-95 ${isSaved
                        ? "bg-emerald-900/50 border border-emerald-700/50 text-emerald-400"
                        : "bg-cyan-900/40 border border-cyan-700/40 text-cyan-300 hover:bg-cyan-800/50"
                      }`}
                  >
                    {isSaved
                      ? <><CheckCircle2 className="w-3 h-3 inline mr-1" />Saved</>
                      : "Save"
                    }
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* SOAR mode */}
      {data && (
        <section>
          <SectionLabel>SOAR Engine</SectionLabel>
          <div className="rounded-xl border border-slate-800/50 bg-slate-900/50 p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-slate-200">Enforcement Mode</p>
                <p className="text-xs text-slate-500 mt-0.5">
                  Rules are pushed to Palo Alto NGFW via PAN-OS API.
                  Set <code className="text-cyan-500 font-mono">SOAR_LIVE_MODE=true</code> to enable live enforcement.
                </p>
              </div>
              <StatusBadge active={data.soar_live} activeLabel="LIVE" inactiveLabel="POLICY REVIEW" />
            </div>
          </div>
        </section>
      )}

      {/* FIDO2 Configuration */}
      <section>
        <SectionLabel>Proof of Oversight (FIDO2)</SectionLabel>
        <div className="rounded-xl border border-blue-800/40 bg-blue-950/20 p-4">
          <div className="flex items-center justify-between">
            <div className="max-w-[70%]">
              <p className="text-sm font-medium text-blue-300">Hardware Security Key Enrollment</p>
              <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">
                Enroll a WebAuthn/FIDO2 authenticator (YubiKey, Windows Hello, TouchID) to cryptographically sign remediation orders. 
                Phase 3 compliance requirement.
              </p>
            </div>
            <button
               onClick={handleRegisterKey}
               className="btn-glow flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold
                          bg-blue-900/40 text-blue-300 border border-blue-700/50 hover:bg-blue-800/60 transition-all"
            >
              <Key className="w-4 h-4" /> Enroll Token
            </button>
          </div>
        </div>
      </section>

      {/* Utilities */}
      <section>
        <SectionLabel>System Utilities</SectionLabel>
        <div className="rounded-xl border border-slate-800/50 bg-slate-900/50 p-4 flex items-center justify-between">
          <div className="min-w-0">
            <p className="text-sm font-semibold text-slate-200">Load BOTSv3 Excerpt Dataset</p>
            <p className="text-xs text-slate-500 mt-1 leading-relaxed">
              Ingests a pre-packaged Boss of the SOC v3 subset for testing the RAG functionality.
            </p>
          </div>
          <button
            onClick={handleIngestBotsV3}
            disabled={ingesting}
            className="shrink-0 px-4 py-2 rounded-lg text-xs font-medium bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-50"
          >
            {ingesting ? <Loader2 className="w-4 h-4 animate-spin inline mr-1" /> : "Load Dataset"}
          </button>
        </div>
      </section>

      {/* ── Danger Zone ──────────────────────────────────────────────────── */}
      <section>
        <div className="flex items-center gap-2 mb-3">
          <span className="w-px h-3.5 bg-red-500/40" />
          <h3 className="text-[10px] uppercase tracking-widest font-semibold" style={{ color: "#f87171" }}>
            Danger Zone
          </h3>
        </div>

        <div
          className="rounded-xl p-4 transition-all"
          style={{ border: "1px solid rgba(239,68,68,0.18)", background: "rgba(239,68,68,0.03)" }}
        >
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="text-sm font-semibold" style={{ color: "#f1f5f9" }}>Wipe Telemetry Database</p>
              <p className="text-xs mt-1 leading-relaxed" style={{ color: "#64748b" }}>
                Permanently deletes all ingested network flows, SOAR execution logs, AI alerts,
                and scan history. API keys and configuration are preserved. Use this before
                loading a new dataset for a clean demo environment.
              </p>
              {confirm && (
                <div className="flex items-center gap-1.5 mt-2">
                  <AlertTriangle className="w-3 h-3 shrink-0" style={{ color: "#f87171" }} />
                  <p className="text-xs font-semibold" style={{ color: "#f87171" }}>
                    Click again to confirm — this action cannot be undone.
                  </p>
                </div>
              )}
            </div>

            <button
              onClick={handleWipe}
              disabled={wiping}
              className="btn-glow-red shrink-0 flex items-center gap-2 px-4 py-2 rounded-lg
                         text-xs font-semibold active:scale-95 disabled:opacity-40
                         disabled:cursor-not-allowed transition-all"
              style={confirm
                ? { background: "rgba(239,68,68,0.22)", borderColor: "rgba(239,68,68,0.55)", color: "#f87171" }
                : undefined
              }
            >
              {wiping ? (
                <><Loader2 className="w-3 h-3 animate-spin" /> Wiping…</>
              ) : confirm ? (
                <><AlertTriangle className="w-3 h-3" /> Confirm Wipe</>
              ) : (
                <><Trash2 className="w-3 h-3" /> Wipe Database</>
              )}
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 mb-3">
      <span className="w-px h-3.5 bg-cyan-500/50" />
      <h3 className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold">{children}</h3>
    </div>
  );
}

function StatusBadge({
  active, activeLabel = "ACTIVE", inactiveLabel = "INACTIVE",
}: {
  active: boolean; activeLabel?: string; inactiveLabel?: string;
}) {
  return active ? (
    <span className="px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wide
                     bg-emerald-950/60 text-emerald-400 border border-emerald-700/40
                     shadow-[0_0_8px_rgba(52,211,153,0.2)]">
      {activeLabel}
    </span>
  ) : (
    <span className="px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wide
                     bg-slate-800/60 text-slate-500 border border-slate-700/40">
      {inactiveLabel}
    </span>
  );
}
