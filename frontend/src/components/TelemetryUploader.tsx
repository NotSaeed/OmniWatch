/**
 * TelemetryUploader
 * =================
 * Upload modal with decoupled upload / processing phases.
 *
 * Architecture
 * ------------
 *  Phase 1 — Upload:  Axios streams bytes to the server.  The server writes
 *             them to a temp file and returns a 200 with {session_id} as soon
 *             as the file is on disk (no processing yet).
 *
 *  Phase 2 — Poll:   A setInterval loop hits GET /api/sessions/{id}/status
 *             every 2.5 s.  This is a lightweight endpoint (single SQLite
 *             SELECT) that returns {status, rows_processed, alerts_found}.
 *             The UI updates the progress bar from these values.
 *
 *  Phase 3 — Complete: When polling sees status="complete", it fetches the
 *             full session (with CISO summary) once and renders results.
 *
 * WebSocket messages from the parent are still used for instant stage
 * transitions (normalizing → tier1 → tier2) so the user sees the pipeline
 * stages without waiting for the next poll tick.
 *
 * Timeout strategy
 * ----------------
 * The Axios upload call has NO timeout — the only thing that can take time is
 * streaming file bytes to disk, which has no safe upper bound for large files.
 * The processing timeout is implicitly handled by the polling loop: if the
 * backend task crashes, status becomes "error" and polling stops.
 */

import {
  useCallback, useEffect, useRef, useState,
  type DragEvent, type ChangeEvent,
} from "react";
import { useQueryClient } from "@tanstack/react-query";
import axios from "axios";
import {
  CheckCircle, XCircle, Upload, Shield,
  Loader2, FileText, X, ChevronRight,
  AlertTriangle, Lock, Copy, Check,
} from "lucide-react";
import type { PipelineCompletion, PipelineSession, PipelineWsMessage } from "../lib/types";
import { api } from "../lib/api";

// ── Types ─────────────────────────────────────────────────────────────────────

type Stage =
  | "idle"
  | "uploading"
  | "normalizing"
  | "tier1"
  | "tier2"
  | "complete"
  | "error";

interface Props {
  onClose:    () => void;
  pipelineWsMessage?: PipelineWsMessage | null;
  /** Called once when a pipeline session reaches "complete" with real data */
  onComplete?: (result: PipelineCompletion) => void;
}

// ── Stage metadata ────────────────────────────────────────────────────────────

const STAGES: { key: Stage; label: string; sub: string }[] = [
  { key: "uploading",   label: "Uploading",          sub: "Streaming to secure buffer"        },
  { key: "normalizing", label: "Normalizing Schema",  sub: "Detecting dataset type & fields"   },
  { key: "tier1",       label: "Tier 1 Analysis",     sub: "Heuristic anomaly filter running"  },
  { key: "tier2",       label: "Tier 2 / MITRE Map",  sub: "ATT&CK enrichment & CISO metrics" },
  { key: "complete",    label: "Complete",             sub: "Pipeline verified & hash-chained" },
];

const STAGE_ORDER: Stage[] = ["uploading", "normalizing", "tier1", "tier2", "complete"];

function stageIndex(s: Stage): number {
  return STAGE_ORDER.indexOf(s);
}

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#e84d4d",
  HIGH:     "#f4a926",
  MEDIUM:   "#4e9af1",
  LOW:      "#72c811",
  INFO:     "#6b6e80",
};

// ── Error extraction ──────────────────────────────────────────────────────────

function extractError(err: any): { status: number | null; message: string } {
  const status: number | null = err?.response?.status ?? null;
  const data = err?.response?.data;
  let message = "Upload failed — check the backend terminal for details";

  if (data !== undefined && data !== null) {
    if (typeof data === "string" && data.length > 0) {
      message = data;
    } else if (typeof data === "object") {
      if (typeof data.detail === "string") message = data.detail;
      else if (data.detail !== undefined)  message = JSON.stringify(data.detail, null, 2);
      else if (typeof data.message === "string") message = data.message;
      else message = JSON.stringify(data, null, 2);
    }
  } else if (err?.message) {
    message = err.message;
  }

  return { status, message };
}

// ── Component ─────────────────────────────────────────────────────────────────

export function TelemetryUploader({ onClose, pipelineWsMessage, onComplete }: Props) {
  const qc = useQueryClient();

  const [stage,           setStage]           = useState<Stage>("idle");
  const [uploadPct,       setUploadPct]       = useState(0);
  const [sessionId,       setSessionId]       = useState<string | null>(null);
  const [uploadedFilename,setUploadedFilename]= useState<string>("");
  const [session,         setSession]         = useState<PipelineSession | null>(null);
  const [errorMsg,    setErrorMsg]    = useState<string | null>(null);
  const [errorStatus, setErrorStatus] = useState<number | null>(null);
  const [errorTrace,  setErrorTrace]  = useState<string | null>(null);
  const [dragOver,    setDragOver]    = useState(false);
  const [wsStage,     setWsStage]     = useState<string | null>(null);
  const [pollRows,    setPollRows]    = useState(0);
  const [pollAlerts,  setPollAlerts]  = useState(0);
  const [copied,      setCopied]      = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const cancelRef    = useRef<AbortController | null>(null);
  const pollingRef   = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Stop polling helper ───────────────────────────────────────────────────
  function stopPolling() {
    if (pollingRef.current !== null) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }

  // Cleanup on unmount
  useEffect(() => stopPolling, []);

  // ── Start polling after upload returns session_id ─────────────────────────
  function startPolling(sid: string) {
    stopPolling(); // safety: clear any previous interval

    pollingRef.current = setInterval(async () => {
      try {
        const s = await api.getSessionStatus(sid);
        setPollRows(s.rows_processed);
        setPollAlerts(s.alerts_found);

        if (s.status === "complete") {
          stopPolling();
          // The status endpoint now returns ciso_summary + chain_tip_hash on
          // completion — push directly to global state without an extra fetch.
          if (s.ciso_summary && s.chain_tip_hash && onComplete) {
            onComplete({
              session_id:     sid,
              filename:       uploadedFilename,
              chain_tip_hash: s.chain_tip_hash,
              ciso_summary:   s.ciso_summary,
              rows_processed: s.rows_processed,
              alerts_found:   s.alerts_found,
            });
          }
          // Still fetch full session for the modal CISO details display
          try {
            const full = await api.getPipelineSession(sid);
            setSession(full);
          } catch {
            // CISO fetch failed — still mark complete; dashboard will refresh
          }
          setStage("complete");
          qc.invalidateQueries({ queryKey: ["stats"] });
          qc.invalidateQueries({ queryKey: ["botsv3-dashboard"] });
          qc.invalidateQueries({ queryKey: ["cicids-stats"] });
          qc.invalidateQueries({ queryKey: ["pipeline-alerts"] });
        } else if (s.status === "error") {
          stopPolling();
          setErrorMsg("Backend analysis pipeline encountered an error — check server terminal.");
          setStage("error");
        }
        // "pending" / "running" → keep polling
      } catch (err: any) {
        // Transient network hiccup — do NOT clear the interval.
        // If the server is genuinely down, the WS disconnect will surface it.
        console.warn("[TelemetryUploader] poll error (non-fatal):", err?.message);
      }
    }, 2_500);
  }

  // ── WebSocket stage transitions (instant — no poll lag) ───────────────────
  useEffect(() => {
    if (!pipelineWsMessage) return;
    if (pipelineWsMessage.session_id !== sessionId) return;

    const t = pipelineWsMessage.type;

    if (t === "pipeline_stage") {
      const s = pipelineWsMessage.stage as Stage;
      if (s && stageIndex(s) > stageIndex(stage)) setStage(s);
      if (pipelineWsMessage.message) setWsStage(pipelineWsMessage.message);
    }

    if (t === "pipeline_progress") {
      // WS progress supersedes the poll values for this tick
      setPollRows(pipelineWsMessage.rows_processed);
      setPollAlerts(pipelineWsMessage.alerts_found);
    }

    if (t === "pipeline_complete") {
      // WS beat the poll — stop it and fetch full session
      stopPolling();
      setStage("complete");
      // Push to global state immediately from WS payload (no extra HTTP round-trip)
      if (pipelineWsMessage.ciso && pipelineWsMessage.chain_tip && onComplete) {
        onComplete({
          session_id:     pipelineWsMessage.session_id,
          filename:       pipelineWsMessage.filename,
          chain_tip_hash: pipelineWsMessage.chain_tip,
          ciso_summary:   pipelineWsMessage.ciso,
          rows_processed: pipelineWsMessage.rows_processed,
          alerts_found:   pipelineWsMessage.alerts_found,
        });
      }
      api.getPipelineSession(sessionId!).then(setSession).catch(() => {});
      qc.invalidateQueries({ queryKey: ["stats"] });
      qc.invalidateQueries({ queryKey: ["botsv3-dashboard"] });
      qc.invalidateQueries({ queryKey: ["cicids-stats"] });
    }

    if (t === "pipeline_error") {
      stopPolling();
      setStage("error");
      setErrorMsg(pipelineWsMessage.error ?? "Pipeline error — check server terminal");
      if (pipelineWsMessage.traceback) setErrorTrace(pipelineWsMessage.traceback);
    }
  }, [pipelineWsMessage, sessionId, stage, qc]);

  // ── Upload ────────────────────────────────────────────────────────────────
  const handleFile = useCallback(async (file: File) => {
    if (!file.name.toLowerCase().endsWith(".csv")) {
      setErrorMsg("Only .csv files are accepted.");
      setStage("error");
      return;
    }

    cancelRef.current = new AbortController();
    setStage("uploading");
    setUploadPct(0);
    setErrorMsg(null);
    setErrorStatus(null);
    setErrorTrace(null);
    setSessionId(null);
    setUploadedFilename(file.name);
    setSession(null);
    setPollRows(0);
    setPollAlerts(0);

    const form = new FormData();
    form.append("file", file);

    try {
      const { data } = await axios.post<{ session_id: string }>(
        "/api/upload-telemetry",
        form,
        {
          headers: { "Content-Type": "multipart/form-data" },
          signal:  cancelRef.current.signal,
          // No timeout: the only work done before the server responds is
          // streaming bytes to disk.  For 200 MB+ files on a slow drive this
          // can take tens of seconds — any fixed cap would be arbitrary.
          onUploadProgress: (e) => {
            if (e.total) setUploadPct(Math.round((e.loaded * 100) / e.total));
          },
        },
      );

      setUploadPct(100);
      setSessionId(data.session_id);
      setStage("normalizing");
      startPolling(data.session_id);   // begin polling immediately

    } catch (err: any) {
      if (axios.isCancel(err)) {
        setStage("idle");
        return;
      }
      const { status, message } = extractError(err);
      setErrorStatus(status);
      setErrorMsg(message);
      setStage("error");
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Drag & drop / file input ──────────────────────────────────────────────
  const onDrop = useCallback((e: DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }, [handleFile]);

  const onFileChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
    e.target.value = "";
  }, [handleFile]);

  function handleCancel() {
    cancelRef.current?.abort();
    stopPolling();
    setStage("idle");
    setErrorMsg(null);
  }

  function handleReset() {
    stopPolling();
    setStage("idle");
    setSessionId(null);
    setSession(null);
    setErrorMsg(null);
    setErrorStatus(null);
    setErrorTrace(null);
    setUploadPct(0);
    setWsStage(null);
    setPollRows(0);
    setPollAlerts(0);
    setCopied(false);
  }

  function handleCopyError() {
    const text = [
      errorStatus ? `HTTP ${errorStatus}` : null,
      errorMsg,
      errorTrace,
    ].filter(Boolean).join("\n\n");
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  const ciso    = session?.ciso_summary;
  const rows    = pollRows  || session?.rows_processed  || 0;
  const alerts  = pollAlerts || session?.alerts_found || 0;

  const fullErrorText = [
    errorMsg,
    errorTrace ? `\n--- Traceback ---\n${errorTrace}` : null,
  ].filter(Boolean).join("\n");

  // Progress label shown under the Tier 1 step while processing
  const processingLabel = rows > 0
    ? `${rows.toLocaleString()} rows analyzed${alerts > 0 ? ` — ${alerts.toLocaleString()} alerts flagged` : ""}`
    : null;

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40"
        style={{ background: "rgba(0,0,0,0.72)", backdropFilter: "blur(10px)" }}
        onClick={stage === "idle" || stage === "complete" || stage === "error" ? onClose : undefined}
      />

      {/* Modal */}
      <div className="fixed z-50 inset-0 flex items-center justify-center p-4 pointer-events-none">
        <div
          className="pointer-events-auto w-full max-w-xl rounded-2xl shadow-2xl overflow-hidden"
          style={{ background: "#131417", border: "1px solid #2a2b32" }}
        >
          {/* ── Header ──────────────────────────────────────────────────── */}
          <div
            className="flex items-center justify-between px-5 py-4"
            style={{ background: "#1a1b1f", borderBottom: "1px solid #2a2b32" }}
          >
            <div className="flex items-center gap-2.5">
              <div
                className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
                style={{
                  background: stage === "error"
                    ? "rgba(232,77,77,0.15)" : "rgba(78,154,241,0.15)",
                  border: `1px solid ${stage === "error"
                    ? "rgba(232,77,77,0.30)" : "rgba(78,154,241,0.30)"}`,
                }}
              >
                {stage === "error"
                  ? <XCircle className="w-3.5 h-3.5" style={{ color: "#e84d4d" }} />
                  : <Upload  className="w-3.5 h-3.5" style={{ color: "#4e9af1" }} />}
              </div>
              <div>
                <p className="text-sm font-semibold text-white leading-none">
                  {stage === "error" ? "Upload Error" : "Upload Telemetry Dataset"}
                </p>
                <p className="text-[10px] mt-0.5" style={{ color: "#4d5060" }}>
                  BOTSv3 · CICIDS-2017 · Zeek · Generic CSV
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="w-7 h-7 flex items-center justify-center rounded-lg transition-all hover:bg-white/5 active:opacity-60"
              style={{ color: "#4d5060" }}
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* ── Body ────────────────────────────────────────────────────── */}
          <div className="p-5 space-y-4">

            {/* Drop zone */}
            {stage === "idle" && (
              <div
                onDragOver={e => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={onDrop}
                onClick={() => fileInputRef.current?.click()}
                className="rounded-xl flex flex-col items-center justify-center gap-3 py-10 cursor-pointer transition-all"
                style={{
                  border: `2px dashed ${dragOver ? "#4e9af1" : "#2a2b32"}`,
                  background: dragOver ? "rgba(78,154,241,0.05)" : "rgba(255,255,255,0.02)",
                }}
              >
                <div
                  className="w-12 h-12 rounded-xl flex items-center justify-center"
                  style={{ background: "rgba(78,154,241,0.10)", border: "1px solid rgba(78,154,241,0.20)" }}
                >
                  <FileText className="w-5 h-5" style={{ color: "#4e9af1" }} />
                </div>
                <div className="text-center">
                  <p className="text-sm font-medium text-white">Drag &amp; drop a CSV file here</p>
                  <p className="text-[11px] mt-0.5" style={{ color: "#4d5060" }}>
                    or click to browse · 200 MB+ supported
                  </p>
                </div>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".csv"
                  className="hidden"
                  onChange={onFileChange}
                />
              </div>
            )}

            {/* Stage progress track */}
            {stage !== "idle" && stage !== "error" && (
              <div className="space-y-3">
                {STAGES.map((s, i) => {
                  const cur    = stageIndex(stage);
                  const idx    = stageIndex(s.key);
                  const done   = idx < cur || stage === "complete";
                  const active = s.key === stage;

                  return (
                    <div key={s.key} className="flex items-start gap-3">
                      <div className="shrink-0 mt-0.5">
                        {done ? (
                          <CheckCircle className="w-4 h-4" style={{ color: "#72c811" }} />
                        ) : active ? (
                          <Loader2 className="w-4 h-4 animate-spin" style={{ color: "#4e9af1" }} />
                        ) : (
                          <div className="w-4 h-4 rounded-full border-2" style={{ borderColor: "#2a2b32" }} />
                        )}
                      </div>

                      <div className="flex-1 min-w-0">
                        <p
                          className="text-xs font-semibold"
                          style={{ color: done ? "#72c811" : active ? "#f4f4f5" : "#3d3f4a" }}
                        >
                          {s.label}
                        </p>
                        <p className="text-[10px] mt-0.5" style={{ color: "#3d3f4a" }}>
                          {active && wsStage ? wsStage : s.sub}
                        </p>

                        {/* Upload progress bar */}
                        {s.key === "uploading" && active && (
                          <div className="mt-1.5 h-1 rounded-full overflow-hidden" style={{ background: "#2a2b32" }}>
                            <div
                              className="h-full rounded-full transition-all duration-300"
                              style={{ width: `${uploadPct}%`, background: "linear-gradient(90deg,#4e9af1,#06b6d4)" }}
                            />
                          </div>
                        )}

                        {/* Row counter — updated by polling every 2.5 s */}
                        {s.key === "tier1" && (active || done) && processingLabel && (
                          <p className="text-[10px] mt-0.5 font-mono tabular-nums" style={{ color: "#4e9af1" }}>
                            {processingLabel}
                          </p>
                        )}

                        {/* "Polled Xs ago" nudge so the user knows the number refreshes */}
                        {s.key === "tier1" && active && rows > 0 && (
                          <p className="text-[9px] mt-0.5" style={{ color: "#3d3f4a" }}>
                            updates every 2.5 s
                          </p>
                        )}
                      </div>

                      {i < STAGES.length - 1 && (
                        <ChevronRight className="shrink-0 mt-0.5 w-3 h-3" style={{ color: "#2a2b32" }} />
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* ── Error panel ───────────────────────────────────────────── */}
            {stage === "error" && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <XCircle className="w-4 h-4 shrink-0" style={{ color: "#e84d4d" }} />
                    <span className="text-xs font-semibold" style={{ color: "#e84d4d" }}>
                      {errorStatus ? `HTTP ${errorStatus} — ` : ""}
                      {errorStatus === 500 ? "Internal Server Error" :
                       errorStatus === 400 ? "Bad Request" :
                       errorStatus === 404 ? "Endpoint Not Found" :
                       errorStatus === 422 ? "Validation Error" :
                       errorStatus        ? "Request Failed" :
                                           "Upload Failed"}
                    </span>
                  </div>
                  <button
                    onClick={handleCopyError}
                    className="flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium transition-all active:opacity-60"
                    style={{ background: "rgba(232,77,77,0.10)", border: "1px solid rgba(232,77,77,0.25)", color: "#e84d4d" }}
                  >
                    {copied ? <><Check className="w-2.5 h-2.5" /> Copied</> : <><Copy className="w-2.5 h-2.5" /> Copy</>}
                  </button>
                </div>

                <div
                  className="rounded-lg overflow-auto"
                  style={{ background: "rgba(232,77,77,0.06)", border: "1px solid rgba(232,77,77,0.25)", maxHeight: "260px" }}
                >
                  <pre
                    className="p-3 text-[10px] leading-relaxed whitespace-pre-wrap break-all"
                    style={{ color: "#fca5a5", fontFamily: "JetBrains Mono, Consolas, monospace" }}
                  >
                    {fullErrorText || "No error detail received — check the backend terminal (uvicorn output)."}
                  </pre>
                </div>

                <p className="text-[9px]" style={{ color: "#4d5060" }}>
                  Full traceback is in the backend terminal. The message above is the exact Python exception returned by the server.
                </p>
              </div>
            )}

            {/* ── Complete: CISO results ────────────────────────────────── */}
            {stage === "complete" && ciso && (
              <div className="space-y-3 pt-1">
                <div className="grid grid-cols-3 gap-2">
                  {[
                    { label: "Alerts Found",      value: ciso.total_alerts.toLocaleString(),                                                        color: "#e84d4d" },
                    { label: "Analyst Hrs Saved", value: `${ciso.analyst_hours_saved}h`,                                                            color: "#72c811" },
                    { label: "Cost Avoided",      value: ciso.cost_avoided_usd >= 1000 ? `$${(ciso.cost_avoided_usd/1000).toFixed(0)}K` : `$${ciso.cost_avoided_usd}`, color: "#4e9af1" },
                  ].map(k => (
                    <div key={k.label} className="rounded-lg px-3 py-2.5" style={{ background: "#0d0d10", border: "1px solid #1a1a1f" }}>
                      <p className="text-[9px] uppercase tracking-widest font-semibold" style={{ color: "#4d5060" }}>{k.label}</p>
                      <p className="text-lg font-bold mt-0.5 font-mono leading-none" style={{ color: k.color }}>{k.value}</p>
                    </div>
                  ))}
                </div>

                {Object.keys(ciso.by_severity).length > 0 && (
                  <div className="rounded-lg p-3" style={{ background: "#0d0d10", border: "1px solid #1a1a1f" }}>
                    <p className="text-[9px] uppercase tracking-widest font-semibold mb-2" style={{ color: "#4d5060" }}>Severity Breakdown</p>
                    <div className="flex gap-3 flex-wrap">
                      {Object.entries(ciso.by_severity).map(([sev, cnt]) => (
                        <span key={sev} className="text-[11px] font-mono tabular-nums font-semibold" style={{ color: SEV_COLOR[sev] ?? "#6b6e80" }}>
                          {sev} <span className="font-bold">{(cnt as number).toLocaleString()}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {ciso.top_techniques.length > 0 && (
                  <div className="rounded-lg p-3" style={{ background: "#0d0d10", border: "1px solid #1a1a1f" }}>
                    <p className="text-[9px] uppercase tracking-widest font-semibold mb-2" style={{ color: "#4d5060" }}>Top MITRE ATT&CK Techniques</p>
                    <div className="space-y-1.5">
                      {ciso.top_techniques.slice(0, 5).map(t => {
                        const max = ciso.top_techniques[0]?.count || 1;
                        return (
                          <div key={t.id} className="flex items-center gap-2">
                            <span className="text-[9px] font-mono shrink-0 w-16" style={{ color: "#d946ef" }}>{t.id}</span>
                            <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: "#1a1a1f" }}>
                              <div className="h-full rounded-full" style={{ width: `${Math.round((t.count/max)*100)}%`, background: "linear-gradient(90deg,#d946ef,#8b5cf6)", opacity: 0.8 }} />
                            </div>
                            <span className="text-[9px] font-mono tabular-nums shrink-0" style={{ color: "#6b6e80" }}>{t.count.toLocaleString()}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {session?.chain_tip_hash && (
                  <div className="rounded-lg px-3 py-2.5 flex items-center gap-2" style={{ background: "rgba(114,200,17,0.06)", border: "1px solid rgba(114,200,17,0.20)" }}>
                    <Lock className="w-3.5 h-3.5 shrink-0" style={{ color: "#72c811" }} />
                    <div className="min-w-0">
                      <p className="text-[9px] uppercase tracking-widest font-semibold" style={{ color: "#72c811" }}>SHA-256 Chain Verified</p>
                      <p className="text-[9px] font-mono truncate mt-0.5" style={{ color: "#3d3f4a" }}>
                        tip: {session.chain_tip_hash.slice(0, 32)}…
                      </p>
                    </div>
                    <Shield className="w-3.5 h-3.5 shrink-0 ml-auto" style={{ color: "#72c811" }} />
                  </div>
                )}

                <p className="text-[10px] font-mono text-center" style={{ color: "#3d3f4a" }}>
                  {session?.dataset_type?.toUpperCase()} · {rows.toLocaleString()} rows · session {sessionId?.slice(0, 8)}
                </p>
              </div>
            )}

            {/* Complete but CISO summary still loading */}
            {stage === "complete" && !ciso && (
              <div className="flex items-center justify-center gap-2 py-4" style={{ color: "#4d5060" }}>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span className="text-xs">Finalising metrics…</span>
              </div>
            )}

            {/* No anomalies warning */}
            {stage === "complete" && ciso && ciso.total_alerts === 0 && (
              <div className="rounded-xl p-3 flex items-start gap-2" style={{ background: "rgba(244,169,38,0.08)", border: "1px solid rgba(244,169,38,0.22)" }}>
                <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" style={{ color: "#f4a926" }} />
                <p className="text-[11px]" style={{ color: "#f4a926" }}>
                  No anomalies detected. The file may be all-benign traffic or headers weren't recognised — try checking the schema.
                </p>
              </div>
            )}
          </div>

          {/* ── Footer ──────────────────────────────────────────────────── */}
          <div className="flex items-center justify-end gap-2 px-5 py-3" style={{ borderTop: "1px solid #2a2b32" }}>
            {(stage === "idle" || stage === "error") && (
              <button
                onClick={onClose}
                className="px-4 py-1.5 rounded text-xs font-medium transition-all active:opacity-70"
                style={{ background: "rgba(255,255,255,0.04)", border: "1px solid #2a2b32", color: "#6b6e80" }}
              >
                Close
              </button>
            )}
            {stage === "error" && (
              <button
                onClick={handleReset}
                className="px-4 py-1.5 rounded text-xs font-semibold transition-all active:scale-95"
                style={{ background: "rgba(78,154,241,0.12)", border: "1px solid rgba(78,154,241,0.35)", color: "#4e9af1" }}
              >
                Try Again
              </button>
            )}
            {stage === "uploading" && (
              <button
                onClick={handleCancel}
                className="px-4 py-1.5 rounded text-xs font-medium transition-all active:opacity-70"
                style={{ background: "rgba(232,77,77,0.08)", border: "1px solid rgba(232,77,77,0.25)", color: "#fca5a5" }}
              >
                Abort Upload
              </button>
            )}
            {(stage === "normalizing" || stage === "tier1" || stage === "tier2") && (
              <button
                onClick={handleCancel}
                className="px-4 py-1.5 rounded text-xs font-medium transition-all active:opacity-70"
                style={{ background: "rgba(255,255,255,0.03)", border: "1px solid #2a2b32", color: "#4d5060" }}
              >
                Cancel
              </button>
            )}
            {stage === "complete" && (
              <>
                <button
                  onClick={handleReset}
                  className="px-4 py-1.5 rounded text-xs font-medium transition-all active:opacity-70"
                  style={{ background: "rgba(255,255,255,0.04)", border: "1px solid #2a2b32", color: "#6b6e80" }}
                >
                  Upload Another
                </button>
                <button
                  onClick={onClose}
                  className="px-4 py-1.5 rounded text-xs font-semibold transition-all active:scale-95"
                  style={{ background: "rgba(114,200,17,0.12)", border: "1px solid rgba(114,200,17,0.35)", color: "#72c811" }}
                >
                  View Dashboard
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
