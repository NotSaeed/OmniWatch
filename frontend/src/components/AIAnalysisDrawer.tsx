import { X, Brain, Loader2 } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { api } from "../lib/api";
import type { LogFilters } from "./LogExplorer";

interface Props {
  sessionId: string | null;
  isOpen:    boolean;
  onClose:   () => void;
  activeFilters?: LogFilters;
}

export function AIAnalysisDrawer({ sessionId, isOpen, onClose, activeFilters }: Props) {
  const { data, isLoading, isError } = useQuery({
    queryKey:  ["ai-analysis", sessionId, activeFilters],
    queryFn:   () => api.analyzeSession(sessionId!, activeFilters),
    enabled:   isOpen && !!sessionId,
    staleTime: 5 * 60 * 1000,
    retry:     false,
  });

  if (!isOpen) return null;

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/50" onClick={onClose} />
      <div
        className="fixed right-0 top-0 bottom-0 z-50 w-full max-w-xl flex flex-col shadow-2xl overflow-hidden"
        style={{
          background:    "rgba(8,10,18,0.98)",
          borderLeft:    "1px solid rgba(217,70,239,0.25)",
          backdropFilter: "blur(16px)",
        }}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between px-5 py-4 border-b shrink-0"
          style={{ borderColor: "rgba(217,70,239,0.20)", background: "rgba(217,70,239,0.05)" }}
        >
          <div className="flex items-center gap-2.5">
            <Brain className="w-4 h-4 shrink-0" style={{ color: "#d946ef" }} />
            <div>
              <p className="text-sm font-semibold" style={{ color: "#e0aaff" }}>Phi-3 AI Analysis</p>
              <p className="text-[10px]" style={{ color: "#6b6e80" }}>
                {data?.alerts_analyzed != null
                  ? `${data.alerts_analyzed} alerts analyzed`
                  : "Session-level threat summary"}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-7 h-7 flex items-center justify-center rounded-lg text-slate-500
                       hover:text-slate-200 bg-slate-800/60 hover:bg-slate-700/60
                       border border-slate-700/50 active:scale-95 transition-all text-sm"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* AI / Heuristic badge */}
        {data && (
          <div className="px-5 py-2 border-b shrink-0" style={{ borderColor: "rgba(255,255,255,0.05)" }}>
            <span
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold"
              style={data.ai_generated
                ? { background: "rgba(139,92,246,0.15)", border: "1px solid rgba(139,92,246,0.40)", color: "#a78bfa" }
                : { background: "rgba(234,179,8,0.12)", border: "1px solid rgba(234,179,8,0.35)", color: "#fbbf24" }
              }
            >
              {data.ai_generated ? "AI-Generated · Phi-3" : "Heuristic Fallback · Ollama Offline"}
            </span>
          </div>
        )}

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-5">
          {isLoading ? (
            <div className="flex flex-col items-center justify-center gap-3 h-full" style={{ color: "#4d5060" }}>
              <Loader2 className="w-6 h-6 animate-spin" style={{ color: "#d946ef" }} />
              <p className="text-xs">Generating Phi-3 AI Summary…</p>
              <p className="text-[10px]" style={{ color: "#3d3f4a" }}>This may take 10–30 seconds</p>
            </div>
          ) : isError ? (
            <div className="flex flex-col items-center justify-center gap-2 h-full">
              <p className="text-xs text-red-400">Analysis failed. Check backend connection.</p>
            </div>
          ) : data ? (
            <div
              className="prose prose-invert prose-sm max-w-none
                         prose-headings:text-violet-300 prose-headings:font-semibold prose-headings:mt-4 prose-headings:mb-2
                         prose-p:text-slate-400 prose-p:leading-relaxed
                         prose-li:text-slate-400
                         prose-strong:text-slate-200
                         prose-code:text-cyan-400 prose-code:bg-slate-900 prose-code:px-1 prose-code:rounded
                         prose-em:text-slate-500"
            >
              <ReactMarkdown remarkPlugins={[remarkGfm]}>
                {data.report}
              </ReactMarkdown>
            </div>
          ) : null}
        </div>

        {/* Grounding footer */}
        <div
          className="px-5 py-3 border-t shrink-0 text-[9px] leading-relaxed"
          style={{ borderColor: "rgba(255,255,255,0.05)", color: "#3d3f4a" }}
        >
          Grounded on <span className="font-mono">telemetry_alerts</span> for session{" "}
          <span className="font-mono">{sessionId?.substring(0, 8)}…</span>
          {" "}· Review all AI output critically — automated analysis may miss context or contain errors.
        </div>
      </div>
    </>
  );
}
