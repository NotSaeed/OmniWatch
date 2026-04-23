import { useEffect, useRef } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { toast } from "sonner";
import type { Components } from "react-markdown";
import type { CicidsLog, CtiEnrichment, MitreTechnique } from "../lib/types";
import { SEVERITY_BADGE } from "../lib/utils";

interface Props {
  log:          CicidsLog;
  report:       string | null;     // null = still loading
  cti:          CtiEnrichment | null;
  aiGenerated:  boolean;
  onClose:      () => void;
}

// ── Dark-theme markdown component map ────────────────────────────────────────

const MD: Components = {
  h2: ({ children }) => (
    <h2 className="text-[11px] font-bold text-slate-200 mt-6 mb-2 pb-1.5 uppercase tracking-wider
                   border-b border-slate-800/60 first:mt-0 flex items-center gap-2">
      <span className="w-0.5 h-3.5 rounded-full bg-cyan-500/50 shrink-0" />
      {children}
    </h2>
  ),
  h3: ({ children }) => (
    <h3 className="text-xs font-semibold text-slate-300 mt-4 mb-1.5">{children}</h3>
  ),
  p: ({ children }) => (
    <p className="text-xs text-slate-300 leading-relaxed mb-2.5 break-words">{children}</p>
  ),
  strong: ({ children }) => (
    <strong className="font-semibold text-slate-100">{children}</strong>
  ),
  em: ({ children }) => (
    <em className="italic text-slate-500">{children}</em>
  ),
  ul: ({ children }) => <ul className="space-y-1 mb-2.5 ml-3">{children}</ul>,
  ol: ({ children }) => <ol className="space-y-1 mb-2.5 ml-3 list-decimal">{children}</ol>,
  li: ({ children }) => (
    <li className="text-xs text-slate-300 leading-relaxed flex gap-2 break-words">
      <span className="text-cyan-600 shrink-0 mt-0.5">›</span>
      <span className="min-w-0 break-words">{children}</span>
    </li>
  ),
  code: ({ children, className }) => {
    const isBlock = !!className;
    return isBlock ? (
      <pre className="my-2.5 rounded border border-slate-800/60 p-3 overflow-x-auto"
           style={{ background: "#0d1117" }}>
        <code className="text-[11px] font-mono text-emerald-300 break-words whitespace-pre-wrap">{children}</code>
      </pre>
    ) : (
      <code className="px-1.5 py-0.5 rounded bg-slate-800/80 text-cyan-300 text-[11px] font-mono border border-slate-700/40 break-all">
        {children}
      </code>
    );
  },
  blockquote: ({ children }) => (
    <blockquote className="border-l-2 border-cyan-700/60 pl-3 my-3 bg-cyan-950/20 rounded-r py-2 pr-3 text-slate-400 italic text-sm">
      {children}
    </blockquote>
  ),
  table: ({ children }) => (
    <div className="overflow-x-auto mb-3 rounded-lg border border-slate-800/50">
      <table className="w-full text-xs border-collapse">{children}</table>
    </div>
  ),
  thead: ({ children }) => (
    <thead style={{ background: "rgba(15,23,42,0.80)" }}>{children}</thead>
  ),
  tr: ({ children }) => (
    <tr className="border-b border-slate-800/40">{children}</tr>
  ),
  th: ({ children }) => (
    <th className="px-3 py-2 text-left text-[10px] uppercase tracking-wider text-slate-500 font-semibold">{children}</th>
  ),
  td: ({ children }) => (
    <td className="px-3 py-2 text-slate-300 font-mono text-[11px]">{children}</td>
  ),
  hr: () => <hr className="my-5 border-slate-800/60" />,
};

// ── Skeleton loader ───────────────────────────────────────────────────────────

function Skeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="flex items-center gap-2 text-xs text-cyan-500">
        <span className="w-2 h-2 rounded-full bg-cyan-500 animate-ping" />
        AI Analyst is investigating…
      </div>
      {/* Fake section header */}
      <div className="h-2.5 w-40 rounded-md bg-slate-800" />
      {[80, 55, 90, 65, 70].map((w, i) => (
        <div key={i} className="h-2.5 rounded-md bg-slate-800/70" style={{ width: `${w}%` }} />
      ))}
      <div className="h-px bg-slate-800/60" />
      <div className="h-2.5 w-32 rounded-md bg-slate-800" />
      {[60, 85, 50].map((w, i) => (
        <div key={i} className="h-2.5 rounded-md bg-slate-800/70" style={{ width: `${w}%` }} />
      ))}
    </div>
  );
}

// ── CTI Enrichment panel ──────────────────────────────────────────────────────

function AbuseScore({ score }: { score: number }) {
  const pct   = Math.min(100, Math.max(0, score));
  const color =
    pct >= 75 ? "bg-red-500"
    : pct >= 40 ? "bg-orange-500"
    : pct >= 15 ? "bg-yellow-500"
    : "bg-green-500";
  const label =
    pct >= 75 ? "MALICIOUS"
    : pct >= 40 ? "SUSPICIOUS"
    : pct >= 15 ? "LOW RISK"
    : "CLEAN";
  const textColor =
    pct >= 75 ? "text-red-400"
    : pct >= 40 ? "text-orange-400"
    : pct >= 15 ? "text-yellow-400"
    : "text-green-400";

  return (
    <div className="flex items-center gap-2">
      <div className="relative w-28 h-2 rounded-full bg-gray-800 overflow-hidden">
        <div className={`absolute inset-y-0 left-0 rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-[11px] font-bold font-mono ${textColor}`}>{pct}%</span>
      <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${textColor} bg-gray-900 border border-current/30`}>
        {label}
      </span>
    </div>
  );
}

function VtScore({ malicious, total }: { malicious: number; total: number }) {
  const ratio = total > 0 ? malicious / total : 0;
  const color =
    ratio >= 0.2  ? "text-red-400 border-red-800 bg-red-950/40"
    : ratio >= 0.05 ? "text-orange-400 border-orange-800 bg-orange-950/40"
    : "text-green-400 border-green-800 bg-green-950/40";
  return (
    <span className={`text-[11px] font-mono font-bold px-2 py-0.5 rounded border ${color}`}>
      {malicious}/{total}
    </span>
  );
}

function MitreBadge({ tech }: { tech: MitreTechnique }) {
  const tacticColors: Record<string, string> = {
    "Reconnaissance":        "bg-gray-800  border-gray-600  text-gray-300",
    "Initial Access":        "bg-red-950   border-red-700   text-red-300",
    "Execution":             "bg-orange-950 border-orange-700 text-orange-300",
    "Persistence":           "bg-yellow-950 border-yellow-700 text-yellow-300",
    "Privilege Escalation":  "bg-amber-950 border-amber-700  text-amber-300",
    "Defense Evasion":       "bg-lime-950  border-lime-700   text-lime-300",
    "Credential Access":     "bg-emerald-950 border-emerald-700 text-emerald-300",
    "Discovery":             "bg-cyan-950  border-cyan-700   text-cyan-300",
    "Lateral Movement":      "bg-sky-950   border-sky-700    text-sky-300",
    "Collection":            "bg-blue-950  border-blue-700   text-blue-300",
    "Command and Control":   "bg-indigo-950 border-indigo-700 text-indigo-300",
    "Exfiltration":          "bg-violet-950 border-violet-700 text-violet-300",
    "Impact":                "bg-purple-950 border-purple-700 text-purple-300",
  };
  const cls = tacticColors[tech.tactic] ?? "bg-gray-800 border-gray-600 text-gray-300";

  return (
    <span
      title={`${tech.tactic} — ${tech.name}`}
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-mono ${cls}`}
    >
      <span className="font-bold">{tech.id}</span>
      <span className="opacity-70 hidden sm:inline truncate max-w-[120px]">{tech.name}</span>
    </span>
  );
}

function CtiPanel({ cti }: { cti: CtiEnrichment }) {
  const abuse  = cti.abuseipdb;
  const vt     = cti.virustotal;
  const mitre  = cti.mitre ?? [];

  const hasAbuse = !abuse.skipped && !abuse.error;
  const hasVt    = !vt.skipped;

  return (
    <div className="rounded border border-blue-900/50 bg-blue-950/20 px-4 py-3 mb-4 space-y-3">
      {/* Header */}
      <div className="flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-widest text-blue-400 font-semibold">
          CTI Enrichment
        </span>
        {cti.ip && (
          <span className="font-mono text-[10px] text-gray-500">{cti.ip}</span>
        )}
        <span className="ml-auto text-[10px] text-gray-700 italic">AbuseIPDB · VirusTotal (mock) · MITRE ATT&CK</span>
      </div>

      <div className="grid grid-cols-1 gap-2.5">

        {/* AbuseIPDB row */}
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-[10px] text-gray-500 w-20 shrink-0">AbuseIPDB</span>
          {hasAbuse ? (
            <>
              <AbuseScore score={abuse.abuse_confidence_score ?? 0} />
              {abuse.country_code && (
                <span className="text-[10px] text-gray-500 font-mono">
                  {abuse.country_code}
                </span>
              )}
              {abuse.isp && (
                <span className="text-[10px] text-gray-600 truncate max-w-[200px]" title={abuse.isp}>
                  {abuse.isp}
                </span>
              )}
              {abuse.total_reports != null && abuse.total_reports > 0 && (
                <span className="text-[10px] text-gray-600">{abuse.total_reports} report{abuse.total_reports !== 1 ? "s" : ""}</span>
              )}
              {abuse.is_tor && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800">TOR</span>
              )}
            </>
          ) : abuse.skipped ? (
            <span className="text-[10px] text-gray-600 italic">
              {abuse.reason === "no_api_key" ? "API key not configured" : "no public IP"}
            </span>
          ) : (
            <span className="text-[10px] text-gray-600 italic">unavailable — {abuse.error}</span>
          )}
        </div>

        {/* VirusTotal row */}
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-[10px] text-gray-500 w-20 shrink-0">VirusTotal</span>
          {hasVt ? (
            <>
              <VtScore malicious={vt.malicious ?? 0} total={vt.total_engines ?? 80} />
              {vt.threat_label && vt.threat_label !== "clean" && (
                <span className="text-[10px] text-orange-400 font-mono">{vt.threat_label}</span>
              )}
            </>
          ) : (
            <span className="text-[10px] text-gray-600 italic">no IP available</span>
          )}
        </div>

        {/* MITRE row */}
        {mitre.length > 0 && (
          <div className="flex flex-wrap items-start gap-1.5">
            <span className="text-[10px] text-gray-500 w-20 shrink-0 mt-0.5">MITRE</span>
            <div className="flex flex-wrap gap-1.5">
              {mitre.map(t => <MitreBadge key={t.id} tech={t} />)}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function displayIp(ip: string | null | undefined): string {
  return ip && ip !== "-" && ip !== "N/A" ? ip : "Unknown-Source";
}

// ── PDF export ────────────────────────────────────────────────────────────────

function buildPdfHtml(
  log: CicidsLog,
  reportHtml: string,
  cti: CtiEnrichment | null,
): string {
  const abuse  = cti?.abuseipdb;
  const vt     = cti?.virustotal;
  const mitre  = cti?.mitre ?? [];
  const now    = new Date();
  const ts     = now.toLocaleString("en-US", {
    year: "numeric", month: "long", day: "numeric",
    hour: "2-digit", minute: "2-digit", timeZoneName: "short",
  });

  const severityColor: Record<string, string> = {
    CRITICAL: "#dc2626", HIGH: "#ea580c", MEDIUM: "#ca8a04",
    LOW: "#4ade80", INFO: "#9ca3af",
  };
  const sevColor = severityColor[log.severity] ?? "#9ca3af";

  const ctiSection = cti ? `
    <div class="cti-block">
      <div class="cti-header">
        <span class="cti-title">🔍 Cyber Threat Intelligence Enrichment</span>
        <span class="cti-ip">${cti.ip ?? "No IP"}</span>
      </div>
      <table class="cti-table">
        <tr>
          <th>AbuseIPDB Score</th>
          <td>${abuse && !abuse.skipped && !abuse.error
            ? `<span class="score-badge" style="background:${
                (abuse.abuse_confidence_score ?? 0) >= 75 ? "#fee2e2" :
                (abuse.abuse_confidence_score ?? 0) >= 40 ? "#ffedd5" : "#dcfce7"
              };color:${
                (abuse.abuse_confidence_score ?? 0) >= 75 ? "#991b1b" :
                (abuse.abuse_confidence_score ?? 0) >= 40 ? "#9a3412" : "#166534"
              };">${abuse.abuse_confidence_score ?? 0}% confidence</span>
              &nbsp; ${abuse.country_code ?? ""} · ${abuse.isp ?? ""} · ${abuse.total_reports ?? 0} community reports
              ${abuse.is_tor ? '<span class="badge-red">TOR EXIT NODE</span>' : ""}`
            : `<em>${abuse?.reason === "no_api_key" ? "API key not configured — add ABUSEIPDB_API_KEY to .env" : "Unavailable"}</em>`
          }</td>
        </tr>
        <tr>
          <th>VirusTotal Engines</th>
          <td>${vt && !vt.skipped
            ? `<span class="score-badge" style="background:${
                (vt.malicious ?? 0) > 15 ? "#fee2e2" :
                (vt.malicious ?? 0) > 4  ? "#ffedd5" : "#dcfce7"
              };color:${
                (vt.malicious ?? 0) > 15 ? "#991b1b" :
                (vt.malicious ?? 0) > 4  ? "#9a3412" : "#166534"
              };">${vt.malicious ?? 0}/${vt.total_engines ?? 80} malicious</span>
              &nbsp; Threat: ${vt.threat_label ?? "clean"}`
            : "<em>No IP available</em>"
          }</td>
        </tr>
        ${mitre.length > 0 ? `<tr>
          <th>MITRE ATT&amp;CK</th>
          <td>${mitre.map(t =>
            `<span class="mitre-badge">${t.id}</span> ${t.name} <em style="color:#666">(${t.tactic})</em>`
          ).join("<br>")}</td>
        </tr>` : ""}
      </table>
    </div>` : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>IR Report — ${log.label} — ${displayIp(log.src_ip)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
      font-size: 11.5px; color: #1a1a2e; line-height: 1.65;
      padding: 0; background: #fff;
    }

    /* ── Page header ── */
    .page-header {
      background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
      color: white; padding: 20px 32px 16px;
      border-bottom: 3px solid #3b82f6;
    }
    .page-header .brand { font-size: 20px; font-weight: 800; letter-spacing: -0.5px; }
    .page-header .brand span { color: #60a5fa; }
    .page-header .tagline { font-size: 9px; color: #94a3b8; text-transform: uppercase;
                             letter-spacing: 2px; margin-top: 2px; }
    .page-header .doc-type { font-size: 10px; color: #94a3b8; margin-top: 8px; }

    /* ── Alert banner ── */
    .alert-banner {
      padding: 12px 32px;
      border-bottom: 1px solid #e2e8f0;
      background: #f8fafc;
      display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
    }
    .sev-badge {
      display: inline-block; padding: 3px 10px; border-radius: 4px;
      font-size: 10px; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.08em; color: white;
      background: ${sevColor};
    }
    .alert-label { font-size: 15px; font-weight: 700; color: #0f172a; flex: 1; }
    .alert-meta { font-size: 10px; color: #64748b; font-family: "Courier New", monospace; }

    /* ── Body ── */
    .body { padding: 24px 32px; }

    /* ── CTI block ── */
    .cti-block {
      border: 1px solid #bfdbfe; border-radius: 6px;
      background: #eff6ff; padding: 14px 16px; margin-bottom: 20px;
    }
    .cti-header { display: flex; align-items: center; justify-content: space-between;
                  margin-bottom: 10px; }
    .cti-title { font-size: 11px; font-weight: 700; text-transform: uppercase;
                 letter-spacing: 0.06em; color: #1e40af; }
    .cti-ip { font-family: "Courier New", monospace; font-size: 11px; color: #475569;
              background: #dbeafe; padding: 2px 8px; border-radius: 3px; }
    .cti-table { width: 100%; border-collapse: collapse; font-size: 11px; }
    .cti-table th { text-align: left; padding: 5px 10px; background: #dbeafe;
                    color: #1e40af; font-weight: 600; width: 160px;
                    border: 1px solid #bfdbfe; }
    .cti-table td { padding: 5px 10px; border: 1px solid #bfdbfe; color: #1e293b; }
    .score-badge { display: inline-block; padding: 1px 8px; border-radius: 3px;
                   font-weight: 700; font-size: 11px; }
    .mitre-badge { display: inline-block; background: #ede9fe; color: #4c1d95;
                   border: 1px solid #c4b5fd; padding: 1px 6px; border-radius: 3px;
                   font-family: "Courier New", monospace; font-size: 10px;
                   font-weight: 700; margin-right: 4px; }
    .badge-red { display: inline-block; background: #fee2e2; color: #991b1b;
                 border: 1px solid #fca5a5; padding: 1px 6px; border-radius: 3px;
                 font-size: 10px; font-weight: 700; margin-left: 4px; }

    /* ── Report body typography ── */
    h2 { font-size: 12.5px; font-weight: 700; color: #0f172a; margin: 20px 0 8px;
         padding-bottom: 4px; border-bottom: 2px solid #e2e8f0;
         text-transform: uppercase; letter-spacing: 0.04em; }
    h3 { font-size: 11.5px; font-weight: 600; color: #334155; margin: 12px 0 4px; }
    p  { margin-bottom: 10px; color: #334155; }
    ul, ol { margin: 6px 0 10px 18px; }
    li { margin-bottom: 4px; }
    strong { color: #0f172a; font-weight: 700; }
    em { color: #64748b; }
    code { background: #f1f5f9; padding: 1px 5px; border-radius: 3px;
           font-family: "Courier New", monospace; font-size: 10.5px; color: #1e293b; }
    pre  { background: #f8fafc; border: 1px solid #e2e8f0; padding: 10px;
           border-radius: 4px; overflow-x: auto; margin: 8px 0; }
    pre code { background: none; padding: 0; font-size: 10.5px; }
    table { border-collapse: collapse; width: 100%; margin: 8px 0 12px; font-size: 11px; }
    table th { background: #f1f5f9; padding: 5px 10px; text-align: left;
               font-weight: 600; border: 1px solid #e2e8f0; }
    table td { padding: 5px 10px; border: 1px solid #e2e8f0; }
    blockquote { border-left: 3px solid #3b82f6; padding: 6px 12px; margin: 8px 0;
                 background: #eff6ff; color: #334155; font-style: italic; }
    hr { border: none; border-top: 1px solid #e2e8f0; margin: 16px 0; }

    /* ── Footer ── */
    .page-footer {
      border-top: 1px solid #e2e8f0; padding: 10px 32px;
      background: #f8fafc; margin-top: 24px;
      display: flex; justify-content: space-between; align-items: center;
      font-size: 9px; color: #94a3b8;
    }
    .tlp-badge { background: #fef3c7; color: #92400e; border: 1px solid #fbbf24;
                 padding: 2px 8px; border-radius: 3px; font-weight: 700;
                 font-size: 9px; letter-spacing: 0.06em; }

    @media print {
      body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .page-header { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      h2 { page-break-after: avoid; }
      pre, blockquote { page-break-inside: avoid; }
    }
  </style>
</head>
<body>

  <div class="page-header">
    <div class="brand">Omni<span>Watch</span></div>
    <div class="tagline">AI-Powered Security Operations Center · CITREX 2026</div>
    <div class="doc-type">Incident Response Report · Tier 2 AI Analysis · TLP:AMBER</div>
  </div>

  <div class="alert-banner">
    <span class="sev-badge">${log.severity}</span>
    <span class="alert-label">${log.label}</span>
    <span class="alert-meta">
      ${displayIp(log.src_ip)} → ${displayIp(log.dst_ip)}:${log.dst_port ?? "?"}
      &nbsp;|&nbsp; Source: ${log.source_file}
      &nbsp;|&nbsp; Generated: ${ts}
    </span>
  </div>

  <div class="body">
    ${ctiSection}
    ${reportHtml}
  </div>

  <div class="page-footer">
    <span>OmniWatch AI-SOC · Powered by Phi-3-Mini (Ollama) · Confidential</span>
    <span class="tlp-badge">TLP: AMBER</span>
    <span>Report ID: IR-${Date.now().toString(36).toUpperCase()}</span>
  </div>

</body>
</html>`;
}

// ── Main component ────────────────────────────────────────────────────────────

export function IncidentReportModal({ log, report, cti, aiGenerated, onClose }: Props) {
  const reportBodyRef = useRef<HTMLDivElement>(null);

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  function handleExportPdf() {
    const reportHtml = reportBodyRef.current?.innerHTML ?? "";
    const win = window.open("", "_blank");
    if (!win) return;
    win.document.write(buildPdfHtml(log, reportHtml, cti));
    win.document.close();
    win.onload = () => win.print();
    win.focus();
    toast.success("Executive PDF exported", {
      description: `${log.label} · ${displayIp(log.src_ip)} — print dialog opened`,
      duration: 4000,
    });
  }

  return (
    <>
      {/* Backdrop — heavy blur for classified-document feel */}
      <div
        className="fixed inset-0 z-40"
        style={{ background: "rgba(0,0,0,0.75)", backdropFilter: "blur(16px)" }}
        onClick={onClose}
      />

      {/* Slide-over panel */}
      <aside
        className="fixed right-0 top-0 bottom-0 z-50 w-full max-w-[640px] flex flex-col
                   shadow-2xl anim-fade-up"
        style={{ background: "#1a1b1f", borderLeft: "1px solid #2e3038" }}
      >
        {/* Top accent bar */}
        <div className="h-0.5 shrink-0" style={{ background: "var(--splunk-green)" }} />

        {/* Header */}
        <div className="flex items-start gap-3 px-5 py-4 shrink-0"
             style={{ background: "#222429", borderBottom: "1px solid #2e3038" }}>
          <div className="flex-1 min-w-0">
            {/* Classification tag */}
            <div className="flex items-center gap-2 mb-2">
              <span className="text-[9px] font-bold uppercase tracking-widest text-amber-500/80
                               border border-amber-500/30 bg-amber-950/30 px-1.5 py-0.5 rounded">
                TLP:AMBER
              </span>
              <span className="text-[9px] text-slate-600 uppercase tracking-widest">AI Tier 2 Analysis</span>
            </div>
            {/* Alert identity */}
            <div className="flex items-center gap-2 mb-1">
              <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold uppercase shrink-0 ${SEVERITY_BADGE[log.severity] ?? ""}`}>
                {log.severity}
              </span>
              <span className="text-sm font-semibold text-slate-100 truncate">{log.label}</span>
            </div>
            <p className="text-xs text-slate-500 font-mono">
              {displayIp(log.src_ip)}
              <span className="text-slate-700 mx-1">→</span>
              {displayIp(log.dst_ip)}:{log.dst_port ?? "?"}
              {log.protocol != null ? <span className="text-slate-700"> · proto {log.protocol}</span> : ""}
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={handleExportPdf}
              disabled={!report}
              title="Export executive PDF report"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium
                         border border-cyan-700/50 bg-cyan-950/40 text-cyan-300
                         hover:bg-cyan-900/50 hover:border-cyan-600/50
                         shadow-[0_0_10px_rgba(6,182,212,0.15)] hover:shadow-[0_0_16px_rgba(6,182,212,0.3)]
                         active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              <span className="text-sm leading-none">⬇</span>
              Export PDF
            </button>
            <button
              onClick={onClose}
              className="w-7 h-7 flex items-center justify-center rounded-lg text-slate-500
                         hover:text-slate-200 bg-slate-800/60 hover:bg-slate-700/60
                         border border-slate-700/50 transition-all text-sm"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Metadata strip */}
        <div className="flex flex-wrap gap-x-4 gap-y-1 px-5 py-2 text-[10px] font-mono shrink-0"
             style={{ background: "#1e1f23", borderBottom: "1px solid #2e3038", color: "#6b6e80" }}>
          {log.flow_duration != null && (
            <span>duration: <span className="text-slate-500">{(log.flow_duration / 1_000_000).toFixed(3)}s</span></span>
          )}
          {log.flow_bytes_s != null && (
            <span>bytes/s: <span className="text-slate-500">{log.flow_bytes_s.toFixed(1)}</span></span>
          )}
          <span>src: <span className="text-slate-500">{log.source_file}</span></span>
          <span>cat: <span className="text-slate-500">{log.category}</span></span>
        </div>

        {/* Report body */}
        <div className="flex-1 overflow-y-auto px-5 py-5 min-w-0" style={{ wordBreak: "break-word", overflowWrap: "break-word" }}>
          {/* CTI panel */}
          {cti ? (
            <CtiPanel cti={cti} />
          ) : report === null ? (
            <div className="rounded-xl border border-cyan-900/30 bg-cyan-950/10 px-4 py-3 mb-4 animate-pulse">
              <div className="h-2.5 w-36 rounded-md bg-slate-800 mb-3" />
              {[90, 70, 55].map((w, i) => (
                <div key={i} className="h-2 rounded-md bg-slate-800/70 mb-2" style={{ width: `${w}%` }} />
              ))}
            </div>
          ) : null}

          {report === null ? (
            <Skeleton />
          ) : (
            <div ref={reportBodyRef}>
              {!aiGenerated && (
                <div className="rounded-lg border border-amber-700/40 bg-amber-950/20 px-4 py-3 mb-4 flex items-start gap-2">
                  <span className="text-amber-400 text-sm shrink-0 mt-0.5">⚠</span>
                  <div>
                    <p className="text-xs font-semibold text-amber-300">Local Fallback Report</p>
                    <p className="text-[11px] text-amber-500/80 mt-0.5">
                      Ollama (Phi-3-Mini) is not connected. This report was generated from a deterministic
                      template using real event data — not by an AI model. Start Ollama for full AI-generated analysis.
                    </p>
                  </div>
                </div>
              )}
              <ReactMarkdown remarkPlugins={[remarkGfm]} components={MD}>
                {report}
              </ReactMarkdown>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 shrink-0 flex items-center justify-between"
             style={{ background: "#222429", borderTop: "1px solid #2e3038" }}>
          <div className="flex items-center gap-2">
            <span className="w-1 h-1 rounded-full bg-cyan-500 anim-glow" />
            <span className="text-[10px] text-slate-700">
              {aiGenerated ? "Powered by Phi-3-Mini (Ollama) · OmniWatch AI-SOC" : "Deterministic Template · Ollama Offline"}
            </span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg text-xs text-slate-400 hover:text-slate-200
                       bg-slate-800/60 hover:bg-slate-700/60 border border-slate-700/50 transition-all"
          >
            Close
          </button>
        </div>
      </aside>
    </>
  );
}
