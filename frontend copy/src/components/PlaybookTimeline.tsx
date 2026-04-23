/**
 * PlaybookTimeline — n8n / Splunk SOAR visual workflow canvas.
 *
 * Each SOAR execution renders as a full-width workflow card containing a
 * horizontal chain of connected node cards:
 *
 *   ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
 *   │ TRIGGER  │ ──▶ │CONDITION │ ──▶ │  ENRICH  │ ──▶ │  MITRE  │ ──▶ │  ACTION  │
 *   │ Critical │     │AI Check  │     │AbuseIPDB │     │ATT&CK   │     │ Block IP │
 *   │  Alert   │     │Severity≥ │     │+ VT scan │     │ Mapped  │     │ Block IP  │
 *   └──────────┘     └──────────┘     └──────────┘     └──────────┘     └──────────┘
 */

import type { CicidsPlaybookLog } from "../lib/types";

// ── Palette ───────────────────────────────────────────────────────────────────

const C = {
  trigger:   "#e84d4d",
  condition: "#4e9af1",
  enrich:    "#8b5cf6",
  mitre:     "#00d4c8",
  action:    "#72c811",
  notify:    "#f4a926",
} as const;

type NodeType = keyof typeof C;

// ── SVG icons (inline — no external deps) ─────────────────────────────────────

function IconLightning() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  );
}
function IconBranch() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="18" cy="18" r="3" /><circle cx="6" cy="6" r="3" /><circle cx="6" cy="18" r="3" />
      <path d="M6 9v3a3 3 0 0 0 3 3h3" /><line x1="6" y1="9" x2="6" y2="15" />
    </svg>
  );
}
function IconGlobe() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  );
}
function IconGrid() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" />
      <rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" />
    </svg>
  );
}
function IconShield() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <line x1="9" y1="12" x2="15" y2="12" /><line x1="12" y1="9" x2="12" y2="15" />
    </svg>
  );
}
function IconLock() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}
function IconGauge() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2v4M4.93 4.93l2.83 2.83M2 12h4M4.93 19.07l2.83-2.83M12 22v-4M19.07 19.07l-2.83-2.83M22 12h-4M19.07 4.93l-2.83 2.83" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}
function IconKey() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="7.5" cy="15.5" r="5.5" />
      <path d="M21 2l-9.6 9.6M15.5 7.5l3 3L22 7l-3-3" />
    </svg>
  );
}
function IconBell() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.73 21a2 2 0 0 1-3.46 0" />
    </svg>
  );
}
function IconEye() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}
function IconScissors() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="6" cy="6" r="3" /><circle cx="6" cy="18" r="3" />
      <line x1="20" y1="4" x2="8.12" y2="15.88" />
      <line x1="14.47" y1="14.48" x2="20" y2="20" />
      <line x1="8.12" y1="8.12" x2="12" y2="12" />
    </svg>
  );
}
function IconChart() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="20" x2="18" y2="10" /><line x1="12" y1="20" x2="12" y2="4" />
      <line x1="6" y1="20" x2="6" y2="14" /><line x1="2" y1="20" x2="22" y2="20" />
    </svg>
  );
}
function IconHash() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="4" y1="9" x2="20" y2="9" /><line x1="4" y1="15" x2="20" y2="15" />
      <line x1="10" y1="3" x2="8" y2="21" /><line x1="16" y1="3" x2="14" y2="21" />
    </svg>
  );
}
function IconFile() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="8" y1="13" x2="16" y2="13" /><line x1="8" y1="17" x2="12" y2="17" />
    </svg>
  );
}
function IconStop() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <rect x="9" y="9" width="6" height="6" />
    </svg>
  );
}
function IconSearch() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
         strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  );
}

// ── Step definitions ──────────────────────────────────────────────────────────

interface StepDef {
  type:       NodeType;
  icon:       React.ReactNode;
  label:      string;
  sublabel:   string;
  isAction?:  boolean;
}

const PLAYBOOK_STEPS: Record<string, StepDef[]> = {
  Block_IP_Playbook: [
    { type: "trigger",   icon: <IconLightning />, label: "Trigger",       sublabel: "Critical alert received"     },
    { type: "condition", icon: <IconBranch />,    label: "AI Analysis",   sublabel: "Severity threshold passed"   },
    { type: "enrich",    icon: <IconGlobe />,     label: "CTI Lookup",    sublabel: "AbuseIPDB + VirusTotal"      },
    { type: "mitre",     icon: <IconGrid />,      label: "MITRE Map",     sublabel: "ATT&CK technique resolved"   },
    { type: "action",    icon: <IconShield />,    label: "Block IP",      sublabel: "Firewall ingress ACL", isAction: true },
  ],
  Isolate_Host_Playbook: [
    { type: "trigger",   icon: <IconLightning />, label: "Trigger",       sublabel: "Malware signature matched"   },
    { type: "condition", icon: <IconBranch />,    label: "Risk Check",    sublabel: "Confidence ≥ 0.80"           },
    { type: "enrich",    icon: <IconSearch />,    label: "Scan Host",     sublabel: "Endpoint telemetry"          },
    { type: "mitre",     icon: <IconGrid />,      label: "MITRE Map",     sublabel: "ATT&CK technique resolved"   },
    { type: "action",    icon: <IconLock />,      label: "Isolate Host",  sublabel: "VLAN quarantine applied", isAction: true },
  ],
  C2_Containment_Playbook: [
    { type: "trigger",   icon: <IconLightning />, label: "Trigger",       sublabel: "C2 beacon identified"        },
    { type: "condition", icon: <IconBranch />,    label: "Beacon Check",  sublabel: "Interval pattern matched"    },
    { type: "enrich",    icon: <IconGlobe />,     label: "VT Check",      sublabel: "VirusTotal IP reputation"    },
    { type: "mitre",     icon: <IconGrid />,      label: "MITRE Map",     sublabel: "T1071 C2 over HTTP"          },
    { type: "action",    icon: <IconScissors />,  label: "Kill C2 Link",  sublabel: "DNS sinkhole applied", isAction: true },
  ],
  Rate_Limit_Playbook: [
    { type: "trigger",   icon: <IconLightning />, label: "Trigger",       sublabel: "Port scan rate exceeded"     },
    { type: "condition", icon: <IconChart />,     label: "Rate Calc",     sublabel: "pps over 30s window"         },
    { type: "enrich",    icon: <IconGlobe />,     label: "IP Lookup",     sublabel: "Geo + reputation check"      },
    { type: "mitre",     icon: <IconGrid />,      label: "MITRE Map",     sublabel: "T1046 network scan"          },
    { type: "action",    icon: <IconGauge />,     label: "Rate Limit",    sublabel: "QoS rule pushed", isAction: true },
  ],
  Lock_Account_Playbook: [
    { type: "trigger",   icon: <IconLightning />, label: "Trigger",       sublabel: "Auth failure spike"          },
    { type: "condition", icon: <IconHash />,      label: "Count Attempts",sublabel: "Attempt history retrieved"   },
    { type: "enrich",    icon: <IconSearch />,    label: "User Lookup",   sublabel: "AD account identified"       },
    { type: "mitre",     icon: <IconGrid />,      label: "MITRE Map",     sublabel: "T1110 Brute Force"           },
    { type: "action",    icon: <IconKey />,       label: "Lock Account",  sublabel: "AD account suspended", isAction: true },
  ],
};

const DEFAULT_STEPS: StepDef[] = [
  { type: "trigger",   icon: <IconLightning />, label: "Trigger",     sublabel: "Anomaly detected"          },
  { type: "condition", icon: <IconBranch />,    label: "AI Check",    sublabel: "Severity evaluated"        },
  { type: "enrich",    icon: <IconGlobe />,     label: "CTI Enrich",  sublabel: "Threat intelligence"       },
  { type: "mitre",     icon: <IconGrid />,      label: "MITRE Map",   sublabel: "Technique resolved"        },
  { type: "action",    icon: <IconShield />,    label: "Respond",     sublabel: "Action executed", isAction: true },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function playbookLabel(name: string) {
  return name.replace(/_Playbook$/, "").replace(/_/g, " ");
}

function timeAgo(iso: string): string {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60)  return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60)  return `${m}m ago`;
  return `${Math.floor(m / 60)}h ago`;
}

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#e84d4d", HIGH: "#f4a926", MEDIUM: "#e0c020",
  LOW: "#72c811", INFO: "#6b6e80",
};

// ── Arrow connector ───────────────────────────────────────────────────────────

function NodeArrow({ fromColor, toColor }: { fromColor: string; toColor: string }) {
  const id = `grad-${fromColor.replace("#", "")}-${toColor.replace("#", "")}`;
  return (
    <div className="flex items-center shrink-0 self-start" style={{ width: "52px", marginTop: "23px" }}>
      <svg width="52" height="20" viewBox="0 0 52 20" fill="none">
        <defs>
          <linearGradient id={id} x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%"   stopColor={fromColor} stopOpacity="0.6" />
            <stop offset="100%" stopColor={toColor}   stopOpacity="0.6" />
          </linearGradient>
        </defs>
        {/* Dashed line */}
        <line x1="0" y1="10" x2="42" y2="10"
              stroke={`url(#${id})`} strokeWidth="1.5"
              strokeDasharray="4 3" strokeLinecap="round" />
        {/* Arrowhead */}
        <path d="M38 5 L50 10 L38 15" fill="none"
              stroke={toColor} strokeWidth="1.5"
              strokeLinecap="round" strokeLinejoin="round"
              opacity="0.8" />
      </svg>
    </div>
  );
}

// ── Single workflow node ──────────────────────────────────────────────────────

function WorkflowNode({
  step, index,
}: {
  step:  StepDef;
  index: number;
}) {
  const color = C[step.type];

  return (
    <div
      className="node-appear shrink-0 flex flex-col"
      style={{
        animationDelay: `${index * 80 + 60}ms`,
        width: "118px",
      }}
    >
      {/* Card */}
      <div
        className="relative flex flex-col items-center text-center rounded overflow-hidden"
        style={{
          background: "#1a1b1f",
          border: "1px solid #2e3038",
        }}
      >
        {/* Top accent bar */}
        <div
          className="w-full"
          style={{ height: "3px", background: color, boxShadow: `0 0 8px ${color}66` }}
        />

        <div className="flex flex-col items-center gap-1.5 px-2.5 py-3">
          {/* Icon circle */}
          <div
            className="flex items-center justify-center rounded-full"
            style={{
              width: "36px", height: "36px",
              background: `${color}14`,
              border: `1.5px solid ${color}60`,
              color,
              boxShadow: `0 0 12px ${color}22`,
            }}
          >
            {step.icon}
          </div>

          {/* Node type chip */}
          <span
            className="text-[8px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded"
            style={{
              background: `${color}18`,
              color: `${color}cc`,
            }}
          >
            {step.type}
          </span>

          {/* Label */}
          <span className="text-[11px] font-semibold leading-tight text-white">
            {step.label}
          </span>

          {/* Sublabel */}
          <span
            className="text-[9px] leading-snug"
            style={{ color: "#6b6e80" }}
          >
            {step.sublabel}
          </span>
        </div>

        {/* Status bar */}
        <div
          className="w-full flex items-center justify-center gap-1 py-1.5 anim-glow"
          style={{
            background: "#141518",
            borderTop: `1px solid ${color}30`,
            boxShadow: `0 0 6px ${color}18`,
          }}
        >
          <svg viewBox="0 0 24 24" width="8" height="8" fill="none"
               stroke={color} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="20 6 9 17 4 12" />
          </svg>
          <span className="text-[9px] font-semibold" style={{ color }}>
            {step.isAction ? "EXECUTED" : "DONE"}
          </span>
        </div>
      </div>

      {/* Execution confirmation below action node */}
      {step.isAction && (
        <div
          className="text-center text-[8px] mt-1 py-0.5 rounded"
          style={{
            background: "rgba(114,200,17,0.08)",
            border: "1px solid rgba(114,200,17,0.25)",
            color: "#72c811",
          }}
        >
          Palo Alto Firewall ingress ACL updated.
        </div>
      )}
    </div>
  );
}

// ── Workflow card (one execution) ─────────────────────────────────────────────

function WorkflowCard({
  entry, cardIndex, actionOverride, onEdit,
}: {
  entry:          CicidsPlaybookLog;
  cardIndex:      number;
  actionOverride?: ActionOverride;
  onEdit?:        () => void;
}) {
  const rawSteps = PLAYBOOK_STEPS[entry.playbook_name] ?? DEFAULT_STEPS;
  const steps    = actionOverride
    ? rawSteps.map(s => s.isAction ? { ...s, label: actionOverride.label, sublabel: actionOverride.sublabel } : s)
    : rawSteps;
  const sevColor = SEV_COLOR[entry.severity] ?? "#6b6e80";
  const pbColor  = C.action;

  return (
    <div
      className="node-appear"
      style={{
        animationDelay: `${cardIndex * 50}ms`,
        background: "#1e1f23",
        border: "1px solid #2e3038",
        borderLeft: `3px solid ${pbColor}`,
        borderRadius: "4px",
        marginBottom: "10px",
        overflow: "hidden",
      }}
    >
      {/* ── Header ────────────────────────────────────────────────────────── */}
      <div
        className="flex items-center justify-between px-3 py-2 gap-3"
        style={{ background: "#222429", borderBottom: "1px solid #2e3038" }}
      >
        {/* Left: badges + name + IP */}
        <div className="flex items-center gap-2 min-w-0">
          {/* SOAR chip */}
          <span
            className="shrink-0 text-[9px] font-bold uppercase px-1.5 py-0.5 rounded tracking-wider"
            style={{ background: `${pbColor}18`, border: `1px solid ${pbColor}40`, color: pbColor }}
          >
            SOAR
          </span>

          {/* Playbook name */}
          <span className="text-xs font-semibold text-white truncate">
            {playbookLabel(entry.playbook_name)}
          </span>

          {/* Separator */}
          <span className="text-[#3d3f4a] text-xs shrink-0">·</span>

          {/* Target IP */}
          {entry.target_ip && (
            <span className="font-mono text-[11px] shrink-0" style={{ color: "#e84d4d" }}>
              {entry.target_ip}
            </span>
          )}

          {/* Severity */}
          <span
            className="shrink-0 text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
            style={{
              background: `${sevColor}15`,
              border: `1px solid ${sevColor}40`,
              color: sevColor,
            }}
          >
            {entry.severity}
          </span>
        </div>

        {/* Right: status + edit + timestamp */}
        <div className="flex items-center gap-2 shrink-0">
          <span
            className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded tracking-wider anim-glow"
            style={{
              background: "rgba(114,200,17,0.10)",
              border: "1px solid rgba(114,200,17,0.35)",
              color: "#72c811",
            }}
          >
            EXECUTED
          </span>
          {onEdit && (
            <button
              onClick={onEdit}
              title="Edit enforcement action for this execution"
              className="px-2 py-0.5 rounded text-[9px] font-medium transition-all active:opacity-70 hover:opacity-90"
              style={{
                background: "rgba(139,92,246,0.12)",
                border: "1px solid rgba(139,92,246,0.30)",
                color: "#a78bfa",
              }}
            >
              ✎ Edit
            </button>
          )}
          <span className="font-mono text-[10px]" style={{ color: "#4d5060" }}>
            {timeAgo(entry.executed_at)}
          </span>
        </div>
      </div>

      {/* ── Attack label + detail ──────────────────────────────────────────── */}
      <div className="flex items-center gap-3 px-3 py-1.5" style={{ borderBottom: "1px solid #2e3038" }}>
        <span className="text-[10px] font-mono" style={{ color: "#4d5060" }}>label</span>
        <span className="text-[11px] font-mono font-medium" style={{ color: "#c5c7d4" }}>
          {entry.label}
        </span>
        {entry.target_port && (
          <>
            <span className="text-[#3d3f4a]">·</span>
            <span className="text-[10px] font-mono" style={{ color: "#4d5060" }}>port</span>
            <span className="text-[11px] font-mono" style={{ color: "#8b8fa8" }}>{entry.target_port}</span>
          </>
        )}
        {entry.action_detail && (
          <>
            <span className="text-[#3d3f4a]">·</span>
            <span
              className="text-[10px] font-mono truncate max-w-[340px]"
              style={{ color: "#4d5060" }}
              title={entry.action_detail}
            >
              {entry.action_detail}
            </span>
          </>
        )}
      </div>

      {/* ── Node canvas ───────────────────────────────────────────────────── */}
      <div className="flex items-start gap-0 px-4 py-4 overflow-x-auto">
        {steps.map((step, i) => (
          <div key={i} className="flex items-center">
            <WorkflowNode step={step} index={i} />
            {i < steps.length - 1 && (
              <NodeArrow
                fromColor={C[step.type]}
                toColor={C[steps[i + 1].type]}
              />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Empty state ───────────────────────────────────────────────────────────────

function EmptyCanvas() {
  return (
    <div
      className="flex flex-col items-center justify-center py-14 text-center"
      style={{ color: "#4d5060" }}
    >
      {/* Faint node diagram illustration */}
      <div className="flex items-center gap-2 mb-5 opacity-20">
        {(["#e84d4d", "#4e9af1", "#8b5cf6", "#72c811"] as const).map((col, i) => (
          <div key={i} className="flex items-center">
            <div
              className="rounded"
              style={{ width: "32px", height: "40px", background: "#222429", border: `1px solid ${col}` }}
            />
            {i < 3 && (
              <div className="flex items-center mx-1">
                <div className="h-px w-4" style={{ background: col }} />
                <svg width="6" height="8" viewBox="0 0 6 8" fill={col}>
                  <path d="M0 0 L6 4 L0 8 Z" />
                </svg>
              </div>
            )}
          </div>
        ))}
      </div>
      <p className="text-xs font-semibold" style={{ color: "#6b6e80" }}>No SOAR executions yet</p>
      <p className="text-[11px] mt-1">Upload network telemetry to activate automated playbooks</p>
      <div className="flex items-center gap-1.5 mt-3 text-[10px]">
        <span className="px-1.5 py-0.5 rounded" style={{ background: "#222429", border: "1px solid #2e3038", color: "#6b6e80" }}>
          Trigger
        </span>
        <span style={{ color: "#3d3f4a" }}>──▶</span>
        <span className="px-1.5 py-0.5 rounded" style={{ background: "#222429", border: "1px solid #2e3038", color: "#6b6e80" }}>
          Condition
        </span>
        <span style={{ color: "#3d3f4a" }}>──▶</span>
        <span className="px-1.5 py-0.5 rounded" style={{ background: "#222429", border: "1px solid #2e3038", color: "#6b6e80" }}>
          Enrich
        </span>
        <span style={{ color: "#3d3f4a" }}>──▶</span>
        <span className="px-1.5 py-0.5 rounded" style={{ background: "#222429", border: "1px solid #2e3038", color: "#6b6e80" }}>
          Action
        </span>
      </div>
    </div>
  );
}

// ── Exported component ────────────────────────────────────────────────────────

export interface ActionOverride { label: string; sublabel: string }

interface Props {
  entries:         CicidsPlaybookLog[];
  actionOverrides?: Record<number, ActionOverride>;
  onEditEntry?:    (entry: CicidsPlaybookLog) => void;
}

export function PlaybookTimeline({ entries, actionOverrides = {}, onEditEntry }: Props) {
  if (entries.length === 0) return <EmptyCanvas />;

  return (
    <div className="max-h-[680px] overflow-y-auto pr-0.5">
      {/* Canvas header */}
      <div className="flex items-center justify-between mb-3 px-0.5">
        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-widest font-semibold" style={{ color: "#4d5060" }}>
            Workflow Canvas
          </span>
          <span
            className="text-[9px] font-bold px-1.5 py-0.5 rounded tabular-nums"
            style={{ background: "rgba(114,200,17,0.10)", border: "1px solid rgba(114,200,17,0.25)", color: "#72c811" }}
          >
            {entries.length} execution{entries.length !== 1 ? "s" : ""}
          </span>
        </div>
        <span className="text-[10px]" style={{ color: "#4d5060" }}>
          All rules pushed to{" "}
          <span style={{ color: "#72c811" }}>Palo Alto NGFW</span>
          {" "}via PAN-OS API
        </span>
      </div>

      {entries.map((entry, i) => (
        <WorkflowCard
          key={entry.id}
          entry={entry}
          cardIndex={i}
          actionOverride={actionOverrides[entry.id]}
          onEdit={onEditEntry ? () => onEditEntry(entry) : undefined}
        />
      ))}
    </div>
  );
}
