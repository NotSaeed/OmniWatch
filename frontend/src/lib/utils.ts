import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import type { Severity } from "./types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// ── Chart colours ─────────────────────────────────────────────────────────────
export const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "#e84d4d",
  HIGH:     "#f4a926",
  MEDIUM:   "#e0c020",
  LOW:      "#72c811",
  INFO:     "#6b6e80",
};

// ── Alert table — severity pill badge ────────────────────────────────────────
export const SEVERITY_BG: Record<Severity, string> = {
  CRITICAL: "bg-red-500/10 text-red-400 border border-red-500/40 shadow-[0_0_8px_rgba(239,68,68,0.25)]",
  HIGH:     "bg-orange-500/10 text-orange-400 border border-orange-500/35",
  MEDIUM:   "bg-yellow-500/10 text-yellow-400 border border-yellow-500/35",
  LOW:      "bg-blue-500/10 text-blue-400 border border-blue-500/35",
  INFO:     "bg-slate-500/10 text-slate-400 border border-slate-500/25",
};

export const CATEGORY_LABELS: Record<string, string> = {
  BRUTE_FORCE:  "Brute Force",
  PORT_SCAN:    "Port Scan",
  MALWARE:      "Malware / C2",
  EXFILTRATION: "Exfiltration",
  ANOMALY:      "Anomaly",
  BENIGN:       "Benign",
};

// ── Log Explorer — full row highlight ────────────────────────────────────────
export const LOG_ROW_STYLE: Record<string, string> = {
  CRITICAL: "bg-red-950/50 border-l-[3px] border-red-500 text-red-100 row-critical",
  HIGH:     "bg-orange-950/30 border-l-[3px] border-orange-600 text-orange-100",
  MEDIUM:   "bg-yellow-950/25 border-l-[3px] border-yellow-600 text-yellow-100",
  LOW:      "bg-slate-900/40 border-l-[2px] border-slate-600 text-slate-300",
  INFO:     "bg-slate-950/30 border-l-[2px] border-slate-800 text-slate-500",
};

// ── Severity pill badge (LogExplorer + IncidentModal) ─────────────────────────
export const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-400 border border-red-500/40 shadow-[0_0_8px_rgba(239,68,68,0.2)]",
  HIGH:     "bg-orange-500/15 text-orange-400 border border-orange-500/40",
  MEDIUM:   "bg-yellow-500/15 text-yellow-400 border border-yellow-500/40",
  LOW:      "bg-blue-500/15 text-blue-400 border border-blue-500/35",
  INFO:     "bg-slate-500/10 text-slate-500 border border-slate-600/30",
};

export function formatConfidence(v: number): string {
  return `${(v * 100).toFixed(0)}%`;
}

export function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString("en-US", { hour12: false });
}
