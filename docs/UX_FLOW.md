# OmniWatch Analyst UX Flow

## Overview

This document describes the end-to-end analyst journey in OmniWatch, from telemetry upload through
zk-STARK proof generation and FIDO2-gated remediation authorization.

Design philosophy: **keyboard-first, context-preserving, latency-aware**. Every action from triage
to sign-off should be reachable without lifting hands from the keyboard. The 15–32 s proof window
is surfaced as a live, informative process — not a frozen spinner.

---

## Phase 1 — Ingest

```
Upload CSV  →  POST /api/upload-telemetry  →  WebSocket pipeline_progress events
```

- Progress bar increments every **~10 k rows** (~200–400 ms per tick, fluid).
- WebSocket message shape: `{ type: "pipeline_progress", rows_processed: N, rows_total: M, alerts_found: K }`
- On `pipeline_complete`: app auto-navigates to the **Log Explorer** tab and shows a toast notification
  with alert counts by severity.
- If ingestion errors, a `pipeline_error` event surfaces the backend traceback in a dismissible banner.

**Key file:** `backend/api/ingestion_route.py` — `_CHUNK_ROWS = 10_000`, `_PROGRESS_EVERY = 10_000`

---

## Phase 2 — Triage

```
Log Explorer  →  session_id pre-selected  →  filter/keyboard-navigate rows
```

### Stats strip (top of Log Explorer)
Shows at a glance: `total alerts | CRITICAL N | HIGH N | MEDIUM N`

Color coding follows ISA-101 HMI — color is **never** the sole indicator:
| Severity | Color token        | Icon prefix |
|----------|--------------------|-------------|
| CRITICAL | `--isa-critical` (red-600)   | `⬛` |
| HIGH     | `--isa-high` (amber-600)     | `▲`  |
| MEDIUM   | `--isa-medium` (yellow-600)  | `◆`  |
| LOW      | `--isa-low` (green-600)      | `▼`  |
| INFO     | `--isa-info` (slate-600)     | `○`  |

### Filter bar
- **Search input** — press `/` to focus without mouse; `Enter` to apply for legacy datasets.
- **Severity dropdown** — or use `Cmd+K` → "Show Critical" for one-keystroke filter.
- **Apply / Clear** — always visible; `Escape` clears keyboard focus.

### Keyboard map (active when no input/select is focused)
| Key               | Action                                        |
|-------------------|-----------------------------------------------|
| `j` / `↓`         | Move focus to next row                        |
| `k` / `↑`         | Move focus to previous row                    |
| `Enter`           | Open **AiIncidentReview** slide-over for focused row |
| `Escape`          | Deselect row / close slide-over               |
| `Cmd+K` / `Ctrl+K`| Open **Command Palette**                      |
| `/`               | Focus search input                            |
| `r`               | Invalidate and refetch current query          |
| `Cmd+Enter`       | Trigger AI analysis on focused row (pipeline sessions) |

Focused row has a cyan outline ring (`--focus-ring`) and `--row-selected-bg` background.

---

## Phase 3 — Investigation

```
Enter on row  →  AiIncidentReview slide-over (right edge, 480 px)
```

The main log grid **remains visible** while the slide-over is open. The backdrop is
`pointer-events-none` — clicks pass through to the grid beneath. The analyst never loses
context of what they were reviewing.

### Slide-over sections

1. **Header** — Alert ID · Severity pill · `×` close
2. **5-tuple** — `src_ip:src_port → dst_ip:dst_port | protocol` in JetBrains Mono
3. **MITRE card** — Tactic name + technique ID (violet-tinted background)
4. **Stats row** — bytes total (KB/MB) · flow duration · triggered-rules bitfield decoded as badges:
   - Bits: `[0] DDSketch` `[1] LODA` `[2] CUSUM-Beacon` `[3] Heuristic-Port` `[4] Heuristic-Volume`
     `[5] Label-Keyword` `[6] Time-Window`
5. **AI Analysis** — "Generate AI Analysis" button → `POST /api/analyze-incident`
   Response renders as markdown. Cached in component state — re-opening the same alert
   does **not** re-fetch.
6. **Footer CTA** — "Review & Sign (STARK + FIDO2)" — triggers Phase 4.

### Command Palette (`Cmd+K`)
Opens a centered overlay with a static command list:
- Show Critical alerts
- Show High alerts
- Show Medium alerts
- Clear all filters
- (Generate AI Analysis — shortcut label only, triggered from slide-over)

`j/k` navigates, `Enter` executes, `Escape` closes.

---

## Phase 4 — Proof & Authorization

```
"Review & Sign"  →  POST /api/pipeline/prove/{id}  →  TrustChainDAG animates
```

### STARK proof generation (15–32 s)

While the proof is generating:
- TrustChainDAG displays a **pulsing cyan ring** around the pending node.
- A status line appears below the DAG: `"⚡ Generating zk-STARK proof… (~15–32 s)"` with a live
  elapsed-seconds counter so the analyst knows the process hasn't stalled.
- The slide-over remains open with a spinner overlay on the footer CTA.

### FIDO2 sign-off

On `proof_complete`:
1. `POST /api/auth/sign/begin` → browser calls `navigator.credentials.get()` (FIDO2/WebAuthn).
2. `POST /api/verify-remediation` with STARK receipt + ECDSA assertion.
3. On `authorized: true`:
   - Alert row in the log grid receives a green `✓` checkmark.
   - Slide-over closes automatically.
   - TrustChainDAG pulse animation stops; node turns solid cyan.

### What the receipt proves

| Field                | Source                        |
|----------------------|-------------------------------|
| `is_threat`          | zkVM deterministic re-run     |
| `category`           | MITRE tactic from LODA model  |
| `confidence_pct`     | LODA + DDSketch combined score |
| `triggered_rules`    | 14-bit bitmask, verified in-circuit |
| `credential_id`      | FIDO2 authenticator ID        |

---

## Component Map

| Component               | File                                   | Role |
|-------------------------|----------------------------------------|------|
| `LogExplorer`           | `components/LogExplorer.tsx`           | Primary triage table; keyboard nav host |
| `AiIncidentReview`      | `components/AiIncidentReview.tsx`      | Per-alert slide-over investigation panel |
| `CommandPalette`        | `components/CommandPalette.tsx`        | `Cmd+K` filter shortcut overlay |
| `TrustChainDAG`         | `components/TrustChainDAG.tsx`         | Three.js chain DAG + STARK latency masker |
| `PlaybookTimeline`      | `components/PlaybookTimeline.tsx`      | SOAR action log |
| `MitreHeatmap`          | `components/MitreHeatmap.tsx`          | ATT&CK tactic coverage |
| `AIAnalysisDrawer`      | `components/AIAnalysisDrawer.tsx`      | Session-level AI summary (not per-alert) |

---

## Design Tokens Reference

```css
--isa-critical:     #dc2626;   /* red-600   — CRITICAL severity */
--isa-high:         #d97706;   /* amber-600 — HIGH severity */
--isa-medium:       #ca8a04;   /* yellow-600 — MEDIUM severity */
--isa-low:          #16a34a;   /* green-600 — LOW severity */
--isa-info:         #475569;   /* slate-600 — INFO */
--focus-ring:       rgba(6,182,212,0.40);   /* cyan focus ring */
--row-selected-bg:  rgba(6,182,212,0.06);   /* keyboard-selected row */
--slideover-bg:     rgba(7,14,26,0.97);     /* AiIncidentReview background */
```

Typography: Inter (UI) + JetBrains Mono (data / IPs / ports / bytes).

---

## API Endpoints Used in This Flow

| Endpoint                              | Phase  | Purpose |
|---------------------------------------|--------|---------|
| `POST /api/upload-telemetry`          | 1      | Ingest CSV |
| `GET  /api/sessions/{id}/status`      | 1      | Poll session state |
| `GET  /api/pipeline/alerts`           | 2      | Fetch alert rows (paginated) |
| `GET  /api/cicids/stats`              | 2      | Session-scoped severity counts |
| `GET  /api/pipeline/top-ips`          | 2      | Top attacker IPs for this session |
| `POST /api/analyze-incident`          | 3      | Per-alert AI narrative + CTI enrichment |
| `POST /api/pipeline/prove/{id}`       | 4      | Generate zk-STARK receipt |
| `POST /api/auth/sign/begin`           | 4      | Start FIDO2 assertion |
| `POST /api/verify-remediation`        | 4      | Verify STARK + FIDO2 assertion |
