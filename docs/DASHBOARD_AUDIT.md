# OmniWatch Dashboard Audit

**Audit Date:** 2026-05-02  
**Scope:** Full-stack audit of backend pipeline, ML surface, and frontend dashboard  
**Outcome:** 3 data integrity bugs fixed, 1 orphaned ML feature surfaced, dashboard redesigned to 3-row no-scroll layout

---

## 1. Data Integrity Failures

### 1.1 Benign Paradox

**File:** `backend/ingestion/analysis_engine.py`, `tier1_filter()` (~line 720)

**Problem:** The filter used OR-logic for port and byte-volume masks. A flow labeled `BENIGN` but destined for port 445 would correctly fail the label check, but then pass `mask |= ports.isin(_SUSPICIOUS_PORTS)`. The OR-mask accumulated bits from multiple independent detectors, so any single signal could override the label exclusion. Result: BENIGN-labeled rows entered `telemetry_alerts`, inflating CRITICAL/HIGH counts.

**Fix:** After all OR-mask accumulation, a hard AND-exclusion strip is applied:
```python
if "label" in df.columns:
    _lc_all = df["label"].astype(str).str.strip().str.lower()
    mask &= ~_lc_all.isin(_BENIGN_LABELS)
```
This is the authoritative BENIGN guard — it fires last, after all detector signals have been OR'd together, and unconditionally removes rows whose label matches `_BENIGN_LABELS`.

**Verification:** After ingest of a CIC-IDS-2017 CSV, run:
```sql
SELECT COUNT(*) FROM telemetry_alerts WHERE LOWER(label) = 'benign';
-- Expected: 0
```

---

### 1.2 KPI Conflict (Split-Brain Stats)

**Files:**  
- `frontend/src/components/StatsCards.tsx`  
- `frontend/src/components/SeverityChart.tsx`

**Problem:** The two primary KPI surfaces read from different tables:
- `StatsCards` read `cicidsStats` → sourced from `telemetry_alerts` (session-scoped, pipeline data)
- `SeverityChart` read `stats` → sourced from the legacy `alerts` table (global AI scan data, different schema)

These tables have different row counts and different scoping semantics. The CRITICAL count shown in `StatsCards` could diverge from `SeverityChart` by 100k+ rows, making the dashboard internally inconsistent.

**Fix:**
- `StatsCards` now uses only `cicidsStats.by_severity` when a session is active, and falls back to legacy `stats` only when `cicidsStats` is null (no session).
- The `combinedCrit` merge that blended `pipelineCiso.by_severity.CRITICAL` into the legacy count was removed — it was double-counting.
- `SeverityChart` is no longer rendered on the dashboard (eliminated by the 3-row redesign), removing the divergence entirely.

---

### 1.3 Orphaned `triggered_rules` (Missing Detector Attribution)

**Files:**  
- `backend/ingestion/analysis_engine.py`, `tier2_enrich()` and `run_tier1_combined()`  
- `backend/api/ingestion_route.py`, `insert_alerts_batch()` and `get_pipeline_top_ips()`  
- `frontend/src/components/AiIncidentReview.tsx`

**Problem:** The frontend `AiIncidentReview` panel decoded a 7-bit `triggered_rules` bitmask to show which detectors flagged each alert, but the backend never computed or stored this field. `tier2_enrich()` only stored 10 network fields in `raw_features`; `triggered_rules` was always 0 in the database, so the "Triggered Detectors" section was always empty.

**Fix — Computation (`run_tier1_combined`):**
After all detector passes complete, a 7-bit bitmask is built per-row:

| Bit | Detector  | Python Source |
|-----|-----------|---------------|
| 0   | DDSketch  | `z_score_bytes > 3.0` (proxy) |
| 1   | LODA      | Row in `ml_flags` index |
| 2   | CUSUM     | `tw_suspicious == True` |
| 3   | Port      | `dest_port in _SUSPICIOUS_PORTS` |
| 4   | Volume    | `bytes_out > 5_000_000` |
| 5   | Label-KW  | Label matches `_ATTACK_PATTERN` |
| 6   | Time-Win  | `tw_suspicious == True` |

Bits 0 and 2 are Python-side proxies — exact DDSketch quantiles and CUSUM state are computed in the RISC Zero STARK guest; the Python values are best-effort approximations used until proof time.

**Fix — Storage (`tier2_enrich`, `insert_alerts_batch`):**
- `tier2_enrich` reads `triggered_rules` from the combined DataFrame and includes it in both `raw_features` JSON and the alert dict.
- `insert_alerts_batch` includes `triggered_rules` in the `INSERT INTO telemetry_alerts` statement.
- `_migrate_triggered_rules()` in `ingestion_route.py` fires at startup to add the column to existing databases via `ALTER TABLE ... ADD COLUMN`.

---

## 2. Orphaned Backend Logic

### 2.1 CUSUM (`CusumBaseliner`)
- **Was:** Detecting C2 beaconing periods (60/300/600s) and setting `tw_suspicious`, but this bit was never surfaced per-alert.
- **Now:** `tw_suspicious == True` sets bits 2 and 6 in `triggered_rules`, making CUSUM detections visible in `AiIncidentReview`.

### 2.2 LODA (`LodaBaseliner`)
- **Was:** Running multivariate anomaly detection via sparse random projections, but only influencing severity; no per-alert attribution.
- **Now:** Row indices from `ml_flags` set bit 1, so LODA-flagged alerts show "LODA" badge in `AiIncidentReview`.

### 2.3 DDSketch (`DDSketchBaseliner`)
- **Was:** Computing per-session z-scores stored as `z_score_bytes`/`z_score_pkts`, but no bitmask attribution.
- **Now:** `z_score_bytes > 3.0` sets bit 0 as a proxy. The STARK guest computes exact DDSketch quantiles at proof time.

---

## 3. Fixes Applied

| Task | File | Change |
|------|------|--------|
| 1A | `analysis_engine.py` | BENIGN AND-mask after OR accumulation in `tier1_filter()` |
| 2A | `analysis_engine.py` | 7-bit `triggered_rules` bitmask in `run_tier1_combined()` |
| 2B | `analysis_engine.py` | `triggered_rules` in `tier2_enrich()` raw_features + alert dict |
| 2C | `ingestion_route.py` | `ALTER TABLE` migration + `triggered_rules` in `INSERT` |
| 3A | `analysis_engine.py` | BENIGN filter + `dominant_rule` in `compute_ciso_summary()` |
| 4A | `ingestion_route.py` | BENIGN filter + `dominant_rule` in `get_pipeline_top_ips` |
| 5A | `types.ts` | `top_attacker_ips` type gains optional `dominant_rule?: string` |
| 5B | `api.ts` | `getTopIps` return type updated to match |
| 6A | `App.tsx` | `DashboardPage` replaced with 3-row no-scroll layout |
| 6B | `TopThreatSourcesPanel.tsx` | New component: IP list with count bar + detector badge |
| 6C | `ExecutiveBriefDrawer.tsx` | New component: right-edge slide-over with session summary |
| 6D | `StatsCards.tsx` | Removed `combinedCrit` legacy merge, single source of truth |

---

## 4. Architecture Notes

### Two-Table Split
OmniWatch maintains two alert stores:
- **`cicids_events`** — Legacy CIC-IDS-2017 ingest, global scope, severity='INFO' for BENIGN rows. KPIs from this table should use `severity NOT IN ('INFO')` to exclude benign.
- **`telemetry_alerts`** — Unified pipeline (BOTSv3, CIC-IDS, edge telemetry), session-scoped by `session_id`. This is the authoritative source for all post-pipeline KPIs.

Any component reading one table for KPIs must not mix results with a component reading the other.

### Session Lifecycle
A `PipelineSession` is created on upload, updated with `rows_processed`/`alerts_found` at each chunk, and finalized with `ciso_summary` + `chain_tip_hash` at `pipeline_complete`. The frontend caches `session_id` in localStorage so a page reload restores the session context without re-uploading.

### STARK Proof Latency Window
The RISC Zero zkVM proof takes 15–32s per alert. During this window, `triggered_rules` in `telemetry_alerts` holds Python-computed approximations. The STARK guest (`verifier/methods/guest/src/main.rs`) recomputes the exact bitmask from the raw telemetry fields; any discrepancy between Python bits and STARK bits indicates a pipeline inconsistency that the proof ceremony will catch.

### Detector Badge Priority Order
When displaying a single "dominant detector" badge for an IP, the priority order is:
`LODA > DDSketch > Port > Volume > Label-KW > CUSUM > Time-Win`

LODA is highest-priority because it operates on numeric feature space (multivariate) rather than threshold rules, giving lower false-positive rates.
