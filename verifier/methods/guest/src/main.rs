//! OmniWatch Threat Verifier — zkVM Guest (v3 — DDSketch Split-Brain Fixed-Point)
//!
//! This program executes inside the RISC Zero zkVM.  Every instruction is
//! recorded in an execution trace that the prover converts into a STARK proof.
//! Anyone holding the receipt can verify — with mathematical certainty — that
//! these exact rules were applied to exactly the committed input.
//!
//! ## v3 changes (Phase 1: Split-Brain Fixed-Point)
//! - All hardcoded byte-rate and packet-count fallback constants removed.
//! - Volumetric rules now follow a strict priority order:
//!     1. DDSketch T (from Python p99 baseliner):
//!          `current_scaled = bytes_per_sec << 14`
//!          `is_threat = current_scaled > T`
//!     2. Z-score |Z| > 3.0 (when stddev_bytes_s_milli > 0)
//!     3. No volumetric detection (no baseline context available)
//! - Packet-count rules use Z-score only (no absolute fallback).
//! - New rule bit `DDSKETCH_VOLUME` distinguishes DDSketch-triggered events
//!   from Z-score-triggered ones.
//! - Zero floating-point (f32/f64) anywhere in this file — all arithmetic is
//!   strict integer, guaranteeing bit-identical results on every RISC-V host.
//!
//! ## Porting note
//! All threat thresholds are derived from the Python invariants in:
//!   - backend/triage/validator.py   (confidence caps, sparse sourcetypes)
//!   - backend/triage/engine.py      (confidence boost logic)
//!   - backend/cicids/analyzer.py    (attack label ↔ severity mapping)

#![no_main]

use sha2::{Digest, Sha256};
use verifier_core::{rules, CusumModel, HostBaselines, LodaModel, NetworkTelemetry, TelemetryInput, ThreatVerdict};

risc0_zkvm::guest::entry!(main);

// ── Sourcetype capping (mirrors Python validator.py) ─────────────────────────

const SPARSE_SOURCETYPES: &[u8] = &[0 /* simulated/unknown */];
const CONFIDENCE_CAP_SPARSE: u8 = 50;

// ── Z-score threshold (fixed-point, ×1000) ────────────────────────────────────
//
// ZSCORE_THRESHOLD = 3000 means |Z| > 3.0.
// Stored as u64 × 1000 to stay integer-only throughout.
const ZSCORE_THRESHOLD: u64 = 3_000;

// ── Forensic timing constants (hard properties of specific attack types) ──────
//
// These are NOT threshold tunables — they are definitional properties of the
// attack pattern and are not replaced by DDSketch or Z-score baselines.
//
// Stealth probe: SYN-only scan completes in < 100 ms with ≤ 2 packets.
const PROBE_DURATION_MS: u64 = 100;
const PROBE_PKT_MAX: u32     = 2;
// Exfiltration: must be a sustained transfer of ≥ 5 seconds to distinguish
// from a brief high-rate burst (e.g. a large image download).
const EXFIL_MIN_DURATION_MS: u64 = 5_000;

// ── Z-score helpers (pure integer, no float) ─────────────────────────────────

/// Compute |value - mean| × 1000 / stddev (fixed-point Z-score magnitude).
///
/// Returns 0 if `stddev == 0` (no baseline — caller must skip the rule).
/// The result is comparable against `ZSCORE_THRESHOLD`:
///   `zscore_scaled(...) > ZSCORE_THRESHOLD` ↔ |Z| > 3.0
#[inline]
fn zscore_scaled(value: u64, mean: u64, stddev: u64) -> u64 {
    if stddev == 0 {
        return 0;
    }
    let diff = if value >= mean { value - mean } else { mean - value };
    diff.saturating_mul(1_000) / stddev
}

/// Z-score for packet count.  Packet counts are stored ×1000 in
/// `HostBaselines` (mean_pkts_milli / stddev_pkts_milli) so the math is
/// identical to the bytes/s path.
#[inline]
fn zscore_pkts(pkt_count: u32, baselines: &HostBaselines) -> u64 {
    zscore_scaled(
        (pkt_count as u64).saturating_mul(1_000),
        baselines.mean_pkts_milli,
        baselines.stddev_pkts_milli,
    )
}

// ── Volumetric decision helpers ───────────────────────────────────────────────

/// Determine whether the current flow's byte rate exceeds the volumetric
/// threshold, following the DDSketch → Z-score → none priority order.
///
/// Priority
/// --------
///   1. DDSketch T > 0:  `current_scaled > T`
///      (T = ⌊p99_bytes_per_sec × 2^14⌋, computed by the Python pipeline)
///   2. Z-score:         `|Z| > 3.0` on bytes/s
///      (requires `stddev_bytes_s_milli > 0`)
///   3. Neither:         false — no volumetric detection possible
///
/// `current_scaled` must be pre-computed as `bytes_per_sec << 14`.
/// `flow_bytes_s_milli` is the raw ×1000 field from `NetworkTelemetry`.
#[inline]
fn volumetric_exceeded(
    current_scaled: u64,
    flow_bytes_s_milli: u64,
    b: &HostBaselines,
) -> bool {
    if b.ddsketch_threshold_fp14 > 0 {
        current_scaled > b.ddsketch_threshold_fp14
    } else if b.stddev_bytes_s_milli > 0 {
        zscore_scaled(flow_bytes_s_milli, b.mean_bytes_s_milli, b.stddev_bytes_s_milli)
            > ZSCORE_THRESHOLD
    } else {
        false
    }
}

/// Rule bits set when a volumetric rule fires.
/// DDSKETCH_VOLUME when the DDSketch path triggered; ZSCORE_ANOMALY otherwise.
#[inline]
fn volumetric_bits(b: &HostBaselines) -> u32 {
    if b.ddsketch_threshold_fp14 > 0 {
        rules::HIGH_RATE | rules::DDSKETCH_VOLUME
    } else {
        rules::HIGH_RATE | rules::ZSCORE_ANOMALY
    }
}

/// Whether the packet count exceeds the Z-score anomaly threshold.
/// Returns false when no packet baselines are available (stddev == 0).
#[inline]
fn packet_threshold_exceeded(pkt_count: u32, b: &HostBaselines) -> bool {
    b.stddev_pkts_milli > 0 && zscore_pkts(pkt_count, b) > ZSCORE_THRESHOLD
}

// ── LODA evaluation (pure integer, no float) ──────────────────────────────────

/// Extract the 4 canonical LODA features as raw integers.
///
/// Feature order (matches Python `_extract_loda_features`):
///   [0] bytes_per_sec_kb  = bytes_per_sec / 1024, clamped to [0, 1_000_000]
///   [1] packet_count      = packet_count,          clamped to [0, 1_000_000]
///   [2] flow_duration_ms  = flow_duration_us / 1000, clamped to [0, 65_535]
///   [3] dest_port         = dst_port                 [0, 65_535]
///
/// Raw integers (not pre-scaled to Q14) — scaling happens inside `loda_score`
/// once per projection, not once per feature × tree-node, saving significant cycles.
#[inline]
fn loda_features(t: &NetworkTelemetry) -> [i64; 4] {
    [
        (t.bytes_per_sec() / 1024).min(1_000_000) as i64,
        (t.packet_count as u64).min(1_000_000) as i64,
        t.duration_ms().min(65_535) as i64,
        t.dst_port as i64,
    ]
}

/// Compute the LODA anomaly score: sum of Q10-scaled −log(density) across k projections.
///
/// Returns `None` when the model is unavailable (k == 0 → Rule 11 skipped).
/// The result is comparable against `model.anomaly_threshold_fp10`:
///   `loda_score(...) > anomaly_threshold_fp10` → anomalous record.
///
/// ## Cycle-count rationale vs. Isolation Forest
/// IF traverse_tree: branch per node × MAX_DEPTH iterations × n_trees pointer-jump loads.
/// LODA inner loop:  match-arm add/subtract per feature (4 ops) + linear scan over
///                   ~10 bin edges — all sequential flat-array accesses, no pointer jumps.
/// On the RV32IM ISA, match { 1 => z += x,  -1 => z -= x,  _ => {} } compiles to
/// two conditional branches and one ADD or SUB — zero MUL instructions.
#[inline]
fn loda_score(model: &LodaModel, t: &NetworkTelemetry) -> Option<i64> {
    if model.k == 0 || model.n_bins == 0 || model.n_features == 0 {
        return None;
    }
    let k  = model.k as usize;
    let nb = model.n_bins as usize;
    let nf = model.n_features as usize;

    let features = loda_features(t);
    let mut total_score: i64 = 0;

    for i in 0..k {
        // ── Sparse projection (zero multiplication) ──────────────────────────
        // w_ij ∈ {-1, 0, 1}: feature contribution is a single ADD or SUB,
        // or is skipped entirely when w_ij == 0.  No MUL on RV32IM.
        let mut z: i64 = 0;
        for j in 0..nf.min(4) {
            match model.projections[i * nf + j] {
                1  => z += features[j],
                -1 => z -= features[j],
                _  => {}  // 0: skip — saves one ADD per zero weight
            }
        }

        // Scale to Q14 so z_fp14 is comparable with Q14-encoded bin edges.
        // One saturating_mul per projection (not per feature × node).
        let z_fp14 = z.saturating_mul(16_384);

        // ── Bin lookup (linear scan, ~10 edges, flat array) ──────────────────
        let edge_base  = i * (nb + 1);
        let score_base = i * nb;
        let mut bin_idx = nb.saturating_sub(1); // default: last bin (right tail)
        for b in 0..nb {
            if z_fp14 < model.bin_edges_fp14[edge_base + b + 1] {
                bin_idx = b;
                break;
            }
        }

        // ── Score accumulation ────────────────────────────────────────────────
        total_score = total_score.saturating_add(
            model.bin_scores_fp10[score_base + bin_idx] as i64,
        );
    }

    Some(total_score)
}

// ── CUSUM C2 beacon evaluation (zero multiplication) ─────────────────────────

/// Stage 3 of the Zero-MUL Time-Domain CUSUM pipeline.
///
/// The Python host executes Stages 0–2 (multiplierless comb pre-filter,
/// epoch-folded L1 histogram) and injects the results as `b_n_fp14` (per-period
/// L1 score for this record) and `cusum_states_fp14` (running S_{n-1} per period).
///
/// The guest proves Stage 3 — one DAS-CUSUM accumulator step per candidate period:
///
///     S_n[i] = max(0,  S_{n-1}[i]  +  B_n[i]  −  k)
///
/// Instruction breakdown on RV32IM:
///   saturating_add  → ADD (with overflow guard — no MUL)
///   saturating_sub  → SUB (with underflow guard)
///   .max(0)         → conditional branch + register select (no MUL)
///
/// Zero `*` operators anywhere in this function.
///
/// Returns `true` when any period's accumulator exceeds `cusum_threshold_fp14`.
/// Short-circuits immediately when `model.k == 0` (CUSUM not configured).
#[inline]
fn cusum_beacon(model: &CusumModel) -> bool {
    if model.k == 0 {
        return false;
    }
    let k_periods = model.k as usize;
    for i in 0..k_periods {
        if i >= model.b_n_fp14.len() || i >= model.cusum_states_fp14.len() {
            break;
        }
        // S_n = max(0, S_{n-1} + B_n − k):  three ops, zero MUL.
        let s_n = model.cusum_states_fp14[i]
            .saturating_add(model.b_n_fp14[i])
            .saturating_sub(model.cusum_k_fp14)
            .max(0);
        if s_n > model.cusum_threshold_fp14 {
            return true;
        }
    }
    false
}

// ── Entry point ──────────────────────────────────────────────────────────────

fn main() {
    let input: TelemetryInput = risc0_zkvm::guest::env::read();

    // Hash the full TelemetryInput (telemetry + baselines) so the verdict is
    // bound to both the data and the statistical context used to evaluate it.
    let input_bytes = bincode::serialize(&input).expect("bincode serialize");
    let mut hasher  = Sha256::new();
    hasher.update(&input_bytes);
    let hash_out = hasher.finalize();
    let mut input_hash = [0u8; 32];
    input_hash.copy_from_slice(&hash_out);

    let verdict = evaluate(&input, input_hash);
    risc0_zkvm::guest::env::commit(&verdict);
}

// ── Threat rule engine ───────────────────────────────────────────────────────

/// Evaluate all threat invariants against one `TelemetryInput`.
///
/// All byte-rate comparisons use the 14-bit fixed-point scaled value:
///   `current_scaled = bytes_per_sec << 14`
///   `is_threat      = current_scaled > T`   (T from DDSketch or Z-score)
///
/// No f32/f64 variables exist in this function.
fn evaluate(input: &TelemetryInput, input_hash: [u8; 32]) -> ThreatVerdict {
    let t         = &input.telemetry;
    let b         = &input.baselines;
    let bytes_s   = t.bytes_per_sec();
    let dur_ms    = t.duration_ms();

    // Pre-scale once; reused by every volumetric rule.
    // current_scaled = bytes_per_sec × 2^14  (14-bit fixed-point, no float)
    // If T = floor(X_limit × 2^14), then current_scaled > T ↔ bytes_s > X_limit.
    // saturating_mul prevents overflow: if bytes_s is huge the result clamps at
    // u64::MAX which is always > T, so the rule fires — correct behaviour.
    let current_scaled: u64 = bytes_s.saturating_mul(16_384);

    let mut fired = 0u32;
    let mut cat   = 0u8; // BENIGN
    let mut conf  = 0u8;

    // ── Rule 1: Volumetric DoS / DDoS ─────────────────────────────────────
    // DDSketch T (priority 1) → Z-score (priority 2) → no detection
    if volumetric_exceeded(current_scaled, t.flow_bytes_s_milli, b) {
        fired |= volumetric_bits(b);
        cat    = cat.max(3); // MALWARE — DoS family
        conf   = conf.max(88);
    }

    // ── Rule 2: FTP / SSH brute force (packet Z-score) ────────────────────
    if t.dst_port == 21 || t.dst_port == 22 {
        fired |= rules::KNOWN_TARGET_PORT;
        if packet_threshold_exceeded(t.packet_count, b) {
            fired |= rules::BRUTE_FORCE;
            if cat < 2 { cat = 2; } // BRUTE_FORCE
            conf = conf.max(82);
        }
    }

    // ── Rule 3: RDP brute force (packet Z-score) ──────────────────────────
    if t.dst_port == 3389 && packet_threshold_exceeded(t.packet_count, b) {
        fired |= rules::RDP_BRUTE | rules::BRUTE_FORCE;
        if cat < 2 { cat = 2; }
        conf = conf.max(78);
    }

    // ── Rule 4: Stealth port probe (hard forensic timing) ─────────────────
    // Fixed thresholds — duration < 100 ms AND ≤ 2 packets is a definitional
    // property of a SYN-only probe; not replaced by DDSketch / Z-score.
    if dur_ms < PROBE_DURATION_MS && t.packet_count <= PROBE_PKT_MAX {
        fired |= rules::RAPID_PROBE;
        if cat == 0 {
            cat  = 1; // PORT_SCAN
            conf = conf.max(70);
        }
    }

    // ── Rule 5: DNS amplification ──────────────────────────────────────────
    if t.dst_port == 53 && t.protocol == 17
        && volumetric_exceeded(current_scaled, t.flow_bytes_s_milli, b)
    {
        fired |= rules::DNS_AMPLIFICATION | volumetric_bits(b);
        cat    = 3; // MALWARE — DoS via amplification
        conf   = conf.max(90);
    }

    // ── Rule 6: Web service volumetric anomaly ─────────────────────────────
    if matches!(t.dst_port, 80 | 443 | 8080 | 8443)
        && volumetric_exceeded(current_scaled, t.flow_bytes_s_milli, b)
    {
        fired |= rules::KNOWN_TARGET_PORT | volumetric_bits(b);
        if cat == 0 {
            cat  = 5; // ANOMALY
            conf = conf.max(65);
        }
    }

    // ── Rule 7: Outbound data exfiltration ────────────────────────────────
    // Byte-rate: DDSketch T / Z-score (no absolute fallback).
    // Duration:  hard minimum — must be a sustained transfer (≥ 5 s).
    if t.direction == 1
        && dur_ms > EXFIL_MIN_DURATION_MS
        && volumetric_exceeded(current_scaled, t.flow_bytes_s_milli, b)
    {
        fired |= rules::EXFIL_PATTERN | volumetric_bits(b);
        cat    = 4; // EXFILTRATION
        conf   = conf.max(80);
    }

    // ── Rule 8: Unauthorized Modbus write (ICS/SCADA) ─────────────────────
    if matches!(t.modbus_func_code, 5 | 6 | 15 | 16) {
        fired |= rules::MODBUS_WRITE;
        cat    = cat.max(3);
        conf   = conf.max(95);
    }

    // ── Rule 9: Invalid Modbus function code ──────────────────────────────
    if t.modbus_func_code > 0
        && !matches!(t.modbus_func_code, 1 | 2 | 3 | 4 | 5 | 6 | 15 | 16)
    {
        fired |= rules::MODBUS_INVALID;
        if cat == 0 {
            cat  = 5; // ANOMALY
            conf = conf.max(75);
        }
    }

    // ── Rule 10: Pure Z-score anomaly (no volumetric rule fired) ─────────
    // Only checked when neither the DDSketch nor the volumetric Z-score path
    // already fired.  Covers edge cases where one dimension exceeds Z > 3.0
    // but the primary volumetric rules didn't trigger.
    let volumetric_already_fired =
        fired & (rules::HIGH_RATE | rules::DDSKETCH_VOLUME | rules::ZSCORE_ANOMALY) != 0;

    if !volumetric_already_fired {
        let z_b = if b.stddev_bytes_s_milli > 0 {
            zscore_scaled(t.flow_bytes_s_milli, b.mean_bytes_s_milli, b.stddev_bytes_s_milli)
        } else {
            0
        };
        let z_p = if b.stddev_pkts_milli > 0 {
            zscore_pkts(t.packet_count, b)
        } else {
            0
        };
        if z_b > ZSCORE_THRESHOLD || z_p > ZSCORE_THRESHOLD {
            fired |= rules::ZSCORE_ANOMALY;
            if cat == 0 {
                cat  = 5; // ANOMALY
                conf = conf.max(68);
            }
        }
    }

    // ── Rule 11: LODA multivariate anomaly ───────────────────────────────
    // The LODA model was trained on 4 canonical features from historical session
    // data.  Records whose sum of per-projection −log(density) scores exceeds the
    // calibrated threshold fall in a low-density region of the projected feature
    // space and are flagged as anomalous.
    //
    // Projection weights ∈ {-1, 0, 1} → inner loop uses only ADD/SUB, no MUL.
    // Bin lookup iterates ≤ n_bins (~10) contiguous array entries — no pointer jumps.
    if let Some(score) = loda_score(&input.loda, t) {
        if score > input.loda.anomaly_threshold_fp10 {
            fired |= rules::LODA_ANOMALY;
            if cat == 0 {
                cat  = 5; // ANOMALY
                conf = conf.max(72);
            }
        }
    }

    // ── Rule 12: CUSUM C2 beacon (zero-MUL DAS-CUSUM) ────────────────────
    // The Python host executes the multiplierless comb pre-filter (Stages 0/1)
    // and epoch-folded L1 histogram (Stage 2), injecting per-period B_n scores
    // and the running CUSUM state into CusumModel for this source IP's history.
    // The guest proves Stage 3 only: S_n = max(0, S_{n-1} + B_n − k) > threshold.
    // All arithmetic is ADD + SUB + MAX — zero `*` operators on the RV32IM path.
    if cusum_beacon(&input.cusum) {
        fired |= rules::CUSUM_BEACON;
        if cat == 0 {
            cat  = 5; // ANOMALY — periodic C2 beaconing pattern
            conf = conf.max(77);
        }
    }

    // ── Confidence capping (mirrors Python validator.py) ──────────────────
    if SPARSE_SOURCETYPES.contains(&t.sourcetype) && conf > CONFIDENCE_CAP_SPARSE {
        conf   = CONFIDENCE_CAP_SPARSE;
        fired |= rules::CONFIDENCE_CAPPED;
    }

    conf = conf.min(100);

    ThreatVerdict {
        input_hash,
        is_threat: cat != 0,
        category:  cat,
        confidence_pct: conf,
        triggered_rules: fired,
    }
}
