//! OmniWatch Threat Verifier — zkVM Guest
//!
//! This program executes inside the RISC Zero zkVM.  Every instruction it
//! runs is recorded in an execution trace that the prover converts into a
//! STARK proof.  Anyone holding the proof receipt can verify — with
//! mathematical certainty — that these exact rules were applied to exactly
//! the committed input, without seeing the raw telemetry.
//!
//! **Porting note**: all threat thresholds here are derived from the Python
//! invariants in:
//!   - backend/triage/validator.py   (confidence caps, sparse sourcetypes)
//!   - backend/triage/engine.py      (confidence boost logic)
//!   - backend/cicids/analyzer.py    (attack label ↔ severity mapping)

#![no_main]

use sha2::{Digest, Sha256};
use verifier_core::{rules, ModbusTelemetry, ThreatVerdict};

risc0_zkvm::guest::entry!(main);

// ── Sourcetype constants (mirrors Python validator.py SPARSE_SOURCETYPES) ───

/// Sourcetype IDs that get confidence capped at 50% — mirrors:
///   SPARSE_SOURCETYPES = {"osquery", "syslog", "simulated"}  (validator.py)
const SPARSE_SOURCETYPES: &[u8] = &[0 /* simulated/unknown */];
const CONFIDENCE_CAP_SPARSE: u8 = 50; // 50% — matches Python 0.50 cap

// ── Threshold constants — ported from Python analyzer patterns ───────────────

/// Bytes/s threshold for DoS / DDoS classification.
/// Derived from observed CIC-IDS-2017 DoS flows (analyzer.py label logic).
const THRESHOLD_DOS_BYTES_S: u64 = 1_000_000; // 1 MB/s

/// Bytes/s for DNS amplification detection (port 53 + UDP).
const THRESHOLD_DNS_AMP_BYTES_S: u64 = 100_000; // 100 KB/s

/// Bytes/s for outbound exfiltration pattern.
const THRESHOLD_EXFIL_BYTES_S: u64 = 500_000; // 500 KB/s

/// Minimum flow duration (ms) required to confirm exfiltration (not just noise).
const THRESHOLD_EXFIL_DURATION_MS: u64 = 5_000; // 5 seconds

/// Packet count threshold for FTP/SSH brute force (port 21/22).
/// Patator tools typically fire 50–500 auth attempts in quick succession.
const THRESHOLD_BRUTE_FORCE_PKTS: u32 = 50;

/// Packet count threshold for RDP brute force (port 3389).
const THRESHOLD_RDP_BRUTE_PKTS: u32 = 30;

/// A stealth port probe is < 100 ms with ≤ 2 packets (SYN-only nmap style).
const THRESHOLD_PROBE_DURATION_MS: u64 = 100;
const THRESHOLD_PROBE_PKTS: u32 = 2;

/// Web service bytes/s anomaly threshold (port 80/443/8080).
const THRESHOLD_WEB_ANOMALY_BYTES_S: u64 = 50_000; // 50 KB/s

// ── Entry point ──────────────────────────────────────────────────────────────

fn main() {
    // 1. Read the telemetry struct sent by the host prover.
    let telemetry: ModbusTelemetry = risc0_zkvm::guest::env::read();

    // 2. Hash the raw (bincode-encoded) input — this binds the verdict to
    //    the exact bytes evaluated, making tampering detectable.
    let input_bytes = bincode::serialize(&telemetry).expect("bincode serialize");
    let mut hasher = Sha256::new();
    hasher.update(&input_bytes);
    let hash_out = hasher.finalize();
    let mut input_hash = [0u8; 32];
    input_hash.copy_from_slice(&hash_out);

    // 3. Run all threat detection rules.
    let verdict = evaluate(&telemetry, input_hash);

    // 4. Commit the verdict to the zkVM journal.
    //    This is the public output that will be embedded in the STARK receipt
    //    and can be inspected by anyone who holds the proof.
    risc0_zkvm::guest::env::commit(&verdict);
}

// ── Threat rule engine ───────────────────────────────────────────────────────

/// Evaluate all threat invariants against one telemetry record.
///
/// Rules are applied in priority order; a higher-priority category can
/// promote a verdict even if a lower-priority one already fired.
fn evaluate(t: &ModbusTelemetry, input_hash: [u8; 32]) -> ThreatVerdict {
    let mut fired = 0u32;
    let mut cat   = 0u8; // BENIGN
    let mut conf  = 0u8;

    // ── Rule 1: Buffer Anomaly ─────────────────────────────────────────────
    // MBAP Length should be: Unit ID (1) + Function Code (1) + Data length
    // If the reported length doesn't match the actual payload size, it's a buffer overflow attempt.
    // Modbus data length in the struct is `data.len()`
    let expected_data_len = if t.length > 2 { (t.length - 2) as usize } else { 0 };
    if expected_data_len != t.data.len() || t.length < 2 {
        fired |= rules::BUFFER_ANOMALY;
        cat    = 5; // ANOMALY
        conf   = conf.max(85);
    }

    // ── Rule 2: Illegal Function Code ──────────────────────────────────────
    // 0x05 (Write Single Coil) and 0x06 (Write Single Register) are control commands.
    // In our invariant, perhaps only certain IPs (HMI) can write. But we're just checking
    // if a write command was even issued. Writing is highly critical.
    if t.function_code == 5 || t.function_code == 6 || t.function_code == 15 || t.function_code == 16 {
        fired |= rules::ILLEGAL_FUNCTION_CODE;
        // Escalation!
        cat  = 3; // MALWARE (Or equivalent critical threat like sabotage)
        conf = conf.max(90);
    }

    ThreatVerdict {
        policy_version: t.policy_version,
        conn_uid: t.conn_uid.clone(),
        epoch_timestamp: t.epoch_timestamp,
        input_hash,
        is_threat: cat != 0,
        category: cat,
        confidence_pct: conf,
        triggered_rules: fired,
    }
}
