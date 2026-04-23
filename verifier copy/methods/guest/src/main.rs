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
use verifier_core::{rules, NetworkTelemetry, ThreatVerdict};

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
    //    `env::read` deserializes from the zkVM's input stream using bincode.
    let telemetry: NetworkTelemetry = risc0_zkvm::guest::env::read();

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
fn evaluate(t: &NetworkTelemetry, input_hash: [u8; 32]) -> ThreatVerdict {
    let bytes_s   = t.bytes_per_sec();
    let dur_ms    = t.duration_ms();
    let mut fired = 0u32;
    let mut cat   = 0u8; // BENIGN
    let mut conf  = 0u8;

    // ── Rule 1: Volumetric DoS / DDoS ─────────────────────────────────────
    // Source: CIC-IDS-2017 DoS flows; Python analyzer DoS/DDoS label families.
    // A sustained data rate > 1 MB/s is well above normal unicast traffic.
    if bytes_s > THRESHOLD_DOS_BYTES_S {
        fired |= rules::HIGH_RATE;
        cat    = 3; // MALWARE (DoS family)
        conf   = conf.max(85);
    }

    // ── Rule 2: FTP / SSH brute force ─────────────────────────────────────
    // Mirrors Python _INTEL["FTP-Patator"] and _INTEL["SSH-Patator"].
    // Patator/Hydra tools typically send 50–500 auth packets per session.
    if t.dst_port == 21 || t.dst_port == 22 {
        fired |= rules::KNOWN_TARGET_PORT;
        if t.packet_count >= THRESHOLD_BRUTE_FORCE_PKTS {
            fired |= rules::BRUTE_FORCE;
            cat    = cat.max(2); // BRUTE_FORCE (if not already higher)
            conf   = conf.max(82);
        }
    }

    // ── Rule 3: RDP brute force ────────────────────────────────────────────
    // TCP 3389 with high packet count → password-spray or Mimikatz spray.
    if t.dst_port == 3389 && t.packet_count >= THRESHOLD_RDP_BRUTE_PKTS {
        fired |= rules::RDP_BRUTE | rules::BRUTE_FORCE;
        if cat < 2 {
            cat = 2; // BRUTE_FORCE
        }
        conf = conf.max(78);
    }

    // ── Rule 4: Stealth port probe (nmap SYN scan style) ──────────────────
    // Single-packet flows lasting < 100 ms match nmap -sS fingerprint.
    // Python: PortScan label family (CIC-IDS-2017 feature: Flow Duration < 1s).
    if dur_ms < THRESHOLD_PROBE_DURATION_MS && t.packet_count <= THRESHOLD_PROBE_PKTS {
        fired |= rules::RAPID_PROBE;
        if cat == 0 {
            cat  = 1; // PORT_SCAN
            conf = conf.max(70);
        }
    }

    // ── Rule 5: DNS amplification ──────────────────────────────────────────
    // UDP/53 with very high bytes/s → reflector abuse (mirrors DDoS pattern).
    if t.dst_port == 53 && t.protocol == 17 && bytes_s > THRESHOLD_DNS_AMP_BYTES_S {
        fired |= rules::DNS_AMPLIFICATION | rules::HIGH_RATE;
        cat    = 3; // MALWARE — DoS via amplification
        conf   = conf.max(90);
    }

    // ── Rule 6: Web anomaly ────────────────────────────────────────────────
    // High-rate traffic to HTTP/HTTPS ports — could be DDoS or web attack.
    // Python: Web Attack / DoS label for HTTP ports.
    if matches!(t.dst_port, 80 | 443 | 8080 | 8443) && bytes_s > THRESHOLD_WEB_ANOMALY_BYTES_S {
        fired |= rules::KNOWN_TARGET_PORT;
        if cat == 0 {
            cat  = 5; // ANOMALY (insufficient signal for stronger category)
            conf = conf.max(65);
        }
    }

    // ── Rule 7: Outbound data exfiltration ────────────────────────────────
    // Large sustained outbound flow — mirrors Python _INTEL["Infiltration"]
    // and _INTEL["Bot"] exfiltration indicators.
    if t.direction == 1
        && bytes_s > THRESHOLD_EXFIL_BYTES_S
        && dur_ms > THRESHOLD_EXFIL_DURATION_MS
    {
        fired |= rules::EXFIL_PATTERN;
        cat    = 4; // EXFILTRATION (overrides weaker categories)
        conf   = conf.max(80);
    }

    // ── Rule 8: Unauthorized Modbus write (ICS/SCADA) ──────────────────────
    // Any Modbus write function code (FC 5, 6, 15, 16) is treated as
    // unauthorized PLC manipulation — CRITICAL severity.
    if matches!(t.modbus_func_code, 5 | 6 | 15 | 16) {
        fired |= rules::MODBUS_WRITE;
        cat    = 3; // MALWARE — PLC manipulation
        conf   = conf.max(95);
    }

    // ── Rule 9: Invalid Modbus function code ──────────────────────────────
    // Function codes > 127 are Modbus exception responses; unusual codes
    // (not 1–6, 15, 16) in requests indicate fuzzing or recon.
    if t.modbus_func_code > 0
        && !matches!(t.modbus_func_code, 1 | 2 | 3 | 4 | 5 | 6 | 15 | 16)
    {
        fired |= rules::MODBUS_INVALID;
        if cat == 0 {
            cat  = 5; // ANOMALY
            conf = conf.max(75);
        }
    }

    // ── Confidence capping (mirrors Python validator.py cap_confidence) ────
    // Sparse/low-fidelity sourcetypes are capped at 50% regardless of rules.
    if SPARSE_SOURCETYPES.contains(&t.sourcetype) && conf > CONFIDENCE_CAP_SPARSE {
        conf   = CONFIDENCE_CAP_SPARSE;
        fired |= rules::CONFIDENCE_CAPPED;
    }

    // Safety: clamp confidence to [0, 100]
    conf = conf.min(100);

    ThreatVerdict {
        input_hash,
        is_threat: cat != 0,
        category: cat,
        confidence_pct: conf,
        triggered_rules: fired,
    }
}
