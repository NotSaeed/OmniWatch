//! Shared protocol types between the Host prover and the zkVM Guest.
//!
//! Both sides must agree on the exact binary layout — bincode encodes struct
//! fields in declaration order, so field order is part of the wire format.
//! Never reorder fields without bumping the crate version.
//!
//! v2 additions (ML upgrade):
//!   - `HostBaselines` — per-host statistical baselines (mean/stddev, ×1000
//!     fixed-point) so the guest can compute Z-scores without floating-point.
//!   - `TelemetryInput` — wrapper that bundles a `NetworkTelemetry` record
//!     with its `HostBaselines`.  The guest reads one `TelemetryInput` per
//!     proof; the host serialises a `TelemetryInput` into the input stream.
//!   - `rules::ZSCORE_ANOMALY` — new rule bit for statistical outlier detection.

use serde::{Deserialize, Serialize};

// ── Threat category codes ────────────────────────────────────────────────────

/// Mirrors the Python `ThreatCategory` enum in `triage/models.py`.
/// Encoded as u8 in the journal to keep the commitment compact.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatCategory {
    Benign       = 0,
    PortScan     = 1,
    BruteForce   = 2,
    Malware      = 3, // includes DoS / DDoS
    Exfiltration = 4,
    Anomaly      = 5,
}

impl ThreatCategory {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::PortScan,
            2 => Self::BruteForce,
            3 => Self::Malware,
            4 => Self::Exfiltration,
            5 => Self::Anomaly,
            _ => Self::Benign,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Benign       => "BENIGN",
            Self::PortScan     => "PORT_SCAN",
            Self::BruteForce   => "BRUTE_FORCE",
            Self::Malware      => "MALWARE",
            Self::Exfiltration => "EXFILTRATION",
            Self::Anomaly      => "ANOMALY",
        }
    }
}

// ── Triggered rule bit-flags ─────────────────────────────────────────────────

pub mod rules {
    /// Volumetric rate exceeded absolute fallback threshold (bytes/s > 1 MB).
    /// Fires only when no baselines are available.
    pub const HIGH_RATE: u32          = 1 << 0;
    /// Destination port matches a known attack-targeted service.
    pub const KNOWN_TARGET_PORT: u32  = 1 << 1;
    /// Port 21/22 + packet_count > threshold — FTP/SSH brute force.
    pub const BRUTE_FORCE: u32        = 1 << 2;
    /// flow_duration < 100 ms AND packet_count ≤ 2 — stealth probe.
    pub const RAPID_PROBE: u32        = 1 << 3;
    /// Port 53 + UDP + bytes/s > 100 KB — DNS amplification.
    pub const DNS_AMPLIFICATION: u32  = 1 << 4;
    /// direction=outbound AND bytes/s > 500 KB AND duration > 5 s — data theft.
    pub const EXFIL_PATTERN: u32      = 1 << 5;
    /// Port 3389 + packet_count > threshold — RDP brute force.
    pub const RDP_BRUTE: u32          = 1 << 6;
    /// Confidence was capped at 50% (sparse sourcetype — mirrors Python validator).
    pub const CONFIDENCE_CAPPED: u32  = 1 << 7;
    /// Modbus write operation detected (FC 5, 6, 15, 16).
    pub const MODBUS_WRITE: u32       = 1 << 8;
    /// Invalid / unusual Modbus function code (fuzzing / recon indicator).
    pub const MODBUS_INVALID: u32     = 1 << 9;
    /// Z-score |Z| > 3.0 on bytes/s or packet count — ML statistical outlier.
    /// Fires only when `HostBaselines.stddev_bytes_s_milli > 0`.
    pub const ZSCORE_ANOMALY: u32      = 1 << 10;
    /// DDSketch 99th-percentile volumetric threshold exceeded:
    ///   `(bytes_per_sec << 14) > ddsketch_threshold_fp14`
    /// Fires only when `HostBaselines.ddsketch_threshold_fp14 > 0`.
    /// Takes priority over ZSCORE_ANOMALY for volumetric byte-rate rules.
    pub const DDSKETCH_VOLUME: u32          = 1 << 11;
    /// Isolation Forest multivariate anomaly: average path length (×2^14)
    /// is below `IsolationForestModel.path_length_threshold`.
    /// Fires only when `IsolationForestModel.tree_roots` is non-empty.
    pub const ISOLATION_FOREST_ANOMALY: u32 = 1 << 12;
}

// ── Network telemetry input ──────────────────────────────────────────────────

/// One processed network flow record sent to the zkVM for evaluation.
///
/// All floating-point values are represented in fixed-point (×1000) to
/// guarantee bit-identical results across every RISC-V platform.
///
/// `flow_bytes_s_milli` = actual_bytes_per_second × 1000
///   e.g. 8_500_000 ≡ 8.5 KB/s
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTelemetry {
    /// Source IPv4 as big-endian octets.
    pub src_ip: [u8; 4],
    /// Destination IPv4 as big-endian octets.
    pub dst_ip: [u8; 4],
    /// Destination port (0–65535).
    pub dst_port: u16,
    /// IANA protocol number: 6=TCP, 17=UDP, 1=ICMP.
    pub protocol: u8,
    /// Flow duration in microseconds.
    pub flow_duration_us: u64,
    /// Bytes per second × 1000 (fixed-point; 8_500_000 = 8.5 KB/s).
    pub flow_bytes_s_milli: u64,
    /// Total packets observed in this flow.
    pub packet_count: u32,
    /// 0 = inbound toward our network, 1 = outbound from it.
    pub direction: u8,
    /// Sourcetype tag from the originating log source.
    /// 0=simulated/unknown, 1=suricata, 2=sysmon, 3=pan_traffic, 4=zeek
    pub sourcetype: u8,
    // ── ICS/SCADA fields ─────────────────────────────────────────────────────
    pub modbus_func_code: u8,
    pub modbus_unit_id: u8,
    pub zeek_uid: [u8; 18],
    pub epoch_nonce: u64,
}

impl NetworkTelemetry {
    /// Returns actual bytes/s as an integer (truncated).
    #[inline]
    pub fn bytes_per_sec(&self) -> u64 {
        self.flow_bytes_s_milli / 1000
    }

    /// Returns flow duration in whole milliseconds.
    #[inline]
    pub fn duration_ms(&self) -> u64 {
        self.flow_duration_us / 1000
    }

    pub fn src_ip_str(&self) -> String {
        format!("{}.{}.{}.{}", self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3])
    }

    pub fn dst_ip_str(&self) -> String {
        format!("{}.{}.{}.{}", self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3])
    }
}

// ── Host baselines (statistical context for Z-score evaluation) ───────────────

/// Per-host flow statistics derived from historical or session-level data.
///
/// All values are **fixed-point × 1000** to match the `flow_bytes_s_milli`
/// scale and to eliminate floating-point from the zkVM guest entirely.
///
/// When `stddev_bytes_s_milli == 0` the Z-score byte-rate rule is skipped.
/// When `stddev_pkts_milli == 0`    the Z-score packet-count rule is skipped.
/// This preserves backward compatibility with unbaselined records.
///
/// # Encoding example
/// If the historical mean bytes/s is 12 345.6 → store 12_345_600.
/// If the historical stddev is 3 210.0 B/s     → store 3_210_000.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostBaselines {
    /// Mean bytes/s × 1000 (matches `flow_bytes_s_milli` scale).
    pub mean_bytes_s_milli: u64,
    /// Standard deviation bytes/s × 1000.  0 = no baseline available.
    pub stddev_bytes_s_milli: u64,
    /// Mean packet count per flow × 1000.
    pub mean_pkts_milli: u64,
    /// Standard deviation of packet count × 1000.  0 = no baseline available.
    pub stddev_pkts_milli: u64,
    /// DDSketch 99th-percentile bytes/s in 14-bit fixed-point.
    /// T = ⌊p99_bytes_per_sec × 2^14⌋, computed by the Python pipeline.
    /// 0 = not computed; guest falls back to Z-score or no volumetric check.
    pub ddsketch_threshold_fp14: u64,
}

// ── Isolation Forest model (flattened for zkVM) ───────────────────────────────

/// Stride-4 flattened IsolationForest trained by the Python pipeline.
///
/// Node layout (4 consecutive i32 values per node at index `i*4`):
///   [0] feature_index   — 0–3 for internal nodes; -1 = leaf
///   [1] threshold_fp14  — floor(threshold × 2^14); 0 for leaves
///   [2] left_child      — GLOBAL node index of left subtree; -1 for leaves
///   [3] right_child     — GLOBAL node index of right subtree; -1 for leaves
///
/// A record is anomalous when:
///   `avg_path_fp14 = (sum of per-tree depths × 2^14) / n_trees`
///   `avg_path_fp14 < path_length_threshold`
///
/// When `tree_roots` is empty the guest skips Rule 11 entirely.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IsolationForestModel {
    /// Stride-4 array: [feature_index, threshold_fp14, left_global, right_global] per node.
    pub nodes: Vec<i32>,
    /// Global node index (offset into `nodes / 4`) of each tree's root.
    pub tree_roots: Vec<i32>,
    /// Average path length × 2^14 below which a record is flagged as anomalous.
    /// 0 = forest not available; guest skips Rule 11.
    pub path_length_threshold: i32,
}

// ── Combined guest input ──────────────────────────────────────────────────────

/// The struct the zkVM guest reads from the input stream.
///
/// Bundling telemetry + baselines in one struct keeps the guest's `env::read`
/// call count at 1, which is cheaper in the STARK proof than two reads.
///
/// For records with no available baselines, set all `HostBaselines` fields to
/// zero — the guest will fall back to the absolute threshold rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryInput {
    pub telemetry: NetworkTelemetry,
    pub baselines: HostBaselines,
    pub forest:    IsolationForestModel,
}

// ── Threat verdict output (committed to zkVM journal) ────────────────────────

/// The tamper-proof output committed by the guest to the STARK journal.
///
/// A verifier can decode this from `receipt.journal` and know — with
/// mathematical certainty — that the threat rules were evaluated honestly
/// on exactly the telemetry that produced `input_hash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatVerdict {
    /// SHA-256 of the bincode-encoded `TelemetryInput`.
    pub input_hash: [u8; 32],
    pub is_threat: bool,
    pub category: u8,
    pub confidence_pct: u8,
    pub triggered_rules: u32,
}

impl ThreatVerdict {
    pub fn category_name(&self) -> &'static str {
        ThreatCategory::from_u8(self.category).name()
    }
}
