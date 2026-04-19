//! Shared protocol types between the Host prover and the zkVM Guest.
//!
//! Both sides must agree on the exact binary layout — bincode encodes
//! struct fields in declaration order, so field order is part of the
//! wire format.  Never reorder fields without bumping the crate version.

use serde::{Deserialize, Serialize};

// ── Threat category codes ────────────────────────────────────────────────────

/// Mirrors the Python `ThreatCategory` enum in `triage/models.py`.
/// Encoded as u8 in the journal to keep the commitment compact.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatCategory {
    Benign         = 0,
    PortScan       = 1,
    BruteForce     = 2,
    Malware        = 3,  // includes DoS / DDoS
    Exfiltration   = 4,
    Anomaly        = 5,
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
    /// bytes/s > 1 MB — DoS / DDoS indicator
    pub const HIGH_RATE: u32         = 1 << 0;
    /// Destination port matches a known attack-targeted service
    pub const KNOWN_TARGET_PORT: u32 = 1 << 1;
    /// Port 21/22 + packet_count > 50 — FTP/SSH brute force
    pub const BRUTE_FORCE: u32       = 1 << 2;
    /// flow_duration < 100 ms AND packet_count <= 2 — stealth probe
    pub const RAPID_PROBE: u32       = 1 << 3;
    /// Port 53 + UDP + bytes/s > 100 KB — DNS amplification
    pub const DNS_AMPLIFICATION: u32 = 1 << 4;
    /// direction=outbound AND bytes/s > 500 KB AND duration > 5 s — data theft
    pub const EXFIL_PATTERN: u32     = 1 << 5;
    /// Port 3389 + packet_count > 30 — RDP brute force
    pub const RDP_BRUTE: u32         = 1 << 6;
    /// Confidence was capped at 50% (sparse sourcetype — matches Python validator)
    pub const CONFIDENCE_CAPPED: u32 = 1 << 7;
}

// ── Network telemetry input ──────────────────────────────────────────────────

/// One processed network flow record sent to the zkVM for evaluation.
///
/// Maps to the CIC-IDS-2017 / OmniWatch `CicidsEvent` schema:
///   src_ip, dst_ip, dst_port, protocol, flow_duration, flow_bytes_s
///
/// Floats are avoided inside the zkVM (non-deterministic across platforms).
/// `flow_bytes_s_milli` = actual_bytes_per_second × 1000 (fixed-point, 3dp).
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
    /// Flow duration in microseconds (avoids f64 in guest).
    pub flow_duration_us: u64,
    /// Bytes per second × 1000 (fixed-point; 8_500_000 = 8.5 KB/s).
    pub flow_bytes_s_milli: u64,
    /// Total packets observed in this flow.
    pub packet_count: u32,
    /// 0 = inbound toward our network, 1 = outbound from it.
    pub direction: u8,
    /// Sourcetype tag from the originating log source.
    /// 0=simulated/unknown, 1=suricata, 2=sysmon, 3=pan_traffic, 4=zeek
    /// Used to apply confidence capping (mirrors Python validator.py).
    pub sourcetype: u8,
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

    /// src_ip formatted as a dotted-decimal string.
    pub fn src_ip_str(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3]
        )
    }

    /// dst_ip formatted as a dotted-decimal string.
    pub fn dst_ip_str(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3]
        )
    }
}

// ── Threat verdict output (committed to zkVM journal) ───────────────────────

/// The tamper-proof output committed by the guest to the STARK journal.
///
/// A verifier can decode this from `receipt.journal` and know — with
/// mathematical certainty — that the threat rules were evaluated honestly
/// on exactly the telemetry that produced `input_hash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatVerdict {
    /// SHA-256 of the bincode-encoded `NetworkTelemetry` input.
    /// Binds this verdict irrevocably to the telemetry that was evaluated.
    pub input_hash: [u8; 32],
    /// Whether the telemetry violates at least one threat rule.
    pub is_threat: bool,
    /// Threat category (see `ThreatCategory`).
    pub category: u8,
    /// Confidence percentage 0–100 (mirrors Python 0.0–1.0 × 100).
    pub confidence_pct: u8,
    /// Bit-field of which rules fired (see `rules` module).
    pub triggered_rules: u32,
}

impl ThreatVerdict {
    pub fn category_name(&self) -> &'static str {
        ThreatCategory::from_u8(self.category).name()
    }
}
