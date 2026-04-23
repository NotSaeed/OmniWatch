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
    /// Function code is considered an illegal or unauthorized command (e.g., FC 05)
    pub const ILLEGAL_FUNCTION_CODE: u32 = 1 << 0;
    /// The specified unit ID is not authorized for control commands
    pub const UNAUTHORIZED_UNIT: u32 = 1 << 1;
    /// The payload length does not match the MBAP header length (Buffer anomaly)
    pub const BUFFER_ANOMALY: u32 = 1 << 2;
}

// ── Network telemetry input ──────────────────────────────────────────────────

/// One processed Modbus network flow record sent to the zkVM for evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusTelemetry {
    /// Source IPv4 as big-endian octets.
    pub src_ip: [u8; 4],
    /// Destination IPv4 as big-endian octets.
    pub dst_ip: [u8; 4],
    /// Modbus Transaction Identifier.
    pub transaction_id: u16,
    /// Protocol Identifier (normally 0 for Modbus).
    pub protocol_id: u16,
    /// Length field from the MBAP header.
    pub length: u16,
    /// Unit Identifier (slave address).
    pub unit_id: u8,
    /// Modbus Function Code.
    pub function_code: u8,
    /// Modbus PDU Data payload.
    pub data: Vec<u8>,
}

impl ModbusTelemetry {
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
