//! OmniWatch zkVM Host Prover
//!
//! Constructs mock network telemetry, invokes the RISC Zero prover to
//! generate a STARK proof, then verifies and decodes the tamper-proof
//! ThreatVerdict from the receipt journal.
//!
//! SCOREBOARD 1 — Performance metrics:
//!   • STARK generation latency (wall-clock, std::time::Instant)
//!   • Total / user cycles consumed inside the zkVM
//!   • Approximate resident memory overhead (via /proc/self/status on Linux
//!     or a conservative stack-based estimate on other platforms)

use std::time::Instant;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rayon::ThreadPoolBuilder;
use methods::{VERIFIER_GUEST_ELF, VERIFIER_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use verifier_core::{CusumModel, HostBaselines, LodaModel, NetworkTelemetry, TelemetryInput, ThreatVerdict};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Encode `[u8; 32]` as a lowercase hex string for display.
fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Attempt to read the current RSS (Resident Set Size) of this process in MiB.
/// On Linux this reads `/proc/self/status`; falls back to 0 on other platforms.
fn resident_mib() -> u64 {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    let kb: u64 = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    return kb / 1024;
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Windows: approximate from the known RISC Zero prover overhead.
        // The Groth16 prover typically peaks around 2–4 GiB; the dev-mode
        // prover is much lighter (~200–600 MiB).
        0 // real measurement requires winapi crate; flag as "see task manager"
    }
}

// ── Verify mode ──────────────────────────────────────────────────────────────

/// Called when the host is invoked as:
///   omniwatch-verifier --verify <base64-encoded-bincode-receipt>
///
/// Deserialises the receipt, verifies it against the compiled guest image ID,
/// decodes the ThreatVerdict from the journal, then prints a JSON object to
/// stdout and exits 0.  Any failure prints to stderr and exits 1.
///
/// The Python backend's /api/verify-remediation calls this function via
/// asyncio.create_subprocess_exec and parses the stdout JSON.
fn verify_mode(b64: &str) -> Result<()> {
    let bytes = B64
        .decode(b64)
        .context("Base64 decode failed — receipt may be truncated or corrupted")?;

    let receipt: Receipt = bincode::deserialize(&bytes)
        .context("bincode deserialise failed — ensure receipt was serialised with bincode 1.3")?;

    receipt
        .verify(VERIFIER_GUEST_ID)
        .context("STARK proof verification failed — image ID mismatch or proof invalid")?;

    let verdict: ThreatVerdict = receipt
        .journal
        .decode()
        .context("Failed to decode ThreatVerdict from journal")?;

    let out = serde_json::json!({
        "valid":           true,
        "input_hash":      hex::encode(verdict.input_hash),
        "is_threat":       verdict.is_threat,
        "category":        verdict.category,
        "category_name":   verdict.category_name(),
        "confidence_pct":  verdict.confidence_pct,
        "triggered_rules": verdict.triggered_rules,
    });
    println!("{}", out);
    Ok(())
}


// ── Scenario builder ─────────────────────────────────────────────────────────

struct Scenario {
    label:     &'static str,
    telemetry: NetworkTelemetry,
    /// Statistical baselines for adaptive Z-score / DDSketch rules.
    baselines: HostBaselines,
    /// LODA model for Rule 11.  Use `LodaModel::default()` (k=0) when not available.
    loda:      LodaModel,
}

fn build_scenarios() -> Vec<Scenario> {
    vec![
        // ── Scenario 1: SSH Brute-Force (Patator-style) ───────────────────
        // 340 TCP packets to port 22 over 15 s at ~8.5 KB/s.
        // Detection: packet Z-score (340 pkts vs mean=12, Z≈32).
        // T=0: brute-force is packet-based, not volumetric — DDSketch unused.
        // Expected verdict: BRUTE_FORCE, ~82% confidence.
        Scenario {
            label: "SSH Brute-Force (Patator)",
            telemetry: NetworkTelemetry {
                src_ip:             [185, 220, 101, 45],
                dst_ip:             [192, 168,   1, 100],
                dst_port:           22,
                protocol:           6,
                flow_duration_us:   15_000_000,
                flow_bytes_s_milli: 8_500_000,
                packet_count:       340,
                direction:          0,
                sourcetype:         1,
                modbus_func_code:   0,
                modbus_unit_id:     0,
                zeek_uid:           [0u8; 18],
                epoch_nonce:        0,
            },
            baselines: HostBaselines {
                mean_bytes_s_milli:      3_000_000,
                stddev_bytes_s_milli:    2_000_000,
                mean_pkts_milli:         12_000,
                stddev_pkts_milli:       9_000,
                ddsketch_threshold_fp14: 0,
            },
            loda: LodaModel::default(),
        },

        // ── Scenario 2: DNS Amplification DDoS ───────────────────────────
        // 18 000 UDP packets to port 53 at 2.5 MB/s over 1 s.
        // T = floor(200 KB/s × 2^14) = 3_276_800_000  (p99 of normal DNS).
        // current_scaled = 2_500_000 × 16384 = 40_960_000_000 > T → DDSKETCH_VOLUME ✓
        // Expected verdict: MALWARE (DoS), ~90% confidence.
        Scenario {
            label: "DNS Amplification DDoS",
            telemetry: NetworkTelemetry {
                src_ip:             [203,   0, 113, 42],
                dst_ip:             [  8,   8,   8,  8],
                dst_port:           53,
                protocol:           17,
                flow_duration_us:   1_000_000,
                flow_bytes_s_milli: 2_500_000_000,
                packet_count:       18_000,
                direction:          0,
                sourcetype:         1,
                modbus_func_code:   0,
                modbus_unit_id:     0,
                zeek_uid:           [0u8; 18],
                epoch_nonce:        0,
            },
            baselines: HostBaselines {
                mean_bytes_s_milli:      50_000_000,
                stddev_bytes_s_milli:    30_000_000,
                mean_pkts_milli:         40_000,
                stddev_pkts_milli:       25_000,
                ddsketch_threshold_fp14: 3_276_800_000,
            },
            loda: LodaModel::default(),
        },

        // ── Scenario 3: Stealth nmap SYN Probe ───────────────────────────
        // 1 TCP SYN to port 443 in 50 ms — classic stealthy port scan.
        // Rule 4 (RAPID_PROBE) fires on fixed timing/packet thresholds only.
        // T=0: timing-based rule; DDSketch unused.
        // Expected verdict: PORT_SCAN, ~70% confidence.
        Scenario {
            label: "Stealth nmap SYN Probe",
            telemetry: NetworkTelemetry {
                src_ip:             [45, 152, 66, 240],
                dst_ip:             [10,   0,  1, 50],
                dst_port:           443,
                protocol:           6,
                flow_duration_us:   50_000,
                flow_bytes_s_milli: 200_000,
                packet_count:       1,
                direction:          0,
                sourcetype:         1,
                modbus_func_code:   0,
                modbus_unit_id:     0,
                zeek_uid:           [0u8; 18],
                epoch_nonce:        0,
            },
            baselines: HostBaselines {
                mean_bytes_s_milli:      30_000_000,
                stddev_bytes_s_milli:    20_000_000,
                mean_pkts_milli:         50_000,
                stddev_pkts_milli:       30_000,
                ddsketch_threshold_fp14: 0,
            },
            loda: LodaModel::default(),
        },

        // ── Scenario 4: Outbound Data Exfiltration ────────────────────────
        // 700 KB/s outbound for 30 s — large sustained data transfer outward.
        // T = floor(600 KB/s × 2^14) = 9_830_400_000  (p99 of normal outbound).
        // current_scaled = 700_000 × 16384 = 11_468_800_000 > T → DDSKETCH_VOLUME ✓
        // Expected verdict: EXFILTRATION, ~80% confidence.
        Scenario {
            label: "Outbound Data Exfiltration",
            telemetry: NetworkTelemetry {
                src_ip:             [10,  0,  1,  25],
                dst_ip:             [91, 108, 4, 167],
                dst_port:           443,
                protocol:           6,
                flow_duration_us:   30_000_000,
                flow_bytes_s_milli: 700_000_000,
                packet_count:       12_000,
                direction:          1,
                sourcetype:         2,
                modbus_func_code:   0,
                modbus_unit_id:     0,
                zeek_uid:           [0u8; 18],
                epoch_nonce:        0,
            },
            baselines: HostBaselines {
                mean_bytes_s_milli:      200_000_000,
                stddev_bytes_s_milli:    100_000_000,
                mean_pkts_milli:         500_000,
                stddev_pkts_milli:       300_000,
                ddsketch_threshold_fp14: 9_830_400_000,
            },
            loda: LodaModel::default(),
        },

        // ── Scenario 5: Benign HTTPS Session ─────────────────────────────
        // Normal HTTPS browsing — 15 KB/s, short, inbound.
        // T = floor(200 KB/s × 2^14) = 3_276_800_000.
        // current_scaled = 15_000 × 16384 = 245_760_000 < T → NOT volumetric ✓
        // Expected verdict: BENIGN, no rules triggered.
        Scenario {
            label: "Benign HTTPS Browsing",
            telemetry: NetworkTelemetry {
                src_ip:             [172, 16, 10,  5],
                dst_ip:             [93, 184, 216, 34],
                dst_port:           443,
                protocol:           6,
                flow_duration_us:   2_500_000,
                flow_bytes_s_milli: 15_000_000,
                packet_count:       42,
                direction:          0,
                sourcetype:         0,
                modbus_func_code:   0,
                modbus_unit_id:     0,
                zeek_uid:           [0u8; 18],
                epoch_nonce:        0,
            },
            baselines: HostBaselines {
                mean_bytes_s_milli:      50_000_000,
                stddev_bytes_s_milli:    30_000_000,
                mean_pkts_milli:         60_000,
                stddev_pkts_milli:       40_000,
                ddsketch_threshold_fp14: 3_276_800_000,
            },
            loda: LodaModel::default(),
        },

        // ── Scenario 6: FTP Brute Force (Patator) ────────────────────────
        // 280 TCP packets to port 21 — Patator dictionary attack.
        // Detection: packet Z-score (280 pkts vs mean=8, Z≈34).
        // T=0: packet-based rule; DDSketch unused.
        // Expected verdict: BRUTE_FORCE, ~82% confidence.
        Scenario {
            label: "FTP Brute-Force (Patator)",
            telemetry: NetworkTelemetry {
                src_ip:             [118, 193, 72, 21],
                dst_ip:             [192, 168,  1, 200],
                dst_port:           21,
                protocol:           6,
                flow_duration_us:   45_000_000,
                flow_bytes_s_milli: 6_200_000,
                packet_count:       280,
                direction:          0,
                sourcetype:         1,
                modbus_func_code:   0,
                modbus_unit_id:     0,
                zeek_uid:           [0u8; 18],
                epoch_nonce:        0,
            },
            baselines: HostBaselines {
                mean_bytes_s_milli:      2_000_000,
                stddev_bytes_s_milli:    1_500_000,
                mean_pkts_milli:         8_000,
                stddev_pkts_milli:       8_000,
                ddsketch_threshold_fp14: 0,
            },
            loda: LodaModel::default(),
        },

        // ── Scenario 7: Unauthorized Modbus PLC Write (ICS/SCADA) ────────
        // FC 16 (Write Multiple Registers) from external IP to a PLC.
        // MODBUS_WRITE rule fires on hard FC match — no baseline needed.
        // Expected verdict: MALWARE, ~95% confidence.
        Scenario {
            label: "Unauthorized Modbus PLC Write",
            telemetry: NetworkTelemetry {
                src_ip:             [ 10,  0, 50,  1],
                dst_ip:             [ 10,  0, 10,  5],
                dst_port:           502,
                protocol:           6,
                flow_duration_us:   200_000,
                flow_bytes_s_milli: 1_200_000,
                packet_count:       4,
                direction:          0,
                sourcetype:         4,
                modbus_func_code:   16,
                modbus_unit_id:     1,
                zeek_uid:           *b"CXbbkK4Ydx3q1M0Z0\x00",
                epoch_nonce:        1_745_000_000,
            },
            baselines: HostBaselines::default(),
            loda:      LodaModel::default(),
        },
    ]
}

// ── Core prove-and-verify routine ────────────────────────────────────────────

/// Run the zkVM prover for one scenario and print the performance report.
fn prove_scenario(s: &Scenario) -> Result<()> {
    println!("\n{}", "═".repeat(68));
    println!("  SCENARIO : {}", s.label);
    println!("  Source   : {}", s.telemetry.src_ip_str());
    println!("  Target   : {}:{}", s.telemetry.dst_ip_str(), s.telemetry.dst_port);
    println!("{}", "─".repeat(68));

    // ── Build the executor environment ────────────────────────────────────
    // Bundle telemetry + baselines into TelemetryInput so the guest can
    // compute Z-scores without floating-point operations.
    let input = TelemetryInput {
        telemetry: s.telemetry.clone(),
        baselines: s.baselines.clone(),
        loda:      s.loda.clone(),
        cusum:     CusumModel::default(), // no beacon history for hardcoded scenarios
    };
    let env = ExecutorEnv::builder()
        .write(&input)
        .context("Failed to write TelemetryInput to executor env")?
        .build()
        .context("Failed to build executor env")?;

    // ── Obtain the prover ─────────────────────────────────────────────────
    // `default_prover()` returns:
    //   • The local CPU prover when RISC0_PROVER=local (or default in dev mode)
    //   • Bonsai cloud prover when RISC0_PROVER=bonsai + BONSAI_API_KEY is set
    let prover = default_prover();

    // ── SCOREBOARD 1: STARK generation latency ────────────────────────────
    let mem_before = resident_mib();
    println!("[*] Starting STARK proof generation…");

    let t0 = Instant::now();
    let prove_info = prover
        .prove(env, VERIFIER_GUEST_ELF)
        .context("Prover failed")?;
    let stark_latency = t0.elapsed();

    let mem_after  = resident_mib();
    let mem_delta  = mem_after.saturating_sub(mem_before);

    // ── Print performance metrics ─────────────────────────────────────────
    println!("[+] STARK generation latency : {:.4}s", stark_latency.as_secs_f64());
    if mem_delta > 0 {
        println!("[+] Prover memory overhead   : ~{} MiB (RSS delta)", mem_delta);
    } else {
        println!("[+] Prover memory overhead   : (set RISC0_PROVER=local on Linux for RSS)");
    }
    println!(
        "[+] Proof segments           : {}",
        prove_info.stats.segments
    );
    println!(
        "[+] Total zkVM cycles        : {}",
        prove_info.stats.total_cycles
    );
    println!(
        "[+] User cycles              : {}  ({:.1}% of total)",
        prove_info.stats.user_cycles,
        prove_info.stats.user_cycles as f64 / prove_info.stats.total_cycles.max(1) as f64 * 100.0
    );

    // ── Verify the receipt (cryptographic integrity check) ────────────────
    let receipt = prove_info.receipt;
    receipt
        .verify(VERIFIER_GUEST_ID)
        .context("Receipt verification failed — image ID mismatch")?;

    // ── Emit the receipt as base64 for /api/verify-remediation ───────────
    // The Python backend parses lines starting with "[RECEIPT] " to extract
    // the base64-encoded bincode Receipt for submission to the dual-factor gate.
    let receipt_bytes = bincode::serialize(&receipt)
        .context("Failed to serialise receipt")?;
    println!("[RECEIPT] {}", B64.encode(&receipt_bytes));

    // ── Decode the journal (committed public output) ──────────────────────
    let verdict: ThreatVerdict = receipt
        .journal
        .decode()
        .context("Failed to decode ThreatVerdict from journal")?;

    // ── Display the tamper-proof verdict ──────────────────────────────────
    println!("\n[✓] Receipt verified — verdict is cryptographically tamper-proof");
    println!("    Input hash      : {}", hex32(&verdict.input_hash));
    println!("    Threat detected : {}", verdict.is_threat);
    println!(
        "    Category        : {} (code {})",
        verdict.category_name(),
        verdict.category
    );
    println!("    Confidence      : {}%", verdict.confidence_pct);
    println!(
        "    Triggered rules : 0b{:08b}  ({} rule(s) fired)",
        verdict.triggered_rules,
        verdict.triggered_rules.count_ones()
    );

    Ok(())
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn run() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║          OmniWatch — RISC Zero zkVM Threat Verifier             ║");
    println!("║  Sprint 1 · Trust Engine Foundation · STARK-proven detection    ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Guest ELF   : {} bytes", VERIFIER_GUEST_ELF.len());
    println!("  Image ID    : {:08x?}", &VERIFIER_GUEST_ID[..4]);

    let scenarios = build_scenarios();
    let total = scenarios.len();
    let mut passed = 0usize;

    let wall_start = Instant::now();

    for s in &scenarios {
        match prove_scenario(s) {
            Ok(())   => passed += 1,
            Err(e)   => eprintln!("\n[!] SCENARIO FAILED: {}\n    {:?}", s.label, e),
        }
    }

    let wall_total = wall_start.elapsed();

    println!("\n{}", "═".repeat(68));
    println!("  SUMMARY");
    println!("  Scenarios run    : {}", total);
    println!("  Scenarios passed : {}", passed);
    println!("  Total wall time  : {:.3}s", wall_total.as_secs_f64());
    println!(
        "  Avg per scenario : {:.3}s",
        wall_total.as_secs_f64() / total.max(1) as f64
    );
    println!("{}", "═".repeat(68));

    if passed < total {
        std::process::exit(1);
    }
}

// The RISC Zero FRI/STARK prover uses rayon worker threads for parallel
// computation.  On Windows the default thread stack is 1 MiB, which causes
// stack overflows during the recursive FRI folding.  Configure both the rayon
// global pool and the main prover thread with 256 MiB stacks.
//
// USAGE
//   omniwatch-verifier                 — prove all 6 scenarios (prints [RECEIPT] lines)
//   omniwatch-verifier --verify <b64>  — verify a single base64-encoded receipt, print JSON
/// Sprint 4: Prove a single NetworkTelemetry record read from a raw bincode file.
/// Called as:  omniwatch-verifier --prove-file <path_to_bincode_file>
///
/// The Python backend writes bincode bytes received from the Pi 4 edge node to
/// a temp file, then calls this mode to generate the STARK receipt.
fn prove_file_mode(path: &str) -> Result<()> {
    use std::fs;

    let raw = fs::read(path)
        .with_context(|| format!("Failed to read bincode file: {}", path))?;

    // Try deserializing as TelemetryInput (new format with baselines) first;
    // fall back to bare NetworkTelemetry (edge nodes that haven't upgraded yet).
    let (telemetry, baselines, loda) = if let Ok(input) = bincode::deserialize::<TelemetryInput>(&raw) {
        println!("[*] Loaded TelemetryInput (with baselines) from file: {}", path);
        (input.telemetry, input.baselines, input.loda)
    } else {
        let t: NetworkTelemetry = bincode::deserialize(&raw)
            .context("Failed to deserialize NetworkTelemetry or TelemetryInput from bincode file")?;
        println!("[*] Loaded NetworkTelemetry (no baselines) from file: {}", path);
        println!("    [!] Absolute fallback thresholds will be used (Z-score rules inactive)");
        (t, HostBaselines::default(), LodaModel::default())
    };

    println!("    Source   : {}", telemetry.src_ip_str());
    println!("    Target   : {}:{}", telemetry.dst_ip_str(), telemetry.dst_port);
    if telemetry.modbus_func_code > 0 {
        println!("    Modbus FC: {} (unit {})", telemetry.modbus_func_code, telemetry.modbus_unit_id);
    }

    let scenario = Scenario {
        label:    "Edge Bincode Input",
        telemetry,
        baselines,
        loda,
    };
    prove_scenario(&scenario)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // ── Verify mode — lightweight, no large stacks needed ────────────────────
    if args.len() >= 3 && args[1] == "--verify" {
        if let Err(e) = verify_mode(&args[2]) {
            eprintln!("error: {:?}", e);
            std::process::exit(1);
        }
        return;
    }

    // ── Prove-file mode (Sprint 4) — prove a single bincode telemetry file ───
    if args.len() >= 3 && args[1] == "--prove-file" {
        ThreadPoolBuilder::new()
            .stack_size(256 * 1024 * 1024)
            .build_global()
            .expect("failed to configure rayon thread pool");

        let path = args[2].clone();
        let result = std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || prove_file_mode(&path))
            .expect("failed to spawn prover thread")
            .join()
            .expect("prover thread panicked");

        if let Err(e) = result {
            eprintln!("error: {:?}", e);
            std::process::exit(1);
        }
        return;
    }

    // ── Default: prove all built-in scenarios ─────────────────────────────────
    ThreadPoolBuilder::new()
        .stack_size(256 * 1024 * 1024)
        .build_global()
        .expect("failed to configure rayon thread pool");

    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(run)
        .expect("failed to spawn prover thread")
        .join()
        .expect("prover thread panicked");
}
