# OmniWatch Enterprise AI-SOC: Architecture Reference

> **Status:** Production Candidate v2 — "Split-Brain" ML/ZK Edition  
> **Scope:** Authoritative source of truth for the full platform: cyber-physical testbed, ML detection pipeline, Zero-Knowledge verification engine, SOAR orchestration, and React frontend session management.  
> **Audience:** Security engineers, cryptography reviewers, and academic evaluators.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)  
2. [Bounded Threat Model and Central Limitations](#2-bounded-threat-model-and-central-limitations)  
3. [Hardware Partitioning and Physical Simulation](#3-hardware-partitioning-and-physical-simulation)  
4. [System Architecture Overview](#4-system-architecture-overview)  
5. [The Split-Brain Zero-Knowledge Paradigm](#5-the-split-brain-zero-knowledge-paradigm)  
6. [Fixed-Point Arithmetic: Q14 Encoding](#6-fixed-point-arithmetic-q14-encoding)  
7. [Detection Pillar I — DDSketch Volumetric Baselining](#7-detection-pillar-i--ddsketch-volumetric-baselining)  
8. [Detection Pillar II — Isolation Forest Multivariate Anomaly](#8-detection-pillar-ii--isolation-forest-multivariate-anomaly)  
9. [Detection Pillar III — Goertzel C2 Beaconing Detector](#9-detection-pillar-iii--goertzel-c2-beaconing-detector)  
10. [The Dual-Verification SOAR Pipeline](#10-the-dual-verification-soar-pipeline)  
11. [SHA-256 Hash Chain Integrity Layer](#11-sha-256-hash-chain-integrity-layer)  
12. [Enterprise AI-SOC Ingestion Pipeline](#12-enterprise-ai-soc-ingestion-pipeline)  
13. [Frontend Session Management Architecture](#13-frontend-session-management-architecture)  
14. [LLM RAG Contextualization](#14-llm-rag-contextualization)  
15. [Design Technology and HCI](#15-design-technology-and-hci)  
16. [Commercial and Regulatory Alignment](#16-commercial-and-regulatory-alignment)  
17. [Algorithm Evaluation Log](#17-algorithm-evaluation-log)

---

## 1. Executive Summary

OmniWatch is a production-grade Enterprise AI Security Operations Centre (AI-SOC) platform built around a novel **"Split-Brain" architecture**: a stateful Python host performs floating-point machine learning and baseline computation, while a stateless Rust zkVM guest performs purely integer threat evaluation and produces a cryptographically unforgeable STARK proof of that computation.

The platform serves three simultaneous mandates:

1. **Academic benchmark** — quantifying the latency overhead of Zero-Knowledge Virtual Machines at the network edge (RISC Zero STARK generation: 9–17 s; Phi-3-Mini inference: 10–25 tokens/s).

2. **Enterprise AI-SOC** — an end-to-end pipeline ingesting large-scale real-world datasets (CIC-IDS-2017, BOTSv3), processing them through three ML detection pillars, storing all detections in a session-scoped SQLite database with cryptographic chain continuity, and surfacing them in a React dashboard with live query invalidation.

3. **Cyber-physical testbed** — a hardware diorama connecting an ESP32 Modbus server, a Raspberry Pi Zero 2W attacker, a Raspberry Pi 4 passive network sensor, and a command-node workstation, forming a verifiable OT/ICS threat-detection loop with FIDO2-backed human authorization.

The system achieves **Computational Integrity** (honest evaluation of committed data, proven via STARK) but explicitly **lacks hardware-rooted Sensing Integrity** (no TPM 2.0 / Secure Boot on the Pi 4 edge node). This boundary is documented as a first-class architectural constraint in §2.

---

## 2. Bounded Threat Model and Central Limitations

### 2.1 Latency vs. Automation Benchmark

RISC Zero STARK generation (9–17 s) combined with 4-bit Phi-3-Mini CPU inference (10–25 tokens/s) creates a total end-to-end operator triage latency of **15–32 seconds**. A one-time Initial WASM Compilation Penalty (10–20 MB verifier bundle on a cold browser cache) delays initial dashboard readiness.

This validates the project's core research hypothesis: current verifiable computation and local generative AI are too slow for real-time OT mitigation, making **cryptographically signed Human-in-the-Loop authorization** the superior operational control for post-detection governance.

### 2.2 Edge-Node Trust Boundary (Central Limitation)

The trust boundary terminates at the Raspberry Pi 4 edge node. The system lacks TPM 2.0 remote attestation and Secure Boot. The Pi 4 serializes JSON telemetry into bincode *before* zkVM evaluation, making the Pi 4 OS the primary attack vector for pre-proof data manipulation. The architecture achieves strict **Computational Integrity** over supplied data, but not **Sensing Integrity** of physical reality.

### 2.3 Static Invariant Recompilation

Deterministic threat rules are hardcoded into the Rust Guest ELF. Adding new rules requires a full recompile and reprovisioning of the zkVM guest image ID (`VERIFIER_GUEST_ID`). This is an accepted v1 trade-off: absolute state immutability over hot-reloading.

### 2.4 Cryptographic Transparency (No SNARK Wrapping)

The pipeline pins `receipt_type` to succinct STARK receipts, rejecting optional Groth16 SNARK wrappers. Raw STARK proofs are ~217–250 KB — negligible on a local high-speed network, but this choice preserves a trusted-setup-free cryptographic environment. The exact `risc0-zkvm` crate version is strictly pinned.

### 2.5 Physical Layer Fidelity

The ESP32 operates Modbus TCP over Wi-Fi. NCA OTCC-1:2022 mandates strict restriction of wireless technologies in production OT/ICS. This setup is a **pedagogical simulation** only. A latency comparison baseline quantifies the deviation between RS-485 (≤ 1 ms cycle time) and ESP32 Wi-Fi (~10–50 ms variable).

### 2.6 SQLite Concurrency Model

All persistent state is stored in a single SQLite file (`omniwatch.db`) with `PRAGMA journal_mode=WAL`. Concurrent pipeline sessions use a lock-retry decorator. Spent-receipt deduplication uses an atomic `INSERT OR IGNORE` pattern to prevent TOCTOU races without blocking the Python GIL.

---

## 3. Hardware Partitioning and Physical Simulation

The infrastructure uses strict physical service isolation to prevent computational bottlenecks.

| Node | Hardware | Role |
|---|---|---|
| **OT Target (Victim)** | ESP32 Type-C Wi-Fi/BT | Modbus TCP server simulating SCADA; drives 5 V pumps and LED status indicators |
| **Attacker Simulation (Red Team)** | Raspberry Pi Zero 2W + TP-Link TL-WN722N | Executes unauthorized Modbus FC 05 (coil write) and FC 16 (register block write) payloads |
| **Network Sensor (Blue Team)** | Raspberry Pi 4 Model B, 128 GB SanDisk Ultra | Passive TAP listener running Zeek + CISA ICSNPP Modbus package; serializes captured flows to bincode and relays to command node |
| **Command Node** | Local workstation | RISC Zero STARK proof generation (Rust host), React/WASM verification, Three.js UI, FastAPI auth backend, Ollama LLM |

### 3.1 Bincode Wire Format

The Pi 4 serializes each captured Modbus flow into a `TelemetryInput` struct encoded in bincode (little-endian, no padding). This eliminates JSON parsing overhead inside the zkVM, reducing proof-generation cycle counts. Field order is part of the wire contract; reordering requires a crate version bump.

```
TelemetryInput {
    telemetry: NetworkTelemetry,   // 61-byte base struct
    baselines: HostBaselines,      // per-host ML baselines
    forest:    IsolationForestModel // flattened IF trees
}
```

All floating-point values in `NetworkTelemetry` are pre-multiplied by 1 000 and stored as `u64` (`flow_bytes_s_milli` = actual B/s × 1 000) to guarantee bit-identical results across every RISC-V platform and eliminate hardware FPU dependence.

### 3.2 Live Demonstration Fallback

To mitigate 2.4 GHz Wi-Fi spectrum saturation at exhibition venues, the pipeline includes a **Deterministic Replay Fallback** mode accepting pre-recorded PCAP captures. Truncating the SQLite Spent-Receipt Registry for PCAP replays is defined as an out-of-band CLI-only operation on the command node OS — an accepted procedural bypass explicitly scoped to pedagogical contexts.

### 3.3 WebAuthn Local Domain Exemption

WebAuthn's Relying Party ID (RPID) requires a registerable domain. The command node uses a local DNS mapping (`omniwatch.local → 127.0.0.1` via `/etc/hosts`). TLS is provided by `mkcert`. Both the local reverse-proxy certificate and the FastAPI FIDO2 configuration are explicitly bound to `omniwatch.local`.

---

## 4. System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       DATA INGESTION LAYER                              │
│  CIC-IDS-2017 CSV  ───┐                                                 │
│  BOTSv3 CSV        ───┼──► FastAPI /upload-telemetry                   │
│  Pi 4 bincode      ───┘         │                                       │
└─────────────────────────────────┼───────────────────────────────────────┘
                                  │ session_id (UUID)
┌─────────────────────────────────▼───────────────────────────────────────┐
│                    PYTHON HOST — Analysis Engine                         │
│  normalize_chunk()   ←──── deduplicate headers, coerce types            │
│  DDSketchBaseliner   ←──── accumulate p99 per-session                   │
│  ForestBaseliner     ←──── online IsolationForest fit (max 200K rows)   │
│  zscore_baseline_filter() ←── flag statistical outliers                 │
│  SHA-256 Hash Chain  ←──── per-alert + per-batch + chain-tip hashes     │
│              │                                                           │
│              ▼ TelemetryInput (bincode)                                 │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────────────┐
│              RUST HOST PROVER  (verifier/host/src/main.rs)              │
│  rayon threadpool (256 MiB stacks, Windows stack overflow mitigation)   │
│  default_prover()  ──► RISC Zero zkVM (RV32IM, ~96-bit security)        │
│              │                                                           │
│              ▼ STARK Receipt (~217–250 KB, bincode→base64)              │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────────────┐
│              RUST GUEST zkVM  (verifier/methods/guest/src/main.rs)      │
│  Pure-integer RV32IM — zero f32/f64                                     │
│  Rule evaluation: 11 rules, 13 bit-flags in ThreatVerdict               │
│  Commits to journal: input_hash | is_threat | category | confidence_pct │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────────────┐
│              FASTAPI BACKEND  (backend/api/routes.py)                   │
│  /verify-remediation: asyncio.create_subprocess_exec → Rust verify_mode │
│  Spent-receipt registry (INSERT OR IGNORE, WAL mode)                    │
│  FIDO2 assertion validation (ECDSA P-256, ASN.1 DER conversion)         │
│  Dual-gate: STARK ∧ ECDSA required before SOAR remediation              │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────────────┐
│              REACT FRONTEND  (frontend/src/)                             │
│  TanStack Query — session-keyed cache invalidation                      │
│  Active session badge (activeSessionId / activeFileName state)           │
│  LogExplorer — data source switch: pipeline_alerts vs. cicids_events    │
│  Three.js DAG — cryptographic trust-chain visualization                  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 5. The Split-Brain Zero-Knowledge Paradigm

The central architectural invariant is a **hard execution boundary** between the Python host and the Rust zkVM guest:

| Dimension | Python Host | Rust Guest (zkVM) |
|---|---|---|
| **State** | Stateful — accumulates baselines across chunks | Stateless — evaluated independently per record |
| **Arithmetic** | Unrestricted floating-point (numpy, sklearn) | Pure integer — RV32IM has no hardware FPU |
| **Outputs** | ML parameters: `p99`, `mean`, `stddev`, `forest_nodes` | `ThreatVerdict` committed to STARK journal |
| **Trust** | Trusted execution (operator-controlled machine) | Cryptographic — STARK proof guarantees honest evaluation |
| **Encoding** | Python float64 | Q14 fixed-point (see §6) transmitted via bincode |

This split is non-negotiable: the RISC Zero zkVM implements the RV32IM ISA, which explicitly omits the F/D floating-point extensions. Any `f32` or `f64` instruction causes an illegal-instruction trap inside the guest. The Python host therefore computes all ML decisions in floating-point, encodes the results into integer fixed-point, and hands the integer representation to the Rust guest for verifiable re-evaluation.

### 5.1 Information Flow Through the Boundary

```
Python (float64)                     Rust Guest (i32/u64 integers only)
─────────────────                    ─────────────────────────────────
DDSketch.p99_bytes_s   ──fp14────►   ddsketch_threshold_fp14  (u64)
IsolationForest nodes  ──fp14────►   nodes[i*4+1]: threshold_fp14 (i32)
mean_bytes_s (float)   ──×1000───►   mean_bytes_s_milli (u64)
stddev_bytes_s (float) ──×1000───►   stddev_bytes_s_milli (u64)
```

The encoding rule for the ×1000 path (Z-score baselines) is:

```
encoded = floor(actual_float × 1000)
```

The encoding rule for the fp14 path (DDSketch and Isolation Forest) is defined in §6.

---

## 6. Fixed-Point Arithmetic: Q14 Encoding

### 6.1 Definition

The platform uses **Q14 fixed-point** throughout the STARK pipeline. A real value `x` is represented as a signed 32-bit (or unsigned 64-bit) integer:

```
Z = floor(x × 2^14)  =  floor(x × 16384)
```

This gives 14 bits of fractional precision. The representable range in `i32` is approximately ±131 072.0; in `u64`, approximately 0 to 1.13 × 10^15.

### 6.2 Arithmetic Rules in the Guest

**Addition / subtraction** — no correction needed; the scale factor cancels:

```
Z_a + Z_b  represents  (a + b)
```

**Multiplication** — the product must be right-shifted by 14 with rounding:

```
Z_product = (Z_a × Z_b + 2^13) >> 14
```

The `+ 2^13` term implements round-half-up, matching Python's `floor()` convention to within ±1 ULP.

**Comparison** — comparisons in Q14 space are identical to comparisons in real space. The guest evaluates:

```rust
// Python host computes: T = floor(p99_bytes_s × 2^14)
// Guest computes:        current_scaled = bytes_per_sec * 16_384
// Comparison (no division needed):
if current_scaled > baselines.ddsketch_threshold_fp14 { /* volumetric alert */ }
```

### 6.3 Q14 Encoding Examples from the Codebase

| Real value | Encoded form | Field |
|---|---|---|
| 200 KB/s p99 threshold | `floor(200 000 × 16 384) = 3 276 800 000` | `ddsketch_threshold_fp14` |
| Isolation Forest node threshold (e.g. 12.7) | `floor(12.7 × 16 384) = 208 076` | `nodes[i*4+1]` |
| Average path length 5.3 trees deep | `5.3 × 16 384 = 86 835` | `avg_path_fp14` |

### 6.4 Saturating Arithmetic

All Q14 multiplications in the guest use Rust's `saturating_mul` to prevent integer overflow from causing incorrect threat verdicts. Overflow is treated as a maximum-confidence threat signal rather than a silent wraparound.

---

## 7. Detection Pillar I — DDSketch Volumetric Baselining

### 7.1 Algorithm

DDSketch is a mergeable, memory-bounded quantile sketch with **guaranteed relative error** α on any quantile estimate. The sketch partitions the value domain into logarithmic buckets:

**Gamma factor:**

```
γ = (1 + α) / (1 − α)
```

For α = 1% (the platform default):

```
γ = 1.01 / 0.99 ≈ 1.0204
```

**Bucket index** for an observed value `x > 0`:

```
i = ceil( log(x) / log(γ) )  =  ceil( log_γ(x) )
```

The sketch stores only the count per bucket index, giving O(log(max/min) / log(γ)) total buckets regardless of the number of observations.

**p99 estimate:** The sketch returns the upper edge of the bucket containing the 99th percentile. For bucket index `i`, the upper edge is `γ^i`.

### 7.2 Python Host — `DDSketchBaseliner`

```python
class DDSketchBaseliner:
    ALPHA = 0.01
    GAMMA = (1 + ALPHA) / (1 - ALPHA)   # ≈ 1.0204

    def add(self, bytes_s: float):
        if bytes_s > 0:
            i = math.ceil(math.log(bytes_s) / math.log(self.GAMMA))
            self._buckets[i] = self._buckets.get(i, 0) + 1
            self._count += 1

    def threshold_fp14(self) -> int:
        """Returns T = floor(p99_bytes_s × 2^14) for the Rust guest."""
        p99 = self._p99()
        return int(math.floor(p99 * 16_384))
```

The `threshold_fp14()` output is placed directly into `HostBaselines.ddsketch_threshold_fp14` before bincode serialization.

### 7.3 Rust Guest — Rule `DDSKETCH_VOLUME` (bit 11)

```rust
// bytes_per_sec = flow_bytes_s_milli / 1000  (integer division)
let current_scaled = bytes_per_sec.saturating_mul(16_384);  // Q14

if baselines.ddsketch_threshold_fp14 > 0
    && current_scaled > baselines.ddsketch_threshold_fp14
{
    triggered |= rules::DDSKETCH_VOLUME;
    // DDSKETCH_VOLUME takes priority over ZSCORE_ANOMALY for byte-rate
}
```

The Q14 multiplication `bytes_per_sec × 16384` is exact because `bytes_per_sec` is already an integer (no fractional component is lost). The comparison with `ddsketch_threshold_fp14` is therefore a pure integer comparison.

### 7.4 Error Bound

The p99 estimate has multiplicative relative error ≤ α = 1%. For a true p99 of 200 KB/s, the threshold is in the interval [198 KB/s, 202 KB/s]. This is acceptable for volumetric anomaly detection — byte-rate outliers are typically 5–50× the baseline, far exceeding the 1% error margin.

---

## 8. Detection Pillar II — Isolation Forest Multivariate Anomaly

### 8.1 Algorithm

Isolation Forest detects anomalies by isolating observations in a random ensemble of binary trees. Anomalous points — those with unusual combinations of features — are isolated closer to the root, yielding a shorter average path length.

**Anomaly score** for a point `x` with `n` training samples:

```
s(x, n) = 2^( −E[l(x)] / c(n) )
```

Where:
- `E[l(x)]` — expected path length across all trees
- `c(n) = 2 H(n−1) − (2(n−1)/n)` — expected path length for an unsuccessful BST search; `H(k) = ln(k) + 0.5772...` (Euler–Mascheroni constant)

An anomaly score `s → 1` indicates a high-confidence anomaly; `s → 0.5` indicates a normal point.

### 8.2 zkVM Serialization — Stride-4 Array

sklearn's `IsolationForest` cannot be used directly in the Rust guest. The Python `ForestBaseliner` extracts the trained forest into a **stride-4 flattened integer array** compatible with the no-alloc, deterministic zkVM environment:

```
nodes[i*4 + 0] = feature_index      (0–3 for internal; −1 for leaf)
nodes[i*4 + 1] = threshold_fp14     = floor(sklearn_threshold × 2^14)
nodes[i*4 + 2] = left_child         (global node index; −1 for leaf)
nodes[i*4 + 3] = right_child        (global node index; −1 for leaf)
```

Feature mapping (Python → guest index):

| Index | Feature | Scale |
|---|---|---|
| 0 | `bytes_out` (bytes/s) | raw |
| 1 | `flow_duration` (ms) | raw |
| 2 | `packets` (count) | raw |
| 3 | `dest_port` | raw |

### 8.3 Python Host — `ForestBaseliner`

```python
class ForestBaseliner:
    MAX_FIT_ROWS = 200_000  # memory cap for training

    def accumulate(self, df: pd.DataFrame):
        self._buffer.append(df[FOREST_FEATURES].dropna())

    def fit(self):
        data = pd.concat(self._buffer).head(self.MAX_FIT_ROWS)
        self._forest = IsolationForest(n_estimators=100, contamination=0.05)
        self._forest.fit(data)

    def payload(self) -> dict:
        """Serialize to stride-4 integer format for Rust guest."""
        nodes, roots = [], []
        for estimator in self._forest.estimators_:
            root_global = len(nodes) // 4
            roots.append(root_global)
            self._flatten_tree(estimator.tree_, nodes)
        return {
            "nodes": nodes,
            "tree_roots": roots,
            "path_length_threshold": int(
                self._path_threshold() * 16_384  # Q14 encode
            ),
        }
```

### 8.4 Rust Guest — `traverse_tree` and `traverse_forest`

```rust
fn traverse_tree(nodes: &[i32], root: i32, features: &[i32; 4]) -> i32 {
    let mut node = root as usize;
    let mut depth = 0;
    loop {
        let fi  = nodes[node * 4];
        let thr = nodes[node * 4 + 1];  // Q14
        let lc  = nodes[node * 4 + 2];
        let rc  = nodes[node * 4 + 3];
        if fi < 0 { break; }            // leaf
        // Feature values are raw integers; threshold is Q14.
        // Multiply feature by 2^14 before comparing to threshold_fp14.
        let fval_fp14 = (features[fi as usize] as i32).saturating_mul(16_384);
        node = if fval_fp14 <= thr { lc as usize } else { rc as usize };
        depth += 1;
    }
    depth
}

fn traverse_forest(forest: &IsolationForestModel, features: &[i32; 4]) -> i32 {
    if forest.tree_roots.is_empty() { return i32::MAX; }
    let n = forest.tree_roots.len() as i32;
    let sum_depth: i32 = forest.tree_roots.iter()
        .map(|&r| traverse_tree(&forest.nodes, r, features))
        .sum();
    // avg_path_fp14 = (sum_depth × 2^14) / n_trees
    sum_depth.saturating_mul(16_384) / n
}
```

### 8.5 Rule Evaluation — `ISOLATION_FOREST_ANOMALY` (bit 12)

```rust
let avg_path_fp14 = traverse_forest(&input.forest, &features);
if avg_path_fp14 < input.forest.path_length_threshold {
    triggered |= rules::ISOLATION_FOREST_ANOMALY;
}
```

A short average path (anomalous isolation) is `avg_path_fp14 < threshold`. The threshold encodes the boundary separating normal from anomalous path-length distributions, derived from the training data's score distribution.

---

## 9. Detection Pillar III — Goertzel C2 Beaconing Detector

### 9.1 Algorithm

The Goertzel algorithm is a **second-order IIR filter** optimized to compute a single DFT bin without computing the full FFT. This is exploited to detect Command-and-Control (C2) beaconing: periodic connection attempts at a fixed interval frequency `f_target`.

**Target bin:**

```
k = round( N × f_target / f_s )
```

Where `N` = number of samples in the analysis window, `f_s` = sampling rate (observations per second).

**Goertzel IIR recurrence:**

```
q₀[n] = 2·cos(2πk/N)·q₁[n−1] − q₂[n−1] + x[n]
q₂[n] = q₁[n−1]
q₁[n] = q₀[n]
```

**Power at target frequency** (evaluated once after all N samples):

```
P = q₁² − q₁·q₂·2·cos(2πk/N) + q₂²
```

### 9.2 Integer Implementation in Rust Guest

The cosine term `2·cos(2πk/N)` is pre-computed by the Python host as a Q14 integer coefficient:

```
c_int = floor( 2·cos(2πk/N) × 2^14 )
```

The Rust guest runs the IIR with pure integer operations:

```rust
let mut q1: i64 = 0;
let mut q2: i64 = 0;
for &x in samples.iter() {
    let q0 = ((c_int as i64 * q1) >> 14) - q2 + x as i64;
    q2 = q1;
    q1 = q0;
}
// Power (no division by 2^28 needed — comparison to threshold handles scale)
let power = q1 * q1 - ((c_int as i64 * q1 * q2) >> 14) + q2 * q2;
```

The `>> 14` right-shift in the feedback path renormalizes the Q14 product back to the original scale, preventing exponential growth of the accumulator. The final power value remains in Q28 space (two Q14 multiplications), which is compared against a Q28-encoded threshold without further scaling.

### 9.3 Beaconing Detection Heuristic

C2 beaconing is characterized by a dominant periodic component in the inter-arrival time series. The Goertzel detector flags a flow if:

- `power > beacon_power_threshold` (energy at target frequency exceeds background noise)
- `flow_duration > min_beacon_window` (sufficient observations for reliable frequency estimation)
- The source IP has made repeated connections in the observation window

This is a **heuristic rule** — not a statistically optimal detector. The false-positive rate depends on the calibration of `beacon_power_threshold`, which is set conservatively in v1.

---

## 10. The Dual-Verification SOAR Pipeline

SOAR (Security Orchestration, Automation and Response) remediation is protected by a **dual-factor cryptographic gate**: both a machine-generated STARK proof and a human-generated ECDSA signature must be presented and validated before any network-level action is taken.

### 10.1 Phase 1 — Edge Serialization (Pi 4 → Command Node)

Zeek captures Modbus TCP metadata via the CISA ICSNPP package. The Pi 4 constructs a `TelemetryInput` struct — bundling `NetworkTelemetry`, `HostBaselines`, and `IsolationForestModel` — and serializes it to bincode. The command node receives the payload over a local TCP connection.

### 10.2 Phase 2 — STARK Proof Generation (Rust Host)

```rust
// verifier/host/src/main.rs
let input: TelemetryInput = /* deserialize from Pi 4 */;
let env = ExecutorEnv::builder()
    .write(&input).unwrap()
    .build().unwrap();
let receipt = default_prover()
    .prove(env, VERIFIER_GUEST_ELF)
    .unwrap()
    .receipt;
```

The Rayon thread pool is configured with 256 MiB per-thread stacks to mitigate Windows stack overflow during FRI polynomial commitment generation. The prover emits a `[RECEIPT] <base64>` line to stdout for Python extraction.

### 10.3 Phase 3 — Rust Guest Evaluation (zkVM Interior)

The guest runs on the RV32IM ISA — integer-only. Its evaluation proceeds as:

1. `let input: TelemetryInput = env::read();`
2. Compute `input_hash = sha2::Sha256(bincode::serialize(&input))`.
3. Evaluate all 11 threat rules (§10.4) against `input.telemetry` and `input.baselines`.
4. Commit `ThreatVerdict { input_hash, is_threat, category, confidence_pct, triggered_rules }` to the STARK journal.

Step 2 ensures the STARK proof commits to the exact input that was evaluated. A verifier can replay the hash to confirm no data was substituted.

### 10.4 Threat Rule Table

| Bit | Flag | Condition |
|---|---|---|
| 0 | `HIGH_RATE` | bytes/s > 1 MB (absolute fallback; no baseline required) |
| 1 | `KNOWN_TARGET_PORT` | dst_port ∈ {21, 22, 23, 80, 443, 445, 3389, 8080} |
| 2 | `BRUTE_FORCE` | port ∈ {21, 22} ∧ packet_count > threshold |
| 3 | `RAPID_PROBE` | duration < 100 ms ∧ packets ≤ 2 |
| 4 | `DNS_AMPLIFICATION` | port 53 ∧ UDP ∧ bytes/s > 100 KB |
| 5 | `EXFIL_PATTERN` | outbound ∧ bytes/s > 500 KB ∧ duration > 5 s |
| 6 | `RDP_BRUTE` | port 3389 ∧ packet_count > threshold |
| 7 | `CONFIDENCE_CAPPED` | sourcetype ∈ {0=simulated, 5=sparse} → cap at 50% |
| 8 | `MODBUS_WRITE` | modbus_func_code ∈ {5, 6, 15, 16} |
| 9 | `MODBUS_INVALID` | modbus_func_code ∉ standard valid range |
| 10 | `ZSCORE_ANOMALY` | \|Z\| > 3.0 on bytes/s or packet count (§10.4.1) |
| 11 | `DDSKETCH_VOLUME` | current_scaled > ddsketch_threshold_fp14 (§7.3) |
| 12 | `ISOLATION_FOREST_ANOMALY` | avg_path_fp14 < path_length_threshold (§8.5) |

#### 10.4.1 Z-Score Rule (integer, guest-side)

```rust
fn zscore_scaled(value: u64, mean: u64, stddev: u64) -> u64 {
    // All values are ×1000 (milli-scale), so units cancel.
    // Returns |Z| × 1000 to maintain integer precision.
    if stddev == 0 { return 0; }
    let diff = if value > mean { value - mean } else { mean - value };
    diff * 1000 / stddev  // ×1000 for 3 decimal places
}

let z_bytes = zscore_scaled(
    telemetry.flow_bytes_s_milli,
    baselines.mean_bytes_s_milli,
    baselines.stddev_bytes_s_milli,
);
// 3.0 × 1000 = 3000
if z_bytes > 3_000 || z_pkts > 3_000 {
    triggered |= rules::ZSCORE_ANOMALY;
}
```

### 10.5 Phase 4 — Python Backend Verification

The FastAPI backend invokes the Rust binary in verify mode:

```python
proc = await asyncio.create_subprocess_exec(
    "omniwatch-verifier", "--verify", receipt_b64,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
)
stdout, _ = await proc.communicate()
verdict = json.loads(stdout)  # ThreatVerdict as JSON
```

The Python backend:
1. Deserializes the `ThreatVerdict` from the STARK journal.
2. Checks the `input_hash` against the Spent-Receipt Registry (`INSERT OR IGNORE`).
3. Validates the FIDO2 assertion — `ECDSA-P256` over `SHA256(input_hash || nonce)`.
4. Converts browser-native IEEE P1363 signatures to ASN.1 DER before verification.
5. Only if both gates pass: executes remediation (firewall update, iptables rule).

### 10.6 Phase 5 — FIDO2 Human Authorization

```
Analyst reviews alert in React UI
          │
          ▼
/auth/sign/begin  →  FastAPI generates WebAuthn challenge (nonce)
          │
          ▼
navigator.credentials.get()  →  ECDSA P-256 signature (YubiKey / OS Secure Enclave)
          │
          ▼
/verify-remediation  →  { stark_receipt_b64, assertion_response, session_id }
          │
          ▼
FastAPI dual-validates:  STARK ∧ ECDSA  →  remediation authorized
```

The `mock_fido2=true` flag in development mode bypasses the hardware authenticator for local testing while preserving the full verification code path.

---

## 11. SHA-256 Hash Chain Integrity Layer

The hash chain (`backend/services/trust_chain.py`) provides append-only tamper evidence over the `telemetry_alerts` table, independent of the STARK pipeline.

### 11.1 Per-Alert Hash

For each alert row, a canonical identity hash is computed:

```python
identity = {
    "session_id": row["session_id"],
    "src_ip":     row["src_ip"],
    "dst_ip":     row["dst_ip"],
    "dst_port":   row["dst_port"],
    "protocol":   row["protocol"],
    "label":      row["label"],
    "severity":   row["severity"],
    "ingested_at": row["ingested_at"],
}
alert_hash = SHA256( JSON(identity, sort_keys=True) )
```

JSON with `sort_keys=True` ensures the canonical form is independent of Python dict insertion order.

### 11.2 Batch Hash

All alert hashes in a processing chunk are concatenated and hashed:

```python
batch_hash = SHA256( alert_hash_0 ‖ alert_hash_1 ‖ … ‖ alert_hash_n )
```

### 11.3 Chain Tip

The new chain tip extends the previous tip:

```python
chain_tip = SHA256( prev_tip ‖ batch_hash )
```

The genesis tip is `SHA256(b"omniwatch-genesis")`. Chain tips are stored in the `hash_chain_receipts` table with `batch_id`, `prev_hash`, `batch_hash`, `chain_tip`, and `row_count`.

### 11.4 Chain Verification

`verify_chain()` re-derives every chain tip from the stored alert rows and compares against the stored receipts. Any discrepancy indicates database tampering. This function runs on demand (CISO export, audit request) and does not block the ingestion pipeline.

### 11.5 Relationship to STARK Proofs

The SHA-256 chain and the STARK pipeline are **complementary but independent** integrity mechanisms:

| Layer | Protects | Verifiable by |
|---|---|---|
| SHA-256 hash chain | Database row completeness and ordering | Any party with database access |
| STARK proof | Correctness of threat-rule evaluation on committed input | Any party with the guest ELF image ID |
| FIDO2 ECDSA | Human operator identity and intent at decision time | WebAuthn relying party |

Together they form a **three-layer audit trail**: the analyst's signature ties a human identity to a machine verdict that was proven to have been computed honestly over input whose hash is anchored in the append-only chain.

---

## 12. Enterprise AI-SOC Ingestion Pipeline

### 12.1 Supported Datasets

| Dataset | Format | Volume | Source Type |
|---|---|---|---|
| CIC-IDS-2017 | CSV (~900 MB per day file) | ~690 K rows/session | Network intrusion benchmark |
| BOTSv3 (Splunk BOTS) | CSV | ~120 K rows/session | Enterprise SOC competition |
| Pi 4 live Zeek | bincode over TCP | Real-time | Cyber-physical testbed |

### 12.2 Chunked Processing

All CSV datasets are processed in configurable chunks (default: 65 536 rows) to bound peak memory. Per chunk:

1. **`normalize_chunk(df)`** — deduplicates column headers (`df.loc[:, ~df.columns.duplicated(keep="first")]`), coerces types, drops empty rows.
2. **`_col1(df, col)`** — defensively extracts a single Series from any column reference, guarding against 2D DataFrame returns caused by duplicate headers surviving earlier stages.
3. **Z-score filter** — `zscore_baseline_filter(df)` flags rows where |Z| > 3 on bytes/s or packet count.
4. **Isolation Forest** — `ForestBaseliner.accumulate(df)` adds the chunk to the training buffer.
5. **DDSketch** — `DDSketchBaseliner.add(value)` for each flow's bytes/s.

After all chunks: `ForestBaseliner.fit()` trains the ensemble, `DDSketchBaseliner.threshold_fp14()` computes the STARK-compatible threshold.

### 12.3 Session Architecture

Every upload generates a UUID `session_id`. All `telemetry_alerts` rows carry this `session_id`, enabling:

- **Isolated queries** — `SELECT … WHERE session_id = ?` scopes all stats and log views to the active dataset without interfering with historical sessions.
- **Concurrent uploads** — multiple sessions can coexist in the database; the UI displays only the active session until the user switches.
- **Schema migrations** — `ensure_pipeline_tables()` applies `ALTER TABLE … ADD COLUMN` migrations idempotently, checking for "duplicate column" errors to handle existing databases from before the ML upgrade.

### 12.4 `telemetry_alerts` Schema

```sql
CREATE TABLE IF NOT EXISTS telemetry_alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT,
    ingested_at TEXT,
    src_ip      TEXT,
    dst_ip      TEXT,
    dst_port    INTEGER,
    protocol    TEXT,
    label       TEXT,
    severity    TEXT,
    category    TEXT,
    mitre_id    TEXT,
    mitre_name  TEXT,
    confidence  REAL,
    bytes_total REAL,        -- added by migration
    z_score_bytes REAL,      -- added by migration
    z_score_pkts  REAL,      -- added by migration
    raw_features  TEXT,      -- added by migration (JSON)
    chain_hash    TEXT,      -- added by migration
    dataset_type  TEXT,
    source_file   TEXT
);
```

Migrations use the pattern:

```python
for stmt in ALTER_STATEMENTS:
    try:
        conn.execute(stmt)
    except sqlite3.OperationalError as exc:
        if "duplicate column" not in str(exc).lower():
            raise  # re-raise unexpected errors
```

---

## 13. Frontend Session Management Architecture

### 13.1 Global Session State

Active session identity is held in `App.tsx` root state, propagated to child components as props and React Query keys:

```typescript
const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
const [activeFileName,  setActiveFileName]  = useState<string | null>(null);
```

### 13.2 Session-Scoped React Query Cache

TanStack Query (v5) is used for all API calls. The query key includes `activeSessionId`, so the cache is automatically invalidated and re-fetched when a new upload completes:

```typescript
// App.tsx
const { data: cicidsStats } = useQuery<CicidsStats>({
  queryKey:        ["cicids-stats", activeSessionId],
  queryFn:         () => api.getCicidsStats(activeSessionId),
  refetchInterval: 60_000,
});

// On upload completion:
onComplete={(result) => {
  setActiveSessionId(result.session_id);
  setActiveFileName(result.filename);
  qc.invalidateQueries({ queryKey: ["cicids-stats", result.session_id] });
}}
```

### 13.3 Data Source Switching in LogExplorer

`LogExplorer` receives `sessionId` as a prop and selects its data source accordingly:

```typescript
queryFn: () => {
  if (sessionId) {
    // New pipeline path: query telemetry_alerts with session scope
    return api.getPipelineAlerts({ session_id: sessionId, … })
               .then(rows => rows.map(pipelineAlertToLog));
  }
  if (legacyDataset === "botsv3") {
    return api.getBotsv3Logs({ … });
  }
  return api.getCicidsLogs({ … });
}
```

The `pipelineAlertToLog` mapper normalizes `PipelineAlert` (from `telemetry_alerts`) into the `CicidsLog` shape expected by the table renderer, avoiding a separate component implementation for the new data source.

### 13.4 Active Dataset Badge

A visual badge in the navigation header indicates which session is active:

```tsx
{activeFileName && (
  <div style={{ border: "1px solid rgba(78,154,241,0.25)" }}>
    <span className="animate-pulse" style={{ background: "#4e9af1" }} />
    <span>Active Dataset: {activeFileName}</span>
  </div>
)}
```

The pulsing indicator communicates live-data status without requiring a separate notification system.

### 13.5 Backend Session Filtering

`GET /api/cicids/stats?session_id=<uuid>` branches to a session-scoped SQLite query:

```python
SELECT COUNT(*) FROM telemetry_alerts WHERE session_id = ?
SELECT label, COUNT(*) FROM telemetry_alerts WHERE session_id = ? GROUP BY label
SELECT severity, COUNT(*) FROM telemetry_alerts WHERE session_id = ? GROUP BY severity
```

This preserves full backward compatibility — callers omitting `session_id` receive the legacy `get_cicids_stats()` response from the `cicids_events` table.

---

## 14. LLM RAG Contextualization

The platform's LLM component operates strictly as a **translation and contextualization engine** — it has zero normative weight in the threat detection verdict.

### 14.1 Two-Tier Evaluation

**Scoreboard 1 (Proof-System Metrics):**
- STARK generation latency (wall-clock, `std::time::Instant`)
- Total zkVM cycle count
- Peak RAM during FRI polynomial commitments
- STARK proof size (KB)
- Phi-3 RAG token-streaming latency (tokens/s)
- WASM bundle size and Time to Interactive (TTI) penalty on cold cache

**Scoreboard 2 (LLM RAG Contextualization):**
- Retrieval precision at the calibrated confidence threshold
- Adversarial RAG query resistance (prompt injection attempts)
- "No Grounding Available" UI state activation rate
- Operator comprehension score (exhibition/user study metric)

### 14.2 Embedding Precision Constraint

The generation model (Phi-3-Mini) uses INT4 quantization for memory efficiency. However, the **embedding model must be locked to FP32 or FP16** to maintain mathematically stable cosine similarity calculations. Mixed-precision retrieval (INT4 embeddings) degrades cosine similarity accuracy due to quantization noise accumulating in high-dimensional dot products, reducing retrieval precision below the calibrated threshold.

### 14.3 Source Grounding Enforcement

The UI enforces strict visible source grounding: the exact document excerpt is displayed alongside the LLM summary. If retrieval confidence falls below the calibrated threshold, the UI enters a hard "No Grounding Available" state and suppresses the LLM output entirely. This prevents the operator from acting on hallucinated industrial context.

---

## 15. Design Technology and HCI

### 15.1 Asynchronous WASM Verification

The WebAssembly module (`risc0-zkvm`) is instantiated in a dedicated background Web Worker. This serves as a UX optimization: client-side verification updates the visual state asynchronously without blocking the main thread. The authoritative verification is always the server-side Python → Rust invocation in §10.5.

### 15.2 Spatial WebGL Trust Chain DAG

The verification state is visualized in Three.js as a 3D Directed Acyclic Graph (DAG) mapping the cryptographic trust chain:

```
Raw Telemetry → SHA-256 input_hash → STARK Receipt → FIDO2 ECDSA → Remediation
```

Each node solidifies from a pending grey state to a verified green state as each phase completes. Upon full dual-validation the DAG emits a particle effect signaling readiness for remediation authorization.

### 15.3 Graceful Degradation

If the WebGL context fails to initialize (common on remote desktops or GPU-less VMs), the React architecture degrades to a dense 2D CSS-grid matrix view preserving full alert functionality without any WebGL dependency.

### 15.4 Ecological Interface Design

The interface follows Ecological Interface Design (EID) principles: information is encoded in the structure of the display, not in color alone. Severity levels use both color (red/amber/green) and iconographic shape (circle/triangle/square) to remain accessible under deuteranopia simulation.

---

## 16. Commercial and Regulatory Alignment

### 16.1 NCA OTCC-1:2022 Alignment

Due to the 15–32 second total end-to-end operator latency, the system is explicitly designed for **post-detection governance**, manual remediation approvals, and audit-trail generation, rather than real-time protective response or inline IPS. This positions the platform within the monitoring, event collection, and audit-trail integrity objectives of NCA OTCC-1:2022 Subdomain 2-11 (Cybersecurity Event Logs and Monitoring Management).

### 16.2 Human-in-the-Loop as a Control

By requiring a FIDO2-backed operator ECDSA signature before any remediation is authorized, the system addresses the operational safety requirements for critical water utility infrastructure and Vision 2030 smart city deployments. The STARK proof provides the machine half; the FIDO2 assertion provides the human half. Neither alone is sufficient.

### 16.3 Proof Size and Transmission

Raw STARK receipts (~217–250 KB) are transmitted as base64 strings in the HTTP request body. At gigabit LAN speeds (local command node) this is a ~2 ms overhead. For production deployment over a WAN, the architecture documents that SNARK wrapping (Groth16, ~256 bytes) would reduce proof size by three orders of magnitude at the cost of a one-time trusted setup ceremony.

---

## 17. Algorithm Evaluation Log

This section documents algorithms that were evaluated but not included in v1, preserving the rationale for future reference.

### 17.1 Mahalanobis Distance (Rejected)

**Rationale for evaluation:** Mahalanobis distance accounts for feature correlations and normalizes by the covariance matrix, making it theoretically superior to independent Z-scores for multivariate anomaly detection.

**Rejection reason:** Computing the covariance matrix inverse `Σ⁻¹` requires floating-point matrix operations (numpy `linalg.inv`). Translating this to a Q14 integer matrix inverse in the zkVM guest requires fixed-point matrix inversion algorithms (e.g., Gauss-Jordan with Q14 pivots), which are numerically unstable for near-singular covariance matrices arising from correlated network features. The complexity was deemed out of scope for v1. The Isolation Forest was selected instead as it naturally handles correlated features without requiring an explicit covariance estimate.

### 17.2 Recursive Least Squares (RLS) Adaptive Filter (Rejected)

**Rationale for evaluation:** RLS is an online algorithm that adapts a linear predictor to non-stationary data streams, making it attractive for tracking gradual baseline drift in network traffic.

**Rejection reason:** RLS requires maintaining an `n×n` inverse covariance matrix `P` updated at each step: `P_{k} = (P_{k-1} - K_k C^T P_{k-1}) / λ`. With 4 features, this is a 4×4 matrix updated per row — feasible in Python float64 but requiring 16 Q14 fixed-point multiply-accumulate operations per row in the guest, plus numerical stability guarantees for the forgetting factor `λ` in integer arithmetic. The DDSketch + Z-score combination provides sufficient non-stationarity resistance via sliding window re-baselining without the guest-side matrix operations.

### 17.3 Kalman Filter (Considered, Not Implemented)

The Kalman filter was considered as a more principled state estimator for flow-rate baselining. Like RLS, the prediction step (`x̂ = F x̂_{k-1}`) and update step (`K = PH^T(HPH^T + R)^{-1}`) require matrix operations with guaranteed positive-definite covariance matrices. The same Q14 matrix-operation complexity argument as §17.2 applies. Deferred to v2.

---

*Document last updated: 2026-04-25 — reflects verifier/core v2 (ML upgrade) and analysis_engine.py session-pipeline implementation.*
