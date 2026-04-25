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
9. [Detection Pillar III — Zero-MUL Time-Domain CUSUM Pipeline](#9-detection-pillar-iii--zero-mul-time-domain-cusum-pipeline)  
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
    baselines: HostBaselines,      // per-host ML baselines (Z-score / DDSketch)
    loda:      LodaModel,          // LODA anomaly detector (Rule 11)
    cusum:     CusumModel,         // DAS-CUSUM beacon detector (Rule 12)
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
│  LodaBaseliner       ←──── sparse random projections, 1D histograms     │
│  CusumBaseliner      ←──── epoch-fold L1 + DAS-CUSUM (Stages 0–2)      │
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
│  Rule evaluation: 12 rules, 14 bit-flags in ThreatVerdict               │
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
LODA bin edges         ──fp14────►   bin_edges_fp14[k × (n_bins+1)] (i64)
LODA bin scores        ──Q10─────►   bin_scores_fp10[k × n_bins]    (i32)
mean_bytes_s (float)   ──×1000───►   mean_bytes_s_milli (u64)
stddev_bytes_s (float) ──×1000───►   stddev_bytes_s_milli (u64)
CUSUM epoch-fold L1    ──fp14────►   b_n_fp14[k]              (i64)
CUSUM running state    ──fp14────►   cusum_states_fp14[k]     (i64)
CUSUM drift k          ──fp14────►   cusum_k_fp14             (i64)
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

## 8. Detection Pillar II — LODA (Lightweight On-line Detector of Anomalies)

> **v4 upgrade:** Isolation Forest was superseded by LODA. Rationale is documented in §17.4.

### 8.1 Algorithm

LODA detects multivariate anomalies by projecting high-dimensional data onto k sparse 1-D axes, fitting a histogram on each projected axis, and scoring records by the sum of negative log-densities across all projections. Records that fall in low-density histogram bins across multiple projections are flagged as anomalous.

**Anomaly score** for a record `x`:

```
score(x) = (1/k) · Σᵢ [ −log p̂ᵢ(wᵢᵀ x) ]
```

Where:
- `k` — number of sparse random projections (default: 8)
- `wᵢ` — sparse projection vector with elements `wᵢⱼ ∈ {−1, 0, 1}`
- `p̂ᵢ(·)` — 1D histogram density estimate on the i-th projected axis

A record is anomalous when `score(x) > T`, where `T` is the 95th-percentile score computed over the training population.

### 8.2 Sparse Projection Design

Projection vectors are generated with sparsity `ρ = 0.5` (probability that `wᵢⱼ = 0`):

```python
for j in range(n_features):
    r = rng.random()
    if   r < (1 − ρ) / 2:  wᵢⱼ = −1
    elif r < (1 − ρ):      wᵢⱼ = +1
    else:                   wᵢⱼ =  0   # skipped in both Python and Rust
```

At least one non-zero weight is guaranteed per vector. The seed (`_LODA_SEED = 42`) is fixed so the projection matrix is identical between Python training and the Rust guest, ensuring Q14-encoded bin edges are valid for the same projected space.

### 8.3 zkVM Serialization — Flat Array Payload

The Python `LodaBaseliner` exports the trained model as a JSON payload with Q14/Q10 fixed-point encoding. The `LodaModel` struct in `verifier/core/src/lib.rs` holds the deserialized arrays.

| Field | Python type | Encoding | Rust type |
|---|---|---|---|
| `projections` | `int8[k × 4]` | raw (∈ {−1,0,1}) | `Vec<i8>` |
| `bin_edges_fp14` | `float[k × (n_bins+1)]` | `floor(edge × 2^14)` | `Vec<i64>` |
| `bin_scores_fp10` | `float[k × n_bins]` | `floor(−log(density) × 2^10)` | `Vec<i32>` |
| `anomaly_threshold_fp10` | `float` | `floor(T_mean × k × 2^10)` | `i64` |

The threshold is scaled by `k` because the Rust guest accumulates a raw sum (not a mean) across k projections; multiplying the per-projection mean threshold by k gives the equivalent total-score threshold.

### 8.4 Python Host — `LodaBaseliner`

```python
class LodaBaseliner:
    def fit(self):
        X = np.vstack(self._buffer)             # accumulated feature matrix
        for i in range(_LODA_K):
            w = self._projections[i]
            # Sparse projection — mirrors Rust match-arm add/subtract
            z = np.zeros(len(X))
            for j in range(4):
                if w[j] == 1:  z += X[:, j]
                elif w[j] == -1: z -= X[:, j]
            # 1D histogram
            edges  = np.histogram_bin_edges(z, bins=_LODA_N_BINS)
            counts, _ = np.histogram(z, bins=edges)
            density = counts / (len(X) * np.diff(edges).clip(min=1e-10))
            score   = -np.log(density.clip(min=1e-10)).clip(max=50.0)
            # ... accumulate for threshold, store Q14/Q10 encoded

    def payload(self) -> str:
        # Q14 encode bin edges: floor(edge × 2^14)
        # Q10 encode scores:    floor(score × 2^10)
        # threshold_fp10 = floor(threshold_mean × k × 2^10)
```

### 8.5 Rust Guest — `loda_score`

```rust
fn loda_score(model: &LodaModel, t: &NetworkTelemetry) -> Option<i64> {
    let features = loda_features(t);   // [bps_kb, pkt_count, dur_ms, dst_port] as i64
    let mut total_score: i64 = 0;

    for i in 0..k {
        // ── Sparse projection: zero multiplication ────────────────────────
        let mut z: i64 = 0;
        for j in 0..nf {
            match model.projections[i * nf + j] {
                1  => z += features[j],   // ADD  — single-cycle RV32IM
                -1 => z -= features[j],   // SUB  — single-cycle RV32IM
                _  => {}                  // skip — saves one ADD per zero weight
            }
        }

        // Scale to Q14 for comparison with Q14-encoded bin edges.
        // One saturating_mul per projection — not per feature × tree-node.
        let z_fp14 = z.saturating_mul(16_384);

        // ── Bin lookup: linear scan over ~10 contiguous edges ─────────────
        let mut bin_idx = nb - 1;  // default: last bin (right tail)
        for b in 0..nb {
            if z_fp14 < model.bin_edges_fp14[edge_base + b + 1] {
                bin_idx = b;
                break;
            }
        }

        // ── Score accumulation ────────────────────────────────────────────
        total_score += model.bin_scores_fp10[score_base + bin_idx] as i64;
    }
    Some(total_score)
}
```

### 8.6 Rule Evaluation — `LODA_ANOMALY` (bit 12)

```rust
if let Some(score) = loda_score(&input.loda, t) {
    if score > input.loda.anomaly_threshold_fp10 {
        fired |= rules::LODA_ANOMALY;
        if cat == 0 { cat = 5; conf = conf.max(72); }  // ANOMALY
    }
}
```

### 8.7 Cycle-Count Rationale

The critical path comparison vs. Isolation Forest on RV32IM:

| Operation | Isolation Forest | LODA |
|---|---|---|
| Inner loop body | `MUL` (fp14 scale) + branch + random memory load per node | `ADD` or `SUB` (match arm) per feature — **zero MUL** |
| Memory access pattern | Pointer-jump to child node index — cache-hostile | Sequential flat-array scan — cache-friendly |
| Worst-case iterations | `n_trees × MAX_TREE_DEPTH = 8 × 64 = 512` | `k × n_bins = 8 × 10 = 80` |
| Scaling cost | Grows with tree depth × estimators | Fixed: `k × n_features + k × n_bins` |

On RV32IM, `match { 1 => z += x, -1 => z -= x, _ => {} }` compiles to two conditional branches and one ADD or SUB — no MUL instructions. The Isolation Forest's `fval_fp14 = feature.saturating_mul(16_384)` required a MUL per tree node. LODA's single `z.saturating_mul(16_384)` fires once per projection, not per node.

---

## 9. Detection Pillar III — Zero-MUL Time-Domain CUSUM Pipeline

> **v5 upgrade:** The Goertzel IIR detector was superseded by this pipeline. Full deprecation rationale is in §17.6.

### 9.1 Design Goal

Detect periodic C2 beaconing — repeated inter-arrival intervals clustering around a candidate period P — using only ADD, SUB, and bitwise operations in the Rust zkVM guest. The pipeline is split across four stages: Stages 0/1 and 2 execute in the Python host; Stage 3 alone runs inside the zkVM and produces the cryptographic proof.

### 9.2 Four-Stage Pipeline

#### Stage 0/1 — Multiplierless Comb Pre-Filter (Python host)

For each source IP, accumulate inter-arrival timestamps chronologically. Compute the first-difference sequence — equivalent to a single-pole comb filter with unit delay:

```
Δt[n] = t[n] − t[n−1]    (pure subtraction — no MUL)
```

This removes the DC offset from the timestamp stream, leaving only the periodic components that distinguish beaconing from random arrival processes. All arithmetic is ADD/SUB — zero MUL instructions.

#### Stage 2 — Epoch-Folded L1 Histogram (Python host)

For each candidate beacon period P_i (µs):

```
phase[n]    = t[n] mod P_i             (modulo maps timestamp into [0, P_i))
bin_idx[n]  = phase[n] >> shift_val    (bitshift ≡ divide by bin_width; no MUL)
C[j]        = count of observations in bin j
expected    = N >> shift_val           (bitshift approximates N / n_bins)
L1[P_i]    = Σ_j | C[j] − expected |  (sum of absolute deviations from uniform)
B_n[i]      = floor( L1[P_i] × 2^14 ) (Q14 encoding for Rust guest)
```

Where `shift_val = log₂(n_bins) = 4` for `n_bins = 16`. A beaconing source concentrates observations in one or two bins, producing a large L1 score; a benign random-arrival source distributes uniformly, producing a small L1 score.

The three candidate periods tracked simultaneously:

| Index | Period | Target threat |
|---|---|---|
| 0 | 60 s | Common RAT heartbeat |
| 1 | 300 s | Low-and-slow APT beacon |
| 2 | 600 s | Long-interval C2 check-in |

#### Stage 3 — DAS-CUSUM Accumulator (Rust guest, proved in zkVM)

Applies the **Page's DAS-CUSUM** (Decision-theoretic Adaptive Sum) formula independently for each candidate period:

```
S_n[i] = max( 0,  S_{n-1}[i]  +  B_n[i]  −  k )
```

Where:
- `S_{n-1}[i]` — running accumulator from the previous record (Q14, per source IP)
- `B_n[i]` — epoch-fold L1 score for this record and period (Q14)
- `k` — drift parameter (Q14): calibrated as `K_FACTOR × median(L1)` under benign traffic
- `S_n[i] > cusum_threshold_fp14` → **CUSUM_BEACON** fires (bit 13)

**Rust instruction count per period:**

```
saturating_add  → ADD with overflow guard   (zero MUL)
saturating_sub  → SUB with underflow guard
.max(0)         → conditional branch + register select
```

Zero `*` operators appear anywhere in this path on RV32IM.

### 9.3 Python Host — `CusumBaseliner`

```python
class CusumBaseliner:
    PERIODS_US   = [60_000_000, 300_000_000, 600_000_000]
    N_BINS       = 16       # power-of-2 → bitshift replaces division
    K_FACTOR     = 0.5      # drift = K_FACTOR × median L1 under benign
    THRESHOLD    = 10.0     # real-valued; Q14-encoded for guest

    def update(self, df):
        # Accumulate timestamps per source IP

    def fit(self):
        # Calibrate k = K_FACTOR × median(L1 scores across all IPs and periods)

    def b_n_for_ip(self, source_ip) -> list[int]:
        # Stage 2: epoch-fold → L1 score → Q14 encode → one int per period

    def cusum_state_for_ip(self, source_ip) -> list[int]:
        # Return running Q14 S_{n-1} per period for this source IP

    def advance_state(self, source_ip, b_n_fp14):
        # Mirror Stage 3 in Python to keep host state synchronized with guest

    def payload(self) -> str:
        # JSON: {k, n_bins, shift_val, periods_us, cusum_k_fp14, cusum_threshold_fp14}
```

The `payload()` output is stored in `pipeline_sessions.cusum_payload`. Per-record `b_n_fp14` and `cusum_states_fp14` are computed at STARK-proof time via `b_n_for_ip()` and `cusum_state_for_ip()`.

### 9.4 Rust Guest — `cusum_beacon` (Rule 12, bit 13)

```rust
fn cusum_beacon(model: &CusumModel) -> bool {
    if model.k == 0 { return false; }
    for i in 0..(model.k as usize) {
        // S_n = max(0, S_{n-1} + B_n − k) :  ADD + SUB + MAX, zero MUL
        let s_n = model.cusum_states_fp14[i]
            .saturating_add(model.b_n_fp14[i])
            .saturating_sub(model.cusum_k_fp14)
            .max(0);
        if s_n > model.cusum_threshold_fp14 {
            return true;  // beacon detected on period i
        }
    }
    false
}
```

### 9.5 Split-Brain Information Flow

```
Python host (float64)                     Rust guest (Q14 integers only)
─────────────────────────────             ────────────────────────────────────────
Stage 0/1: comb filter (Δt)
Stage 2: epoch-fold L1 score    ─Q14──►  b_n_fp14[k]       (B_n per period)
Running CUSUM state             ─Q14──►  cusum_states_fp14[k]  (S_{n-1})
Calibrated drift k              ─Q14──►  cusum_k_fp14
Alert threshold                 ─Q14──►  cusum_threshold_fp14
                                          │
                                          ▼ Stage 3 (proved):
                                          S_n = max(0, S_{n-1} + B_n − k)
                                          CUSUM_BEACON = S_n > threshold
```

### 9.6 Statistical Properties

The CUSUM accumulator has expected run length (ARL) characteristics:
- **Under H₀ (benign):** L1 scores ≈ uniform fluctuation; drift k absorbs them; S_n stays near 0
- **Under H₁ (beaconing):** L1 scores consistently above k; S_n increases monotonically until threshold
- **Detection lag:** typically 3–8 records after beaconing begins, depending on interval regularity

The L1 histogram norm was chosen over L2 (chi-squared) because L1 requires only ADD/SUB/ABS in the Python host stage, and the per-bin absolute deviation is a natural fit for the bitshift-encoded expected count.

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
3. Evaluate all 12 threat rules (§10.4) against `input.telemetry`, `input.baselines`, and `input.cusum`.
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
| 12 | `LODA_ANOMALY` | sum of per-projection –log(density) scores > anomaly_threshold_fp10 (§8.6) |
| 13 | `CUSUM_BEACON` | DAS-CUSUM S_n > threshold on any candidate beacon period (§9.4) |

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

### 17.1 Isolation Forest (Evaluated — Superseded by LODA in v4)

**Rationale for initial selection:** Isolation Forest (v3) offered several advantages: no distributional assumption, O(n log n) training, natural handling of correlated features, and deterministic output from a fixed random seed. The stride-4 flattened array serialization was compact and the Q14 path-length threshold encoding was clean.

**Supersession reason — zkVM microarchitectural analysis:** Profiling the RV32IM execution trace revealed two critical bottlenecks:

1. **Pointer-jump memory access pattern.** Each `traverse_tree` call follows a chain of global array indices: `current = nodes[base+2]` or `nodes[base+3]`. With up to 8 trees × 64 nodes, these jumps produce cache-hostile sequential access patterns in the zkVM's simulated memory, each requiring a separate memory-load cycle.

2. **Multiply per node.** The Q14 feature scaling `fval_fp14 = feature.saturating_mul(16_384)` issued one MUL instruction per internal tree node. On RV32IM the MUL instruction costs 3 cycles vs. 1 cycle for ADD/SUB. With `n_trees × average_depth` nodes evaluated per record, this adds up to hundreds of MUL cycles that LODA eliminates entirely.

**LODA's solution:** projection weights `wᵢⱼ ∈ {-1, 0, 1}` replace the MUL with a match-arm ADD or SUB (or a skip). The single Q14 scaling `z.saturating_mul(16_384)` fires once per projection, not once per node. The linear bin-edge scan replaces the branching tree traversal with sequential flat-array accesses.

### 17.2 Hyperdimensional Computing (HDC) (Rejected)

**Rationale for evaluation:** HDC encodes records into high-dimensional binary vectors (hypervectors, dimension `D = 2 000–10 000`) and detects anomalies by measuring Hamming distance to a class prototype. It is inherently integer-based — XOR and POPCOUNT operations only — which made it attractive for the zkVM guest.

**Rejection reason — missing RV32IM POPCOUNT instruction:** HDC's inner loop requires counting the number of 1-bits in an XOR result (popcount). The `x86_64` ISA provides `POPCNT` as a single instruction. RV32IM provides no equivalent; the `B` (bit-manipulation) extension adds `CPOP` but RISC Zero's guest ELF toolchain targets the base `RV32IM` ISA without the B extension. Emulating POPCOUNT on RV32IM requires a multi-instruction software loop (typically 7–12 instructions per 32-bit word using the Hamming-weight bit-trick). For a `D = 2 000` bit hypervector, a single Hamming-distance computation requires `ceil(2000/32) = 63` POPCOUNT calls × 10 instructions = 630 instructions per record — far exceeding LODA's 80-iteration flat-array scan.

Additionally, HDC prototype training (bundling operation over thousands of training records with XOR + majority-vote) requires significant state that is awkward to serialize into the compact `LodaModel`-equivalent struct for `env::read()`.

### 17.3 Mahalanobis Distance (Rejected)

**Rationale for evaluation:** Mahalanobis distance accounts for feature correlations and normalizes by the covariance matrix, making it theoretically superior to independent Z-scores for multivariate anomaly detection.

**Rejection reason:** Computing the covariance matrix inverse `Σ⁻¹` requires floating-point matrix operations (numpy `linalg.inv`). Translating this to a Q14 integer matrix inverse in the zkVM guest requires fixed-point matrix inversion algorithms (e.g., Gauss-Jordan with Q14 pivots), which are numerically unstable for near-singular covariance matrices arising from correlated network features. The complexity was deemed out of scope for v1. LODA was selected instead, as it implicitly captures inter-feature correlations through random projections without requiring an explicit covariance estimate.

### 17.4 Recursive Least Squares (RLS) Adaptive Filter (Rejected)

**Rationale for evaluation:** RLS is an online algorithm that adapts a linear predictor to non-stationary data streams, making it attractive for tracking gradual baseline drift in network traffic.

**Rejection reason:** RLS requires maintaining an `n×n` inverse covariance matrix `P` updated at each step: `P_{k} = (P_{k-1} - K_k C^T P_{k-1}) / λ`. With 4 features, this is a 4×4 matrix updated per row — feasible in Python float64 but requiring 16 Q14 fixed-point multiply-accumulate operations per row in the guest, plus numerical stability guarantees for the forgetting factor `λ` in integer arithmetic. The DDSketch + Z-score combination provides sufficient non-stationarity resistance via sliding window re-baselining without the guest-side matrix operations.

### 17.5 Kalman Filter (Considered, Not Implemented)

### 17.6 Goertzel IIR Beaconing Detector (Evaluated — Superseded by CUSUM in v5)

The Kalman filter was considered as a more principled state estimator for flow-rate baselining. Like RLS, the prediction step (`x̂ = F x̂_{k-1}`) and update step (`K = PH^T(HPH^T + R)^{-1}`) require matrix operations with guaranteed positive-definite covariance matrices. The same Q14 matrix-operation complexity argument as §17.4 applies. Deferred to v2.

---

**Rationale for initial design:** The Goertzel algorithm is a mathematically elegant, single-bin DFT evaluator. Pre-computing the cosine coefficient `c_int = floor(2·cos(2πk/N) × 2^14)` on the Python host and embedding it in the input appeared to satisfy the zero-float constraint for the guest. The Q14 IIR recurrence was clean:

```rust
let q0 = ((c_int as i64 * q1) >> 14) - q2 + x as i64;
```

**Supersession reason — MUL-per-sample and jitter intolerance:**

1. **Multiply per sample.** The feedback term `c_int * q1` requires one `MUL` per input sample. For a window of N = 256 inter-arrival observations, this is 256 MUL instructions — one per record per candidate frequency. The CUSUM Stage 3 requires zero MUL instructions regardless of window size; its per-period cost is 3 operations (ADD, SUB, MAX) total.

2. **Per-frequency MUL in power calculation.** The final power term `q1 * q1 - (c_int * q1 * q2 >> 14) + q2 * q2` requires 4 MUL instructions per candidate frequency, executed once per proof. With k = 3 candidate periods, this adds 12 MUL calls to every receipt.

3. **Jitter intolerance.** The Goertzel algorithm measures spectral power at a single precise frequency bin. Real C2 beaconing exhibits ±5–15% jitter (TCP retransmissions, jitter buffers, host scheduling). Energy smeared across adjacent bins reduces the power at the target bin below the detection threshold. The epoch-folded L1 histogram is jitter-tolerant by design: ±15% jitter in a 60 s period shifts the phase bin by ≤ 2 bins, which still produces an elevated L1 score.

4. **Window management complexity.** Goertzel requires a fixed-length sample window (N samples) before a decision can be made, requiring the Python host to buffer per-IP sample windows. CUSUM accumulates evidence incrementally — no window management needed.

**CUSUM's solution:** Stages 0–2 run on the Python host with no MUL constraint (host is unrestricted floating-point). Stage 3 in the Rust guest is a single `saturating_add + saturating_sub + max(0)` per candidate period — three operations, zero MUL, regardless of the number of records processed.

---

*Document last updated: 2026-04-25 — reflects verifier/core v5 (CUSUM upgrade, superseding Goertzel) and analysis_engine.py CusumBaseliner.*
