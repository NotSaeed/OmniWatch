# OmniWatch — Definitive Walkthrough
## Closing the ICS "Trust Gap" with RISC Zero zkVM, FIDO2, and Autonomous Breach Containment

---

## The Problem: Why ICS Networks Are Uniquely Vulnerable

Industrial Control Systems (ICS) — the computers that run power grids, water treatment plants, and manufacturing lines — were never designed to be networked. A Modbus RTU device from 1979 trusts every write command it receives unconditionally. There is no authentication, no encryption, no audit trail. When these systems were eventually connected to corporate networks (and, inadvertently, the internet), attackers gained the ability to issue commands indistinguishable from legitimate operator traffic.

Modern SOC tools can detect anomalous Modbus traffic. The hard part is what comes next.

A human analyst sees an alert: `192.168.10.47 → PLC-3 — Modbus FC16 write — CRITICAL`. They must decide: is this a rogue attacker rewriting setpoints, or a midnight maintenance window no one told the security team about? If they block it and they're wrong, production stops. If they don't and they're wrong, the turbine overspins.

This is the **ICS Trust Gap**: the chasm between detection and confident, auditable remediation.

OmniWatch bridges that gap with three interlocking mechanisms.

---

## Act I — Edge Capture: Seeing the Attack Before It Lands

The journey begins at the network edge. A Raspberry Pi 4 running **Zeek** and the **ICSNPP** plugin monitors raw Modbus traffic on the OT network segment. Every function-code write — FC5 (coil), FC6 (single register), FC15, FC16 (multiple registers) — is captured and serialized into a compact **61-byte bincode struct**:

```
EdgeRecord {
  src_ip:          [u8; 4],
  dst_ip:          [u8; 4],
  dst_port:        u16,
  modbus_func_code: u8,
  payload_hash:    [u8; 32],
  timestamp_unix:  u64,
  severity_flag:   u8,
}
```

This struct is stored verbatim in `edge_telemetry` — the raw physical evidence. No interpretation yet, no enrichment. The bincode payload is what will later be handed to the zkVM guest program.

The **Edge Telemetry Panel** in the dashboard (`/trustchain` page) shows every captured record in real time, colour-coded by Modbus function code severity. Clicking **PROVE** on any row begins the Trust Chain.

---

## Act II — The STARK Proof: Making the Machine Swear an Oath

When an analyst clicks PROVE, OmniWatch invokes:

```
omniwatch-verifier --prove-file <bincode.bin>
```

This binary is a **RISC Zero zkVM guest program**. It does four things inside the zero-knowledge virtual machine:

1. Reads the 61-byte bincode payload from the host
2. Deserializes it into an `EdgeRecord`
3. Evaluates a deterministic threat classifier (rule engine: `FC16 + CRITICAL + known-malicious IP range → confidence 99.4%`)
4. Writes a `ThreatVerdict` to the **journal** — the cryptographically-sealed output channel

```rust
// guest/src/main.rs (simplified)
let record: EdgeRecord = bincode::deserialize(&payload).unwrap();
let verdict = classify(&record);  // pure deterministic function
env::commit(&verdict);            // sealed into the STARK receipt
```

The host receives a **STARK receipt** — a ~200KB binary blob that is mathematical proof of one thing: *"A program with image ID `0xABCD…` ran on this exact input and produced this exact output."*

**Why does this matter?** Any analyst, judge, or regulator can independently verify this receipt without re-running the program. The proof is not "OmniWatch says so" — it is "mathematics says so." The confidence score (e.g., `99.4%`) was computed inside a sandbox where neither the backend, nor the network, nor the analyst could influence the result.

The `zkvm` node in the 3D DAG turns green. The ParticleBurst fires — 24 particles erupt outward in a Fibonacci-lattice sphere, marking the moment the machine made its oath.

---

## Act III — FIDO2 Human Oversight: Closing the Machine-Only Loophole

A machine proof alone is not enough. Automated systems can be compromised at the infrastructure level (a poisoned model, a manipulated input pipeline). OmniWatch requires a **second factor** from a human being.

After the STARK receipt is generated, the system initiates a WebAuthn ceremony:

1. **`POST /api/auth/sign/begin`** — the backend creates a challenge bound to the receipt's SHA-256 hash. The analyst's FIDO2 device (YubiKey, Touch ID, Windows Hello) must sign this specific challenge — not a generic login, but a cryptographic acknowledgement of *this specific receipt for this specific threat*.

2. The ECDSA signature is returned to **`POST /api/verify-remediation`** alongside the receipt.

3. The backend verifies both in parallel:
   ```python
   stark_task  = asyncio.create_task(_verify_stark(receipt_b64))
   webauthn_task = asyncio.create_task(_verify_fido2(session_id, assertion))
   stark_result, _ = await asyncio.gather(stark_task, webauthn_task)
   ```

4. Only if **both** pass does the system proceed. The machine proved the threat mathematically. The human confirmed they reviewed it and authorised action.

The `fido2` and `gate` nodes turn green. This is the dual-factor gate — the heart of OmniWatch's auditability claim.

---

## Act IV — The Spent-Receipt Registry: Preventing Replay

Before any network isolation action is taken, the receipt's `input_hash` (a SHA-256 of the bincode payload) is written to a **Spent-Receipt Registry**:

```sql
CREATE TABLE spent_receipts (nonce TEXT PRIMARY KEY);
INSERT OR IGNORE INTO spent_receipts (nonce) VALUES (?);
-- Returns 0 rows affected if already spent → replay detected → abort
```

SQLite WAL mode with `PRAGMA journal_mode=WAL` makes this atomic. An attacker who somehow obtained a valid STARK receipt cannot replay it to trigger a second block — the nonce is burned on first use.

---

## Act V — Network Isolation: The Remediation

With the dual-factor gate passed and the nonce consumed, `enforce_active_block()` executes:

1. Writes a `BLOCK` rule to the `firewall_status` table — the **immutable audit ledger**
2. Stores the full `ThreatVerdict` JSON in `verdict_json` — the machine's reasoning, sealed forever
3. Broadcasts a `firewall_block` WebSocket event to every connected analyst terminal

The `action` — Remediation — node turns green. The ParticleBurst fires a final time. A dark-green toast: `NETWORK ISOLATED — 192.168.10.47 blocked at ICS firewall`.

The **FirewallHistoryPanel** updates instantly (the WS event invalidates the React Query cache) and shows the new entry in the Remediation Ledger. Hovering over any entry reveals an **ExternalLink** icon — clicking it opens the **Proof of Integrity Modal**.

---

## Act VI — The Proof Modal: The Cryptographic Audit Record

The ProofModal is where OmniWatch's claims become verifiable. It fetches `/api/firewall/proof/{rule_id}` and renders:

**Seal of Computational Integrity** — an SVG measurement ring with 36 tick marks (calibration marks derived from engineering instrument dials), a shield checkmark, and `VERIFIED` text. The glow filter uses a real SVG `feGaussianBlur + feMerge` bloom, not a CSS approximation.

**Attacker Source** — the raw IP address at 22px, red shadow glow, alongside category, confidence percentage, and timestamp.

**Decision Logic · STARK Verdict Journal** — the raw JSON decoded from the RISC Zero journal, rendered with a custom syntax highlighter. Keys are cyan, strings are orange, numbers are teal, booleans are violet. The full replay-prevention nonce (the `input_hash`) is displayed in its entirety — 64 hex characters, monospaced.

**Security Guarantees** — four machine-verified properties:
- STARK proof verified against compiled image ID
- ThreatVerdict journal decoded from tamper-proof receipt
- Nonce registered in Spent-Receipt Registry
- FIDO2 human oversight signature recorded

This modal is the answer to "prove it." A forensic investigator, an insurance auditor, or a courtroom can verify every claim using the receipt hash and the open-source RISC Zero verifier.

---

## Act VII — Autonomous Breach Containment: When Humans Are Too Slow

For extreme-confidence threats (≥ 98%), waiting for a human to click PROVE introduces unacceptable latency. A PLC setpoint change takes effect in milliseconds. A SOC analyst's reaction time is minutes.

**ABC (Autonomous Breach Containment)** closes this gap. When enabled from the Trust Chain page:

- An **APScheduler** job runs every 15 seconds
- It queries `edge_telemetry` for CRITICAL Modbus write records not yet in `_abc_processed`
- For each new threat, it runs the full pipeline autonomously:
  1. Broadcasts `abc_proving` — the DAG nodes animate to "verifying"
  2. Spawns the zkVM prover in a subprocess
  3. Verifies the receipt — if `confidence_pct < 98.0`, broadcasts `abc_low_confidence` and stops
  4. Spends the nonce, calls `enforce_active_block(auto_blocked=True)`
  5. Broadcasts `abc_auto_block` — all DAG nodes transition to "verified", the FirewallHistoryPanel updates, the Remediation Ledger shows an **ABC** badge

The ABC badge (`Bot` icon, cyan) distinguishes autonomous blocks from human-authorised blocks (`User` icon, magenta) in the ProofModal — preserving the audit trail even in fully automated operation.

**Safety design**: ABC uses the same cryptographic pipeline as manual PROVE. The confidence gate (98%) means only threats with near-certainty are auto-blocked. The Spent-Receipt Registry prevents replay. The full verdict is stored. Nothing is "trusted because the algorithm said so" — the mathematics is verifiable at any time.

---

## The Full Trust Chain — Summary

```
Edge Telemetry (Zeek + ICSNPP)
    │  61-byte bincode struct
    ▼
RISC Zero zkVM Guest Program
    │  STARK receipt (mathematical proof)
    ▼
Dual-Factor Verification Gate ──── FIDO2 Human Signature (ECDSA / WebAuthn)
    │  Both factors passed
    ▼
Spent-Receipt Registry (SQLite WAL, INSERT OR IGNORE)
    │  Nonce burned — replay impossible
    ▼
firewall_status table + WebSocket broadcast
    │  Immutable audit ledger
    ▼
FirewallHistoryPanel → ProofModal
    │  Full cryptographic audit record, verifiable offline
    ▼
Analyst / Auditor / Regulator
```

---

## Running the Demo

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080 --reload

# Frontend
cd frontend
npm install
npm run dev
```

Navigate to `http://localhost:5173` → **Trust Chain** page.

1. The Edge Telemetry Panel populates automatically from `edge_telemetry` (seeded on first run).
2. Click **PROVE** on any CRITICAL row. Watch the 3D DAG animate: zkvm → fido2 → gate → action, each node bursting green.
3. Check the **Remediation Ledger** — the new entry appears instantly.
4. Click the **⧉** icon on any entry to open the **Proof of Integrity Modal** and inspect the full STARK verdict journal.
5. Click **ENABLE ABC** — the autonomous mode activates. New CRITICAL Modbus writes will be proven and blocked within 15 seconds, with the DAG animating and the ledger updating automatically.

---

## Why This Matters for CITREX 2026

OmniWatch demonstrates three advances over conventional ICS security:

| Gap | Conventional SOC | OmniWatch |
|-----|-----------------|-----------|
| **Auditability** | "The SIEM flagged it" | STARK receipt — mathematically verifiable, offline |
| **Human accountability** | None | FIDO2 signature cryptographically binds analyst identity to each decision |
| **Replay protection** | Session tokens (replayable) | Spent-Receipt Registry — SHA-256 nonce burned on first use |
| **Speed at scale** | Minutes (human loop) | ABC closes critical threats in <15 seconds with full proof |
| **False-positive risk** | Binary: block or don't | Confidence gate — only ≥98% triggers autonomous action |

The innovation is not a faster SIEM. It is a new abstraction: **cryptographically-proven, human-supervised, replay-resistant network isolation** — with a full audit trail that survives litigation.

---

*OmniWatch — AI-SOC Platform for Industrial Control Systems*
*Abdullah Ba Nafe · Alhamed · Team UMPSA — CITREX 2026*
*Supervisor: Abdulkareem*
