"""
OmniWatch Unified SOC Analysis Engine — v2 (ML-Upgraded)
==========================================================
Pillar 1 — Schema detection & normalization (BOTSv3 / CICIDS-2017 / Zeek / generic)
Pillar 2 — Tier 1 heuristic filter + Isolation Forest + Z-score baselining
Pillar 3 — Tier 2/3 dynamic MITRE ATT&CK mapping (label > port > z-score > volume > default)
Pillar 4 — Time-window per-IP correlation (connection count aggregation)
Pillar 5 — SQLite WAL-mode persistence with lock-retry

All pandas / sklearn I/O runs inside a ThreadPoolExecutor so the FastAPI event loop
is never blocked.  Every DB write function is wrapped in _db_retry() to survive
concurrent pipeline sessions that would otherwise produce "database is locked" errors.
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import math
import sqlite3
import time
import traceback
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ── Optional heavy dependencies — degrade gracefully if missing ───────────────

try:
    import pandas as pd
    _PANDAS_OK = True
except ImportError:
    _PANDAS_OK = False
    logger.error("pandas not installed — pip install pandas")

try:
    import numpy as _np
    _NUMPY_OK = True
except ImportError:
    _NUMPY_OK = False
    logger.warning("numpy not installed — LODA ML filter disabled (pip install numpy)")

try:
    from ddsketch import DDSketch as _DDSketch
    _DDSKETCH_OK = True
except ImportError:
    _DDSKETCH_OK = False
    logger.warning("ddsketch not installed — dynamic thresholds disabled (pip install ddsketch)")

_LODA_K        = 8          # number of sparse random projections
_LODA_N_BINS   = 10         # 1D histogram bins per projection
_LODA_SPARSITY = 0.5        # probability that a projection weight is 0
_LODA_SEED     = 42         # reproducible projection matrix
_MAX_LODA_ROWS = 200_000    # training buffer cap (memory bound)

# CUSUM C2 beacon detector constants
_CUSUM_PERIODS_US: list[int] = [
    60_000_000,   # 1-min C2 heartbeat (common RAT interval)
    300_000_000,  # 5-min low-and-slow beacon
    600_000_000,  # 10-min APT-style check-in
]
_CUSUM_N_BINS    = 16    # must be power-of-2; bitshift replaces division in guest
_CUSUM_K_FACTOR  = 0.5  # allowance = K_FACTOR × median L1 under benign traffic
_CUSUM_THRESHOLD = 10.0  # DAS-CUSUM alert threshold (real-valued; Q14-encoded for guest)
_MAX_CUSUM_IPS   = 5_000  # max distinct source IPs to track (memory guard)


# ── SQLite lock-retry decorator ───────────────────────────────────────────────

def _db_retry(fn):
    """
    Decorator: retry a SQLite write up to 6 times on 'database is locked'.
    Uses exponential back-off (0.15 s → 0.3 → 0.6 → 1.2 → 2.4 → 4.8 s).
    Any other OperationalError is re-raised immediately.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        last_exc: Exception | None = None
        for attempt in range(6):
            try:
                return fn(*args, **kwargs)
            except sqlite3.OperationalError as exc:
                if "locked" in str(exc).lower():
                    last_exc = exc
                    delay = 0.15 * (2 ** attempt)
                    logger.warning(
                        "%s: DB locked (attempt %d) — retrying in %.2fs",
                        fn.__name__, attempt + 1, delay,
                    )
                    time.sleep(delay)
                else:
                    raise
        assert last_exc is not None
        raise last_exc
    return wrapper


# ── MITRE Technique Derivation Tables ────────────────────────────────────────

_PORT_MITRE: dict[int, tuple[str, str]] = {
    20:    ("T1048",     "Exfiltration Over Alternative Protocol"),
    21:    ("T1021.002", "Remote Services: FTP"),
    22:    ("T1021.004", "Remote Services: SSH"),
    23:    ("T1021.001", "Remote Services: Telnet"),
    25:    ("T1071.003", "Application Layer Protocol: Mail Protocols"),
    53:    ("T1071.004", "Application Layer Protocol: DNS"),
    80:    ("T1071.001", "Application Layer Protocol: Web Protocols"),
    110:   ("T1114.002", "Email Collection: Remote Email Collection"),
    135:   ("T1021.003", "Remote Services: DCOM"),
    139:   ("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    143:   ("T1114.002", "Email Collection: Remote Email Collection"),
    161:   ("T1602.001", "Data from Configuration Repository: SNMP"),
    389:   ("T1087.002", "Account Discovery: Domain Account"),
    443:   ("T1071.001", "Application Layer Protocol: Web Protocols"),
    445:   ("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    514:   ("T1562.006", "Impair Defenses: Indicator Blocking"),
    636:   ("T1087.002", "Account Discovery: Domain Account"),
    1080:  ("T1090",     "Proxy"),
    1433:  ("T1190",     "Exploit Public-Facing Application"),
    1521:  ("T1190",     "Exploit Public-Facing Application"),
    3306:  ("T1190",     "Exploit Public-Facing Application"),
    3389:  ("T1021.001", "Remote Services: Remote Desktop Protocol"),
    4444:  ("T1059",     "Command and Scripting Interpreter"),
    4899:  ("T1219",     "Remote Access Software"),
    5432:  ("T1190",     "Exploit Public-Facing Application"),
    5555:  ("T1219",     "Remote Access Software"),
    5900:  ("T1021.005", "Remote Services: VNC"),
    6667:  ("T1071",     "Application Layer Protocol"),
    6881:  ("T1048",     "Exfiltration Over Alternative Protocol"),
    8080:  ("T1071.001", "Application Layer Protocol: Web Protocols"),
    8443:  ("T1071.001", "Application Layer Protocol: Web Protocols"),
    9001:  ("T1090.003", "Proxy: Multi-hop Proxy"),
    9200:  ("T1190",     "Exploit Public-Facing Application"),
    27017: ("T1190",     "Exploit Public-Facing Application"),
    50000: ("T1190",     "Exploit Public-Facing Application"),
}

# Ordered most-specific → least-specific; first match wins.
_LABEL_MITRE: list[tuple[str, str, str]] = [
    ("ftp-patator",   "T1110.001", "Brute Force: Password Guessing"),
    ("ssh-patator",   "T1110.001", "Brute Force: Password Guessing"),
    ("heartbleed",    "T1190",     "Exploit Public-Facing Application"),
    ("shellshock",    "T1190",     "Exploit Public-Facing Application"),
    ("sql injection", "T1190",     "Exploit Public-Facing Application"),
    ("web attack",    "T1190",     "Exploit Public-Facing Application"),
    ("infiltration",  "T1190",     "Exploit Public-Facing Application"),
    ("ransomware",    "T1486",     "Data Encrypted for Impact"),
    ("ddos",          "T1498",     "Network Denial of Service"),
    ("dos",           "T1499",     "Endpoint Denial of Service"),
    ("port scan",     "T1046",     "Network Service Discovery"),
    ("portscan",      "T1046",     "Network Service Discovery"),
    ("network scan",  "T1046",     "Network Service Discovery"),
    ("brute force",   "T1110",     "Brute Force"),
    ("bruteforce",    "T1110",     "Brute Force"),
    ("bot",           "T1583",     "Acquire Infrastructure"),
    ("xss",           "T1189",     "Drive-by Compromise"),
    ("lateral",       "T1021",     "Remote Services"),
    ("exfil",         "T1041",     "Exfiltration Over C2 Channel"),
    ("c&c",           "T1071",     "Application Layer Protocol"),
    ("command",       "T1059",     "Command and Scripting Interpreter"),
    ("privilege",     "T1548",     "Abuse Elevation Control Mechanism"),
    ("credential",    "T1555",     "Credentials from Password Stores"),
    ("phishing",      "T1566",     "Phishing"),
    ("malware",       "T1204",     "User Execution"),
]


def derive_mitre(
    label: str,
    dst_port: int | None,
    bytes_out: float | None,
    protocol: str | None,
    *,
    z_score_bytes: float | None = None,
    z_score_pkts:  float | None = None,
) -> tuple[str, str]:
    """
    Derive MITRE ATT&CK technique from available runtime signals.

    Priority (most specific → most general):
      1. Label keyword match
      2. Z-score > 3.0 on bytes (volumetric anomaly → T1498 DoS)
      3. Z-score > 3.0 on packets (flood / sweep → T1046)
      4. Destination port lookup
      5. Volume heuristic (absolute byte threshold)
      6. ICMP protocol → T1498
      7. Default → T1046
    """
    # 1. Label keyword
    if label:
        lc = label.strip().lower()
        for keyword, tid, tname in _LABEL_MITRE:
            if keyword in lc:
                return tid, tname

    # 2. Volumetric Z-score anomaly on bytes
    if z_score_bytes is not None and z_score_bytes > 3.0:
        if z_score_bytes > 6.0:
            return "T1498", "Network Denial of Service"
        return "T1499", "Endpoint Denial of Service"

    # 3. Packet-rate Z-score anomaly (sweep / flood)
    if z_score_pkts is not None and z_score_pkts > 3.0:
        return "T1046", "Network Service Discovery"

    # 4. Port lookup
    if dst_port is not None:
        try:
            p = int(dst_port)
            if p in _PORT_MITRE:
                return _PORT_MITRE[p]
            if 49152 <= p <= 65535:
                return "T1571", "Non-Standard Port"
        except (ValueError, TypeError):
            pass

    # 5. Absolute volume heuristic
    if bytes_out is not None:
        try:
            b = float(bytes_out)
            if b > 50_000_000:
                return "T1041", "Exfiltration Over C2 Channel"
            if b > 10_000_000:
                return "T1048", "Exfiltration Over Alternative Protocol"
        except (ValueError, TypeError):
            pass

    # 6. Protocol
    if protocol and protocol.strip().lower() == "icmp":
        return "T1498", "Network Denial of Service"

    return "T1046", "Network Service Discovery"


# ── Schema Detection & Field Normalization ────────────────────────────────────

_CANONICAL_COLS = (
    "source_ip", "dest_ip", "dest_port", "protocol",
    "label", "bytes_out", "bytes_in", "packets", "timestamp",
)

_SCHEMA_MARKERS: dict[str, set[str]] = {
    "cicids2017": {
        "label", "flow duration", "total fwd packets",
        "total backward packets", "destination port",
    },
    "botsv3": {"sourcetype", "_raw", "splunk_server", "source"},
    "zeek":   {"id.orig_h", "id.resp_h", "orig_bytes", "id.resp_p"},
}

_SCHEMA_MAPS: dict[str, dict[str, str]] = {
    "cicids2017": {
        "source ip":                   "source_ip",
        "destination ip":              "dest_ip",
        "destination port":            "dest_port",
        "protocol":                    "protocol",
        "label":                       "label",
        "total length of fwd packets": "bytes_out",
        "total length of bwd packets": "bytes_in",
        "total fwd packets":           "packets",
        "timestamp":                   "timestamp",
        "flow duration":               "flow_duration",
    },
    "botsv3": {
        "src_ip":    "source_ip",
        "src":       "source_ip",
        "dest_ip":   "dest_ip",
        "dest":      "dest_ip",
        "dst_ip":    "dest_ip",
        "dst":       "dest_ip",
        "dest_port": "dest_port",
        "dst_port":  "dest_port",
        "protocol":  "protocol",
        "proto":     "protocol",
        "_time":     "timestamp",
        "sourcetype":"label",
        "bytes_out": "bytes_out",
        "bytes":     "bytes_out",
    },
    "zeek": {
        "id.orig_h": "source_ip",
        "id.resp_h": "dest_ip",
        "id.resp_p": "dest_port",
        "proto":     "protocol",
        "orig_bytes":"bytes_out",
        "resp_bytes":"bytes_in",
        "orig_pkts": "packets",
        "ts":        "timestamp",
    },
    "generic": {
        "src_ip":          "source_ip",
        "source ip":       "source_ip",
        "source_ip":       "source_ip",
        "srcip":           "source_ip",
        "src":             "source_ip",
        "ip_src":          "source_ip",
        "dst_ip":          "dest_ip",
        "dest_ip":         "dest_ip",
        "destination ip":  "dest_ip",
        "dstip":           "dest_ip",
        "dst":             "dest_ip",
        "ip_dst":          "dest_ip",
        "dst_port":        "dest_port",
        "dest_port":       "dest_port",
        "destination port":"dest_port",
        "dport":           "dest_port",
        "proto":           "protocol",
        "protocol":        "protocol",
        "label":           "label",
        "attack":          "label",
        "category":        "label",
        "class":           "label",
        "type":            "label",
        "bytes":           "bytes_out",
        "bytes_out":       "bytes_out",
        "out_bytes":       "bytes_out",
        "sent_bytes":      "bytes_out",
        "bytes_in":        "bytes_in",
        "recv_bytes":      "bytes_in",
        "packets":         "packets",
        "pkt_count":       "packets",
        "timestamp":       "timestamp",
        "time":            "timestamp",
        "ts":              "timestamp",
        "datetime":        "timestamp",
    },
}


def detect_schema(headers: list[str]) -> str:
    norm = {h.strip().lower() for h in headers}
    for schema, markers in _SCHEMA_MARKERS.items():
        if len(markers & norm) >= 2:
            return schema
    return "generic"


def normalize_chunk(df: "pd.DataFrame", schema: str) -> "pd.DataFrame":
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]

    # BOTSv3 Splunk exports often contain duplicate column headers.
    # Keep only the first occurrence of each name so every downstream
    # call to df[col] or df.get(col) always yields a Series, never a DataFrame.
    df = df.loc[:, ~df.columns.duplicated(keep="first")]

    col_map = _SCHEMA_MAPS.get(schema, _SCHEMA_MAPS["generic"])
    rename: dict[str, str] = {}
    for col in df.columns:
        canonical = col_map.get(col.lower())
        if canonical and canonical not in rename.values():
            rename[col] = canonical
    df = df.rename(columns=rename)
    for canon in _CANONICAL_COLS:
        if canon not in df.columns:
            df[canon] = None
    return df


# ── Time-Window Per-IP Correlation ────────────────────────────────────────────

def time_window_correlate(df: "pd.DataFrame", window: str = "1min") -> "pd.DataFrame":
    """
    Aggregate flows per source IP over rolling time windows.

    Returns the original DataFrame with a new column `conn_per_min` indicating
    how many connections the same source IP made in the preceding `window`.
    IPs with conn_per_min > 30 (likely scanner / brute forcer) are flagged via
    a new boolean column `tw_suspicious`.

    Vectorized O(n log n) implementation using numpy searchsorted — safe for
    chunks of any size up to millions of rows.  The original per-row iterrows()
    loop was O(n²) and would stall on chunks ≥ ~5,000 rows.

    If no timestamp column is parsable this is a no-op (both columns remain 0).
    """
    if not _PANDAS_OK or "source_ip" not in df.columns:
        return df

    df = df.copy()
    df["conn_per_min"] = 0
    df["tw_suspicious"] = False

    if "timestamp" not in df.columns:
        return df

    try:
        import numpy as np  # local — safe inside executor

        ts = pd.to_datetime(df["timestamp"], errors="coerce")
        if ts.isna().all():
            return df

        df["_ts"] = ts
        window_ns = int(pd.Timedelta(window).total_seconds() * 1_000_000_000)  # nanoseconds

        result_counts = pd.Series(0, index=df.index, dtype=int)

        for ip, group in df.groupby("source_ip", dropna=True):
            valid = group.dropna(subset=["_ts"])
            if valid.empty:
                continue
            sorted_valid = valid.sort_values("_ts")
            # Convert to int64 nanoseconds for fast binary search
            times_ns = sorted_valid["_ts"].astype("int64").values

            # For each t[i], find how many t[j] satisfy t[i]-window <= t[j] <= t[i].
            # Since the array is sorted: left = first index where t[j] >= t[i]-window.
            # count = i - left + 1  (includes self)
            left_idxs = np.searchsorted(times_ns, times_ns - window_ns, side="left")
            counts    = np.arange(len(times_ns), dtype=int) - left_idxs + 1

            result_counts.loc[sorted_valid.index] = counts

        df["conn_per_min"] = result_counts
        df["tw_suspicious"] = df["conn_per_min"] > 30
        df.drop(columns=["_ts"], inplace=True, errors="ignore")
    except Exception:
        logger.debug("time_window_correlate: %s", traceback.format_exc())
        df.drop(columns=["_ts"], inplace=True, errors="ignore")

    return df


# ── Tier 1: Heuristic Filter ──────────────────────────────────────────────────

_SUSPICIOUS_PORTS = frozenset({
    20, 21, 22, 23, 25, 53, 110, 135, 137, 138, 139, 143, 161,
    389, 443, 445, 514, 636, 1080, 1433, 1521, 3306, 3389,
    4444, 4899, 5432, 5555, 5900, 6667, 6881, 8080, 8443,
    9001, 9200, 27017, 50000,
})

_BENIGN_LABELS = frozenset({
    "benign", "normal", "background", "legitimate", "unknown", "none", "",
})

_ATTACK_PATTERN = (
    r"attack|scan|brute|bot|ddos|dos|exploit|flood|fuzz|inject|"
    r"malware|recon|trojan|worm|shell|ransom|lateral|exfil|infiltrat|heartbleed"
)


def tier1_filter(df: "pd.DataFrame", schema: str) -> "pd.DataFrame":
    """
    Heuristic pre-filter: drop clearly benign rows, keep suspicious ones.
    Adds a `severity` column based on label / port / bytes signals.
    Also sets `tw_suspicious` if time-window correlation fired.
    """
    import pandas as pd  # local — safe inside executor

    mask = pd.Series(False, index=df.index)

    if "label" in df.columns:
        lc       = df["label"].astype(str).str.strip().str.lower()
        non_benign = ~lc.isin(_BENIGN_LABELS)
        has_kw     = lc.str.contains(_ATTACK_PATTERN, na=False, regex=True)
        mask |= (non_benign & has_kw)

    if "dest_port" in df.columns:
        try:
            ports = pd.to_numeric(df["dest_port"], errors="coerce")
            mask |= ports.isin(_SUSPICIOUS_PORTS)
        except Exception:
            pass

    if "bytes_out" in df.columns:
        try:
            bout = pd.to_numeric(df["bytes_out"], errors="coerce")
            mask |= bout > 5_000_000
        except Exception:
            pass

    if schema == "botsv3" and "label" in df.columns:
        lc = df["label"].astype(str).str.lower()
        mask |= lc.isin({"suricata", "pan:threat", "pan:system", "stream:http"})

    # Time-window suspicious flag
    if "tw_suspicious" in df.columns:
        mask |= df["tw_suspicious"].fillna(False).astype(bool)

    flagged = df[mask].copy()
    if flagged.empty:
        return flagged

    def _severity(row: Any) -> str:
        label = str(row.get("label", "")).lower()
        if any(k in label for k in (
            "ddos", "ransom", "heartbleed", "shellshock", "exploit",
            "infiltrat", "dos",
        )):
            return "CRITICAL"
        if any(k in label for k in (
            "brute", "patator", "scan", "bot", "worm", "trojan",
            "lateral", "exfil", "shell",
        )):
            return "HIGH"
        try:
            p = int(float(row.get("dest_port", 0) or 0))
            if p in {445, 3389, 4444, 6667, 9001}:
                return "HIGH"
        except (ValueError, TypeError):
            pass
        try:
            if float(row.get("bytes_out", 0) or 0) > 20_000_000:
                return "HIGH"
        except (ValueError, TypeError):
            pass
        return "MEDIUM"

    flagged["severity"] = flagged.apply(_severity, axis=1)
    return flagged


# ── LODA / shared feature extraction ─────────────────────────────────────────

def _col1(df: "pd.DataFrame", col: str, default: "pd.Series | None" = None) -> "pd.Series":
    """
    Safely retrieve a single column from a DataFrame that may have duplicate headers.

    Splunk/BOTSv3 CSV exports frequently export the same field name twice.
    `df.get("bytes_out")` then returns a DataFrame, and `pd.to_numeric` raises
    `TypeError: arg must be a list, tuple, 1-d array, or Series`.

    This helper always returns a 1-D Series:
      • Column absent  → returns `default` (or a zero Series aligned to df.index)
      • Column present as Series    → returned as-is
      • Column present as DataFrame → first column selected via `.iloc[:, 0]`
    """
    import pandas as pd  # local — safe inside executor

    val = df.get(col)
    if val is None:
        return default if default is not None else pd.Series(0, index=df.index, dtype="float64")
    if isinstance(val, pd.DataFrame):
        return val.iloc[:, 0]
    return val  # type: ignore[return-value]  # already a Series


def _extract_loda_features(df: "pd.DataFrame") -> "pd.DataFrame":
    """
    Extract 4 canonical features for LODA in integer-safe units.

    Feature order matches the Rust guest `loda_features()` function exactly:
      [0] bytes_per_sec_kb  — bytes_out / flow_duration_s / 1024  [KB/s, max 1_000_000]
      [1] packet_count      — packets                             [count, max 1_000_000]
      [2] flow_duration_ms  — flow_duration_µs / 1000            [ms, clamped to 65_535]
      [3] dest_port         — dest_port                           [0–65_535]
    """
    import pandas as pd  # local — safe inside executor

    feats = pd.DataFrame(index=df.index)

    bout = pd.to_numeric(_col1(df, "bytes_out"), errors="coerce").fillna(0.0)

    if "flow_duration" in df.columns:
        fdur_us = pd.to_numeric(_col1(df, "flow_duration"), errors="coerce").fillna(0.0)
        dur_s   = (fdur_us / 1_000_000.0).clip(lower=1e-6)
        bps_kb  = (bout / dur_s / 1024.0).clip(lower=0.0, upper=1_000_000.0)
        feats["flow_duration_ms"] = (fdur_us / 1000.0).clip(lower=0.0, upper=65_535.0)
    else:
        bps_kb = (bout / 1024.0).clip(lower=0.0, upper=1_000_000.0)
        feats["flow_duration_ms"] = 0.0

    feats["bytes_per_sec_kb"] = bps_kb
    feats["packet_count"] = pd.to_numeric(
        _col1(df, "packets"), errors="coerce"
    ).fillna(0.0).clip(lower=0.0, upper=1_000_000.0)
    feats["dest_port"] = pd.to_numeric(
        _col1(df, "dest_port"), errors="coerce"
    ).fillna(0.0).clip(lower=0.0, upper=65_535.0)

    # Reorder to match the feature indices used by the Rust guest: 0,1,2,3
    return feats[["bytes_per_sec_kb", "packet_count", "flow_duration_ms", "dest_port"]]


# ── Tier 1 ML: LODA (per-chunk) ───────────────────────────────────────────────

def tier1_loda_filter(
    df: "pd.DataFrame",
    contamination: float = 0.05,
) -> "pd.DataFrame":
    """
    Per-chunk LODA anomaly detection.

    Trains a fresh LODA model on the current chunk's 4 canonical features and
    returns rows whose mean –log(density) score exceeds the (1 – contamination)
    percentile.

    Replaces the old per-chunk IsolationForest.  Cycle-count advantages in the zkVM:
      • Projection = {-1, 0, +1} dot product → no MUL instructions on RV32IM
      • Bin lookup = linear scan over ~10 contiguous edges → no pointer-jump traversal
      • Deterministic output given fixed _LODA_SEED

    Falls back to an empty DataFrame when numpy is unavailable or the chunk
    has fewer than 20 rows (insufficient histogram statistics).
    """
    if not _NUMPY_OK or not _PANDAS_OK:
        logger.debug("tier1_loda_filter: numpy/pandas unavailable — skipped")
        return df.iloc[0:0]

    feats = _extract_loda_features(df)
    if len(feats) < 20:
        logger.debug("tier1_loda_filter: chunk too small (%d rows) — skipped", len(feats))
        return df.iloc[0:0]

    try:
        X   = feats.values.astype(float)
        rng = _np.random.default_rng(_LODA_SEED)

        # Generate k sparse projection vectors: w_ij ∈ {-1, 0, 1}
        P = _np.zeros((_LODA_K, 4), dtype=_np.int8)
        for i in range(_LODA_K):
            for j in range(4):
                r = rng.random()
                if r < (1.0 - _LODA_SPARSITY) / 2.0:
                    P[i, j] = -1
                elif r < (1.0 - _LODA_SPARSITY):
                    P[i, j] = 1
            if not _np.any(P[i]):          # guarantee ≥ 1 non-zero weight
                P[i, rng.integers(4)] = 1

        scores = _np.zeros(len(X))
        for i in range(_LODA_K):
            w = P[i]
            # Sparse projection — mirrors the Rust match-arm add/subtract
            z = _np.zeros(len(X))
            for j in range(4):
                if w[j] == 1:
                    z += X[:, j]
                elif w[j] == -1:
                    z -= X[:, j]

            edges   = _np.histogram_bin_edges(z, bins=_LODA_N_BINS)
            counts, _ = _np.histogram(z, bins=edges)
            widths  = _np.diff(edges).clip(min=1e-10)
            density = counts / (len(X) * widths)
            score   = -_np.log(density.clip(min=1e-10)).clip(max=50.0)

            bin_idx = _np.searchsorted(edges[1:], z, side="left")
            bin_idx = _np.clip(bin_idx, 0, _LODA_N_BINS - 1)
            scores += score[bin_idx]

        scores      /= _LODA_K
        threshold    = float(_np.percentile(scores, 100.0 * (1.0 - contamination)))
        outlier_mask = scores > threshold
        result = df[outlier_mask].copy()
        if "severity" not in result.columns:
            result["severity"] = "MEDIUM"
        logger.debug(
            "tier1_loda_filter: %d/%d rows flagged (contamination=%.2f)",
            int(outlier_mask.sum()), len(df), contamination,
        )
        return result
    except Exception:
        logger.warning("tier1_loda_filter failed: %s", traceback.format_exc())
        return df.iloc[0:0]


# ── Z-Score Baselining ────────────────────────────────────────────────────────

def zscore_baseline_filter(
    df: "pd.DataFrame",
    z_threshold: float = 3.0,
) -> tuple["pd.DataFrame", dict[str, dict[str, float]]]:
    """
    Compute per-column Z-scores for `bytes_out` and `packets`.

    Returns:
      anomalous_rows — DataFrame of rows with |Z| > z_threshold on any column
      baselines      — dict of {col: {"mean": float, "std": float, "z_threshold": float}}

    Also attaches `z_score_bytes` and `z_score_pkts` columns so `derive_mitre()`
    can use the magnitude to choose between T1498 / T1499 / T1046.
    """
    if not _PANDAS_OK:
        return df.iloc[0:0], {}

    import pandas as pd

    stat_cols = ["bytes_out", "packets"]
    baselines: dict[str, dict[str, float]] = {}
    mask = pd.Series(False, index=df.index)
    z_bytes_series = pd.Series(0.0, index=df.index)
    z_pkts_series  = pd.Series(0.0, index=df.index)

    for col in stat_cols:
        if col not in df.columns:
            continue
        # Guard against duplicate-header CSVs (CICIDS-2017, BOTSv3 Splunk exports)
        # where df[col] returns a DataFrame instead of a Series.
        series = pd.to_numeric(_col1(df, col), errors="coerce").fillna(0.0)
        mean   = float(series.mean())
        std    = float(series.std())
        if std < 1e-9 or math.isnan(std):
            continue
        z = (series - mean).abs() / std
        baselines[col] = {"mean": mean, "std": std, "z_threshold": z_threshold}
        above_thresh = z > z_threshold
        mask |= above_thresh

        if col == "bytes_out":
            z_bytes_series = z
        elif col == "packets":
            z_pkts_series = z

    anomalous = df[mask].copy()
    if not anomalous.empty:
        anomalous["z_score_bytes"] = z_bytes_series[mask].values
        anomalous["z_score_pkts"]  = z_pkts_series[mask].values
        # Assign severity based on z-score magnitude
        def _zsev(row: Any) -> str:
            zb = row.get("z_score_bytes", 0) or 0
            zp = row.get("z_score_pkts",  0) or 0
            if max(zb, zp) > 6.0:
                return "CRITICAL"
            if max(zb, zp) > 4.0:
                return "HIGH"
            return "MEDIUM"
        anomalous["severity"] = anomalous.apply(_zsev, axis=1)

    logger.debug(
        "zscore_baseline_filter: %d/%d rows exceed |Z|>%.1f; baselines=%s",
        mask.sum(), len(df), z_threshold,
        {k: f"μ={v['mean']:.0f} σ={v['std']:.0f}" for k, v in baselines.items()},
    )
    return anomalous, baselines


# ── DDSketch Volumetric Baseliner (Phase 1: Split-Brain Fixed-Point) ─────────

class DDSketchBaseliner:
    """
    Accumulates per-flow bytes/s observations across pipeline chunks using
    the DDSketch quantile sketch (relative_accuracy=1%).

    After all chunks are processed, `threshold_fp14()` returns T — the 14-bit
    fixed-point encoding of the 99th-percentile bytes/s boundary:

        T = floor(p99_bytes_per_sec × 2^14)

    This single integer is written to `pipeline_sessions.ddsketch_threshold_fp14`
    and passed to the Rust zkVM guest via `HostBaselines.ddsketch_threshold_fp14`
    so the guest can execute:

        current_scaled = bytes_per_sec << 14
        is_volumetric  = current_scaled > T

    with no floating-point arithmetic — guaranteeing bit-identical results
    across every RISC-V execution environment.
    """

    def __init__(self) -> None:
        self._sketch = _DDSketch(relative_accuracy=0.01) if _DDSKETCH_OK else None
        self._n      = 0

    def update(self, df: "pd.DataFrame") -> None:
        """
        Add bytes/s values from one normalized chunk to the sketch.

        Computes bytes/s = bytes_out / flow_duration_s per row.
        Falls back to treating bytes_out directly as a rate proxy when
        flow_duration is absent or zero (e.g. BOTSv3 raw-log rows).
        """
        if self._sketch is None or "bytes_out" not in df.columns:
            return

        import pandas as pd  # local — safe inside executor

        bout = pd.to_numeric(df["bytes_out"], errors="coerce").fillna(0.0)

        if "flow_duration" in df.columns:
            # CICIDS-2017: flow_duration is stored in microseconds
            fdur_us = pd.to_numeric(df["flow_duration"], errors="coerce").fillna(0.0)
            dur_s   = (fdur_us / 1_000_000.0).clip(lower=1e-6)
            bps     = (bout / dur_s).clip(lower=0.0)
        else:
            bps = bout.clip(lower=0.0)

        positives = bps[bps > 0]
        if positives.empty:
            return

        # Bulk-add if the sketch supports it (faster for large chunks);
        # fall back to single-add for older ddsketch versions.
        try:
            self._sketch.add_all(positives.tolist())
            self._n += len(positives)
        except AttributeError:
            for v in positives.values:
                self._sketch.add(float(v))
                self._n += 1

    @property
    def sample_count(self) -> int:
        return self._n

    def threshold_fp14(self) -> int:
        """
        Return T = floor(p99_bytes_per_sec × 2^14).

        Returns 0 when:
          - ddsketch is not installed
          - fewer than 100 observations have been added (insufficient for p99)
          - the computed p99 is non-positive
        The zkVM guest treats T == 0 as "no DDSketch context; fall back to
        Z-score baselines or no volumetric check."
        """
        if self._sketch is None or self._n < 100:
            return 0
        try:
            p99 = self._sketch.get_quantile_value(0.99)
        except Exception:
            logger.warning("DDSketch.get_quantile_value failed", exc_info=True)
            return 0
        if p99 is None or p99 <= 0.0:
            return 0
        return int(math.floor(p99 * (1 << 14)))  # T = floor(X_limit × 2^14)


# ── LODA Baseliner (Split-Brain Fixed-Point) ──────────────────────────────────

class LodaBaseliner:
    """
    Lightweight On-line Detector of Anomalies — session-level Split-Brain baseliner.

    Accumulates normalized telemetry rows across pipeline chunks, then fits
    k sparse random projections and a 1D histogram per projection after all chunks.

    After fit(), payload() returns a JSON string suitable for storage in
    pipeline_sessions.loda_payload.  The Rust zkVM guest deserialises this into
    a LodaModel and evaluates Rule 11 (LODA_ANOMALY) without any floating-point.

    Projection weights w_ij ∈ {-1, 0, 1}:
      • Python training:  sparse dot-product via numpy column add/subtract
      • Rust guest eval:  match-arm ADD/SUB — zero MUL instructions on RV32IM

    Histogram bin edges and –log(density) scores are Q14/Q10 encoded so the
    guest compares z_fp14 against integer bin boundaries with no division.
    """

    def __init__(self) -> None:
        self._buffer: list = []
        self._fitted: bool = False
        self._projections: "_np.ndarray | None" = None
        self._bin_edges:   "list | None" = None  # k arrays, each (n_bins+1,)
        self._bin_scores:  "list | None" = None  # k arrays, each (n_bins,)
        self._threshold:   float = 0.0
        self._gen_projections()

    def _gen_projections(self) -> None:
        if not _NUMPY_OK:
            return
        rng = _np.random.default_rng(_LODA_SEED)
        P   = _np.zeros((_LODA_K, 4), dtype=_np.int8)
        for i in range(_LODA_K):
            for j in range(4):
                r = rng.random()
                if r < (1.0 - _LODA_SPARSITY) / 2.0:
                    P[i, j] = -1
                elif r < (1.0 - _LODA_SPARSITY):
                    P[i, j] = 1
            if not _np.any(P[i]):      # guarantee ≥ 1 non-zero weight per vector
                P[i, rng.integers(4)] = 1
        self._projections = P

    def update(self, df: "pd.DataFrame") -> None:
        """Accumulate canonical feature rows from one normalised chunk."""
        if not _NUMPY_OK or not _PANDAS_OK or self._projections is None:
            return
        already = sum(len(r) for r in self._buffer)
        if already >= _MAX_LODA_ROWS:
            return
        feats = _extract_loda_features(df)
        if not feats.empty:
            remaining = _MAX_LODA_ROWS - already
            self._buffer.append(feats.values[:remaining])

    def fit(self) -> None:
        """
        Fit histograms on all accumulated projected data.
        CPU-bound — called inside a thread-pool executor after the chunk loop.
        """
        if not _NUMPY_OK or not self._buffer or self._projections is None:
            return
        try:
            X = _np.vstack(self._buffer)
            if len(X) < 20:
                logger.debug("LodaBaseliner.fit: too few rows (%d) — skipped", len(X))
                return

            bin_edges_list:  list = []
            bin_scores_list: list = []
            all_scores = _np.zeros(len(X), dtype=_np.float64)

            for i in range(_LODA_K):
                w = self._projections[i]

                # Sparse projection — mirrors Rust match-arm add/subtract
                z = _np.zeros(len(X), dtype=_np.float64)
                for j in range(4):
                    if w[j] == 1:
                        z += X[:, j]
                    elif w[j] == -1:
                        z -= X[:, j]

                # 1D histogram
                edges     = _np.histogram_bin_edges(z, bins=_LODA_N_BINS)
                counts, _ = _np.histogram(z, bins=edges)
                widths    = _np.diff(edges).clip(min=1e-10)
                density   = counts / (len(X) * widths)

                # Score = –log(density), capped for numerical stability
                score = -_np.log(density.clip(min=1e-10)).clip(max=50.0)
                bin_edges_list.append(edges)
                bin_scores_list.append(score)

                bin_idx = _np.searchsorted(edges[1:], z, side="left")
                bin_idx = _np.clip(bin_idx, 0, _LODA_N_BINS - 1)
                all_scores += score[bin_idx]

            self._bin_edges  = bin_edges_list
            self._bin_scores = bin_scores_list
            # 95th-percentile of per-sample mean scores → anomaly threshold
            self._threshold = float(_np.percentile(all_scores / _LODA_K, 95))
            self._fitted = True
            logger.info(
                "LodaBaseliner fitted: %d rows, k=%d, n_bins=%d, threshold=%.4f",
                len(X), _LODA_K, _LODA_N_BINS, self._threshold,
            )
        except Exception:
            logger.warning("LodaBaseliner.fit failed: %s", traceback.format_exc())

    @property
    def is_trained(self) -> bool:
        return self._fitted

    def payload(self) -> "str | None":
        """
        Return a JSON string encoding the LODA model in Q14/Q10 fixed-point for
        the Rust zkVM guest, or None if the model has not been trained.

        Encoding:
          projections        — flat i8 array (k × 4), elements ∈ {-1, 0, 1}
          bin_edges_fp14     — floor(real_edge × 2^14); i64; Q14
          bin_scores_fp10    — floor(–log(density) × 2^10); i32; Q10; capped ≥ 0
          anomaly_threshold_fp10 — floor(threshold_mean × k × 2^10)
                               (guest sums k scores; Python threshold is their mean)
        """
        if not self._fitted or self._projections is None:
            return None
        try:
            proj_flat = self._projections.flatten().tolist()

            edges_flat: list[int] = []
            for edges in self._bin_edges:
                for e in edges:
                    edges_flat.append(int(math.floor(e * (1 << 14))))

            scores_flat: list[int] = []
            for scores in self._bin_scores:
                for s in scores:
                    v = int(math.floor(s * (1 << 10)))
                    scores_flat.append(max(0, min(v, 2**31 - 1)))

            # Guest accumulates raw sum across k projections; multiply mean by k
            threshold_fp10 = int(math.floor(self._threshold * _LODA_K * (1 << 10)))

            return json.dumps({
                "k":                      _LODA_K,
                "n_bins":                 _LODA_N_BINS,
                "n_features":             4,
                "projections":            proj_flat,
                "bin_edges_fp14":         edges_flat,
                "bin_scores_fp10":        scores_flat,
                "anomaly_threshold_fp10": threshold_fp10,
            })
        except Exception:
            logger.warning("LodaBaseliner.payload failed: %s", traceback.format_exc())
            return None


# ── CUSUM C2 Beacon Baseliner (Zero-MUL Split-Brain) ─────────────────────────

class CusumBaseliner:
    """
    Zero-MUL Time-Domain CUSUM C2 Beacon Baseliner — Split-Brain implementation.

    Accumulates per-source-IP inter-arrival times across pipeline chunks, then
    calibrates DAS-CUSUM parameters for periodic beaconing detection.

    Stage 0/1 — Multiplierless comb pre-filter (Python host, ADD/SUB only):
        For each source IP, accumulate timestamps chronologically.
        The "comb" is the first-difference Δt[n] = t[n] − t[n-1] — pure subtraction.

    Stage 2 — Epoch-Folded L1 Histogram (Python host):
        For each candidate period P_i (microseconds):
            phase[n]   = t[n] % P_i
            bin_idx[n] = phase[n] // bin_width       (integer division)
            C[j]       = count of observations in bin j
            expected   = N >> shift_val              (bitshift approximates N / n_bins)
            L1 score   = Σ_j | C[j] − expected |   (no MUL — pure ADD/SUB/ABS)

    Stage 3 — DAS-CUSUM accumulator (Rust guest, proved in zkVM):
        S_n[i] = max(0,  S_{n-1}[i]  +  B_n[i]  −  k)
        Alert when S_n[i] > cusum_threshold_fp14

    The payload() method returns static model parameters (k, threshold, drift).
    Per-record B_n scores and CUSUM states are computed on-the-fly via
    b_n_for_ip() / cusum_state_for_ip() when assembling TelemetryInput for STARK proof.
    """

    def __init__(self) -> None:
        # Per-source-IP sorted timestamp lists: {ip: [t_us, ...]}
        self._timestamps: dict[str, list[int]] = {}
        # Running CUSUM state per source IP per period: {ip: [S_0, S_1, S_2]}
        self._cusum_states: dict[str, list[float]] = {}
        self._fitted:        bool  = False
        self._cusum_k:       float = 0.0
        self._cusum_threshold: float = _CUSUM_THRESHOLD

    def update(self, df: "pd.DataFrame") -> None:
        """Accumulate timestamp sequences from one normalised chunk."""
        if not _PANDAS_OK:
            return
        if "timestamp" not in df.columns or "source_ip" not in df.columns:
            return
        try:
            import pandas as pd  # noqa: F811
            ts_col = pd.to_datetime(df["timestamp"], errors="coerce")
            ip_col = df["source_ip"]
            for ip, ts in zip(ip_col, ts_col):
                if ip is None or pd.isna(ts):
                    continue
                ip_s = str(ip)
                if len(self._timestamps) >= _MAX_CUSUM_IPS and ip_s not in self._timestamps:
                    continue
                t_us = int(ts.timestamp() * 1_000_000)
                self._timestamps.setdefault(ip_s, []).append(t_us)
        except Exception:
            logger.warning("CusumBaseliner.update failed: %s", traceback.format_exc())

    def fit(self) -> None:
        """
        Calibrate the CUSUM drift parameter k from accumulated training data.
        k = K_FACTOR × median(L1 scores across all IPs and periods).
        CPU-bound — call inside a thread-pool executor after the chunk loop.
        """
        if not self._timestamps:
            return
        try:
            all_l1: list[float] = []
            for times in self._timestamps.values():
                if len(times) < 4:
                    continue
                times_s = sorted(times)
                for p_us in _CUSUM_PERIODS_US:
                    l1 = self._l1_score(times_s, p_us)
                    if l1 is not None:
                        all_l1.append(l1)

            if not all_l1:
                self._fitted = True
                return

            all_l1.sort()
            median = all_l1[len(all_l1) // 2]
            self._cusum_k = _CUSUM_K_FACTOR * median
            self._fitted = True
            logger.info(
                "CusumBaseliner fitted: %d IPs, median_L1=%.2f, k=%.4f, threshold=%.2f",
                len(self._timestamps), median, self._cusum_k, self._cusum_threshold,
            )
        except Exception:
            logger.warning("CusumBaseliner.fit failed: %s", traceback.format_exc())

    def _l1_score(self, times_us: list[int], period_us: int) -> "float | None":
        """
        Stage 2: Epoch-fold timestamps mod period_us into _CUSUM_N_BINS bins,
        compute L1 distance from uniform using bitshift-approximated expected count.

        Returns the L1 score (float) or None when there are too few observations.
        """
        n = len(times_us)
        if n < 2 or period_us <= 0:
            return None
        bin_width = period_us // _CUSUM_N_BINS
        if bin_width <= 0:
            return None

        counts = [0] * _CUSUM_N_BINS
        for t in times_us:
            phase   = t % period_us
            bin_idx = min(phase // bin_width, _CUSUM_N_BINS - 1)
            counts[bin_idx] += 1

        # Bitshift approximates n // n_bins: mirrors the Rust guest's shift_val.
        shift_val = _CUSUM_N_BINS.bit_length() - 1  # log2(16) = 4
        expected  = n >> shift_val
        return float(sum(abs(c - expected) for c in counts))

    def b_n_for_ip(self, source_ip: str) -> list[int]:
        """
        Compute the per-period Q14-encoded L1 score (B_n) for a given source IP
        using its full accumulated timestamp history.

        Returns k Q14 integers (one per _CUSUM_PERIODS_US).
        Returns all-zeros when fewer than 4 timestamps are available.
        """
        times = self._timestamps.get(source_ip)
        if not times or len(times) < 4:
            return [0] * len(_CUSUM_PERIODS_US)
        times_s = sorted(times)
        result: list[int] = []
        for p_us in _CUSUM_PERIODS_US:
            l1 = self._l1_score(times_s, p_us)
            raw = l1 if l1 is not None else 0.0
            result.append(int(math.floor(raw * (1 << 14))))
        return result

    def cusum_state_for_ip(self, source_ip: str) -> list[int]:
        """
        Return the running Q14-encoded CUSUM state per period for a source IP.
        Returns all-zeros when no prior state exists (new IP or session start).
        """
        states = self._cusum_states.get(source_ip)
        if not states:
            return [0] * len(_CUSUM_PERIODS_US)
        return [int(math.floor(s * (1 << 14))) for s in states]

    def advance_state(self, source_ip: str, b_n_fp14: list[int]) -> None:
        """
        Advance the Python-side CUSUM state by one record — mirrors the Rust guest
        Stage 3 formula.  Call this after building each TelemetryInput so the running
        state stays synchronized between the Python host and the zkVM guest.

        S_n[i] = max(0,  S_{n-1}[i]  +  B_n[i]  −  k)
        """
        k = self._cusum_k if self._fitted else 0.0
        fp14 = 1 << 14
        prev = self._cusum_states.get(source_ip, [0.0] * len(_CUSUM_PERIODS_US))
        self._cusum_states[source_ip] = [
            max(0.0, prev[i] + (b_fp14 / fp14) - k)
            for i, b_fp14 in enumerate(b_n_fp14)
        ]

    @property
    def is_trained(self) -> bool:
        return self._fitted

    def payload(self) -> "str | None":
        """
        Return a JSON string with the static CusumModel parameters for storage
        in pipeline_sessions.cusum_payload.

        The Rust host reads this to reconstruct the static parts of CusumModel
        (drift k, threshold) when assembling per-record TelemetryInput structs.
        Per-record B_n and CUSUM states are computed separately via b_n_for_ip()
        and cusum_state_for_ip().

        Q14 encoding: floor(real_value × 2^14)
        """
        try:
            k_fp14        = int(math.floor(self._cusum_k        * (1 << 14)))
            thresh_fp14   = int(math.floor(self._cusum_threshold * (1 << 14)))
            shift_val     = _CUSUM_N_BINS.bit_length() - 1
            return json.dumps({
                "k":                    len(_CUSUM_PERIODS_US),
                "n_bins":               _CUSUM_N_BINS,
                "shift_val":            shift_val,
                "periods_us":           _CUSUM_PERIODS_US,
                "cusum_k_fp14":         k_fp14,
                "cusum_threshold_fp14": thresh_fp14,
            })
        except Exception:
            logger.warning("CusumBaseliner.payload failed: %s", traceback.format_exc())
            return None


# ── Tier 2/3: MITRE Enrichment ────────────────────────────────────────────────

def tier2_enrich(
    df: "pd.DataFrame",
    baselines: dict[str, dict[str, float]] | None = None,
) -> list[dict]:
    """
    Map each flagged row to a MITRE ATT&CK technique derived from runtime
    signals (label > Z-score > port > volume > protocol).

    If `baselines` is provided (from zscore_baseline_filter), per-row Z-scores
    are computed and passed to derive_mitre() so volumetric anomalies get
    statistically-grounded MITRE assignments.
    """
    import pandas as pd  # noqa: F811

    alerts: list[dict] = []

    # Pre-compute per-column stats if baselines provided
    has_baselines = bool(baselines)
    b_mean_bytes = baselines.get("bytes_out", {}).get("mean", 0) if has_baselines else 0
    b_std_bytes  = baselines.get("bytes_out", {}).get("std",  1) if has_baselines else 1
    b_mean_pkts  = baselines.get("packets",   {}).get("mean", 0) if has_baselines else 0
    b_std_pkts   = baselines.get("packets",   {}).get("std",  1) if has_baselines else 1

    for _, row in df.iterrows():

        def _get(col: str) -> Any:
            v = row.get(col)
            return None if (v is None or (isinstance(v, float) and pd.isna(v))) else v

        label     = str(_get("label") or "").strip()
        dst_port  = _safe_int(_get("dest_port"))
        bytes_out = _safe_float(_get("bytes_out"))
        protocol  = _safe_str(_get("protocol"))

        # Compute Z-scores per row if baselines are available
        z_bytes: float | None = None
        z_pkts:  float | None = None
        if has_baselines:
            # Use pre-attached columns if present (from zscore_baseline_filter)
            if "z_score_bytes" in row.index:
                z_bytes = _safe_float(_get("z_score_bytes"))
            elif bytes_out is not None and b_std_bytes > 0:
                z_bytes = abs(bytes_out - b_mean_bytes) / b_std_bytes

            pkts = _safe_float(_get("packets"))
            if "z_score_pkts" in row.index:
                z_pkts = _safe_float(_get("z_score_pkts"))
            elif pkts is not None and b_std_pkts > 0:
                z_pkts = abs(pkts - b_mean_pkts) / b_std_pkts

        tid, tname = derive_mitre(
            label, dst_port, bytes_out, protocol,
            z_score_bytes=z_bytes,
            z_score_pkts=z_pkts,
        )

        alerts.append({
            "source_ip":       _safe_str(_get("source_ip")),
            "dest_ip":         _safe_str(_get("dest_ip")),
            "dest_port":       dst_port,
            "protocol":        protocol,
            "label":           label or None,
            "severity":        str(_get("severity") or "MEDIUM"),
            "mitre_technique": tid,
            "mitre_name":      tname,
            "bytes_total":     bytes_out,
            "z_score_bytes":   z_bytes,
            "z_score_pkts":    z_pkts,
            "raw_features":    _row_snapshot(row),
        })

    return alerts


# ── Combined Tier 1 Pipeline (heuristic ∪ ML ∪ Z-score) ──────────────────────

def run_tier1_combined(
    df: "pd.DataFrame",
    schema: str,
) -> tuple["pd.DataFrame", dict[str, dict[str, float]]]:
    """
    Run all three Tier 1 detection modes and return the union of flagged rows.

    Returns:
      combined  — DataFrame of all flagged rows (deduplicated by index)
      baselines — Z-score baseline stats (empty dict if sklearn unavailable)
    """
    import pandas as pd

    # Mode A: heuristic rules (always runs)
    heuristic = tier1_filter(df, schema)

    # Mode B: LODA per-chunk anomaly detection (requires numpy)
    ml_flags = tier1_loda_filter(df, contamination=0.05)

    # Mode C: Z-score baselining (always runs if pandas available)
    z_flags, baselines = zscore_baseline_filter(df, z_threshold=3.0)

    # Union — preserve highest severity when a row appears in multiple modes
    combined_idx = (
        set(heuristic.index)
        | set(ml_flags.index)
        | set(z_flags.index)
    )

    if not combined_idx:
        return df.iloc[0:0], baselines

    combined = df.loc[sorted(combined_idx)].copy()

    # Severity: take the maximum across all modes that flagged the row
    sev_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": -1}

    def _best_sev(idx: int) -> str:
        candidates = []
        if idx in heuristic.index:
            candidates.append(heuristic.at[idx, "severity"] if "severity" in heuristic.columns else "MEDIUM")
        if idx in ml_flags.index:
            candidates.append(ml_flags.at[idx, "severity"] if "severity" in ml_flags.columns else "MEDIUM")
        if idx in z_flags.index:
            candidates.append(z_flags.at[idx, "severity"] if "severity" in z_flags.columns else "MEDIUM")
        return max(candidates, key=lambda s: sev_order.get(s, 0)) if candidates else "MEDIUM"

    combined["severity"] = [_best_sev(i) for i in combined.index]

    # Attach Z-score columns from z_flags where available
    if not z_flags.empty and "z_score_bytes" in z_flags.columns:
        common = combined.index.intersection(z_flags.index)
        combined.loc[common, "z_score_bytes"] = z_flags.loc[common, "z_score_bytes"]
        combined.loc[common, "z_score_pkts"]  = z_flags.loc[common, "z_score_pkts"]

    return combined, baselines


# ── Private helpers ───────────────────────────────────────────────────────────

def _safe_str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return None if s.lower() in ("nan", "none", "null", "") else s


def _safe_int(v: Any) -> int | None:
    try:
        return int(float(v)) if v is not None else None
    except (ValueError, TypeError):
        return None


def _safe_float(v: Any) -> float | None:
    try:
        f = float(v) if v is not None else None
        return None if (f is None or math.isnan(f)) else f
    except (ValueError, TypeError):
        return None


def _row_snapshot(row: Any) -> str:
    keep = ("source_ip", "dest_ip", "dest_port", "protocol",
            "bytes_out", "bytes_in", "packets", "timestamp", "flow_duration")
    out: dict[str, str] = {}
    for k in keep:
        v = row.get(k)
        if v is None:
            continue
        try:
            if isinstance(v, float) and math.isnan(v):
                continue
        except Exception:
            pass
        out[k] = str(v)[:64]
    return json.dumps(out)[:512]


# ── Database: Pipeline Tables ─────────────────────────────────────────────────

_PIPELINE_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=30000;

CREATE TABLE IF NOT EXISTS telemetry_alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT    NOT NULL,
    ingested_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    dataset_type    TEXT    NOT NULL,
    source_ip       TEXT,
    dest_ip         TEXT,
    dest_port       INTEGER,
    protocol        TEXT,
    label           TEXT,
    severity        TEXT    NOT NULL DEFAULT 'HIGH',
    mitre_technique TEXT,
    mitre_name      TEXT,
    bytes_total     REAL,
    z_score_bytes   REAL,
    z_score_pkts    REAL,
    raw_features    TEXT,
    chain_hash      TEXT
);
CREATE INDEX IF NOT EXISTS idx_ta_session   ON telemetry_alerts(session_id);
CREATE INDEX IF NOT EXISTS idx_ta_severity  ON telemetry_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_ta_src       ON telemetry_alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_ta_mitre     ON telemetry_alerts(mitre_technique);

CREATE TABLE IF NOT EXISTS pipeline_sessions (
    session_id               TEXT    PRIMARY KEY,
    filename                 TEXT    NOT NULL,
    dataset_type             TEXT,
    started_at               TEXT    NOT NULL,
    completed_at             TEXT,
    status                   TEXT    NOT NULL DEFAULT 'uploading',
    rows_processed           INTEGER DEFAULT 0,
    alerts_found             INTEGER DEFAULT 0,
    chain_root_hash          TEXT,
    chain_tip_hash           TEXT,
    ciso_summary             TEXT,
    ddsketch_threshold_fp14  INTEGER DEFAULT 0,
    loda_payload             TEXT,
    cusum_payload            TEXT
);
"""


def ensure_pipeline_tables(db_path: str) -> None:
    try:
        with sqlite3.connect(db_path, timeout=30.0) as conn:
            conn.executescript(_PIPELINE_DDL)
            # Schema migration: add column to existing databases that were
            # created before the DDSketch phase.
            try:
                conn.execute(
                    "ALTER TABLE pipeline_sessions "
                    "ADD COLUMN ddsketch_threshold_fp14 INTEGER DEFAULT 0"
                )
            except sqlite3.OperationalError:
                pass  # column already exists — no-op
            try:
                conn.execute(
                    "ALTER TABLE pipeline_sessions ADD COLUMN loda_payload TEXT"
                )
            except sqlite3.OperationalError:
                pass  # column already exists — no-op
            try:
                conn.execute(
                    "ALTER TABLE pipeline_sessions ADD COLUMN cusum_payload TEXT"
                )
            except sqlite3.OperationalError:
                pass  # column already exists — no-op
            # Backward-compat: keep old forest_payload column if present in DB
            try:
                conn.execute(
                    "ALTER TABLE pipeline_sessions ADD COLUMN forest_payload TEXT"
                )
            except sqlite3.OperationalError:
                pass  # already exists from a pre-LODA schema — leave it unused

            # ── telemetry_alerts migrations ───────────────────────────────────
            # Databases created before the ML-upgrade sprint are missing the
            # columns below.  ALTER TABLE ADD COLUMN is idempotent here because
            # SQLite raises OperationalError("duplicate column name") which we
            # swallow.  Any other error is re-raised so real problems are visible.
            _ta_migrations: list[str] = [
                "ALTER TABLE telemetry_alerts ADD COLUMN bytes_total     REAL",
                "ALTER TABLE telemetry_alerts ADD COLUMN z_score_bytes   REAL",
                "ALTER TABLE telemetry_alerts ADD COLUMN z_score_pkts    REAL",
                "ALTER TABLE telemetry_alerts ADD COLUMN raw_features     TEXT",
                "ALTER TABLE telemetry_alerts ADD COLUMN chain_hash       TEXT",
            ]
            for _stmt in _ta_migrations:
                try:
                    conn.execute(_stmt)
                except sqlite3.OperationalError as _exc:
                    if "duplicate column" not in str(_exc).lower():
                        raise  # unexpected error — propagate
        logger.info("Pipeline DB tables ready (WAL mode enabled)")
    except Exception:
        logger.error("ensure_pipeline_tables failed:\n%s", traceback.format_exc())
        raise


@_db_retry
def create_session(db_path: str, session_id: str, filename: str) -> None:
    with sqlite3.connect(db_path, timeout=30.0) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "INSERT OR IGNORE INTO pipeline_sessions (session_id, filename, started_at) "
            "VALUES (?, ?, ?)",
            (session_id, filename, datetime.now(tz=timezone.utc).isoformat()),
        )


@_db_retry
def update_session(db_path: str, session_id: str, **kwargs: Any) -> None:
    if not kwargs:
        return
    cols = ", ".join(f"{k} = ?" for k in kwargs)
    vals = [*kwargs.values(), session_id]
    with sqlite3.connect(db_path, timeout=30.0) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            f"UPDATE pipeline_sessions SET {cols} WHERE session_id = ?",  # noqa: S608
            vals,
        )


@_db_retry
def insert_alerts_batch(
    db_path: str,
    session_id: str,
    dataset_type: str,
    alerts: list[dict],
) -> None:
    if not alerts:
        return
    now = datetime.now(tz=timezone.utc).isoformat()

    def _input_hash(a: dict) -> str:
        # Deterministic SHA-256 of the alert's raw telemetry fields — mirrors the
        # input_hash that the Rust zkVM guest computes from bincode(TelemetryInput).
        # Uniquely binds each committed row to its source data without calling the
        # guest inline (which is reserved for the STARK proof flow).
        blob = json.dumps({
            "src":      a.get("source_ip") or "",
            "dst":      a.get("dest_ip") or "",
            "port":     a.get("dest_port") or 0,
            "proto":    a.get("protocol") or "",
            "features": a.get("raw_features") or "",
        }, sort_keys=True).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    rows = [
        (
            session_id, now, dataset_type,
            a.get("source_ip"), a.get("dest_ip"), a.get("dest_port"),
            a.get("protocol"), a.get("label"), a.get("severity", "HIGH"),
            a.get("mitre_technique"), a.get("mitre_name"),
            a.get("bytes_total"), a.get("z_score_bytes"), a.get("z_score_pkts"),
            a.get("raw_features"), _input_hash(a),
        )
        for a in alerts
    ]
    with sqlite3.connect(db_path, timeout=30.0) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executemany(
            """
            INSERT INTO telemetry_alerts
              (session_id, ingested_at, dataset_type, source_ip, dest_ip, dest_port,
               protocol, label, severity, mitre_technique, mitre_name,
               bytes_total, z_score_bytes, z_score_pkts, raw_features, chain_hash)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            rows,
        )


# ── CISO Summary Metrics ──────────────────────────────────────────────────────

def compute_ciso_summary(db_path: str, session_id: str) -> dict:
    """Compute analyst-value metrics from a completed pipeline session."""
    try:
        with sqlite3.connect(db_path, timeout=30.0) as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM telemetry_alerts WHERE session_id = ?",
                (session_id,),
            ).fetchone()[0]

            by_sev = dict(conn.execute(
                "SELECT severity, COUNT(*) FROM telemetry_alerts "
                "WHERE session_id = ? GROUP BY severity",
                (session_id,),
            ).fetchall())

            top_techniques = conn.execute(
                "SELECT mitre_technique, mitre_name, COUNT(*) AS cnt "
                "FROM telemetry_alerts WHERE session_id = ? "
                "GROUP BY mitre_technique ORDER BY cnt DESC LIMIT 8",
                (session_id,),
            ).fetchall()

            top_src_ips = conn.execute(
                "SELECT source_ip, COUNT(*) AS cnt "
                "FROM telemetry_alerts "
                "WHERE session_id = ? AND source_ip IS NOT NULL "
                "GROUP BY source_ip ORDER BY cnt DESC LIMIT 10",
                (session_id,),
            ).fetchall()

            top_labels = conn.execute(
                "SELECT label, COUNT(*) AS cnt "
                "FROM telemetry_alerts "
                "WHERE session_id = ? AND label IS NOT NULL "
                "GROUP BY label ORDER BY cnt DESC LIMIT 6",
                (session_id,),
            ).fetchall()

            # ML signal summary: average Z-scores where detected
            ml_stats_row = conn.execute(
                "SELECT AVG(z_score_bytes), AVG(z_score_pkts), "
                "COUNT(CASE WHEN z_score_bytes > 3 THEN 1 END) "
                "FROM telemetry_alerts WHERE session_id = ?",
                (session_id,),
            ).fetchone()

    except Exception:
        logger.error("compute_ciso_summary failed:\n%s", traceback.format_exc())
        return {"total_alerts": 0, "by_severity": {}, "top_techniques": [],
                "top_attacker_ips": [], "top_labels": [],
                "analyst_hours_saved": 0, "cost_avoided_usd": 0}

    crit = by_sev.get("CRITICAL", 0)
    high = by_sev.get("HIGH", 0)
    med  = by_sev.get("MEDIUM", 0)

    analyst_hours = round(crit * 2.0 + high * 0.75 + med * 0.25, 1)
    cost_avoided  = crit * 500 + high * 150 + med * 50

    ml_stats = {
        "avg_z_score_bytes":  round(float(ml_stats_row[0] or 0), 2),
        "avg_z_score_pkts":   round(float(ml_stats_row[1] or 0), 2),
        "z_score_detections": int(ml_stats_row[2] or 0),
    }

    return {
        "total_alerts":        total,
        "by_severity":         by_sev,
        "top_techniques":      [{"id": t[0], "name": t[1], "count": t[2]} for t in top_techniques],
        "top_attacker_ips":    [{"ip": r[0], "count": r[1]} for r in top_src_ips],
        "top_labels":          [{"label": r[0], "count": r[1]} for r in top_labels],
        "analyst_hours_saved": analyst_hours,
        "cost_avoided_usd":    cost_avoided,
        "ml_stats":            ml_stats,
    }
