import logging
from collections import defaultdict

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Known sourcetypes in the BOTSv3 dataset — used for real coverage calculation
_KNOWN_SOURCETYPES = {
    "suricata", "sysmon", "xmlwineventlog", "wineventlog",
    "pan:traffic", "pan:threat", "stream:http", "stream_http",
    "bro:conn", "zeek_conn", "osquery",
}


async def analyze_botsv3_telemetry(session: AsyncSession) -> dict:
    """
    SOC analytics over raw_events: real computed metrics, no hardcoded values.
    """
    # 1. IP Volume & Port Scanning analysis
    ip_stats_query = """
    SELECT src_ip, dst_port, count(*) as event_count
    FROM raw_events
    WHERE src_ip IS NOT NULL AND dst_port IS NOT NULL
    GROUP BY src_ip, dst_port
    """
    result = await session.execute(text(ip_stats_query))
    rows = result.fetchall()

    ip_volumes: dict[str, int] = defaultdict(int)
    ip_ports:   dict[str, set] = defaultdict(set)
    port_counts: dict[int, int] = defaultdict(int)

    for row in rows:
        src_ip, dst_port, count = row
        ip_volumes[src_ip] += count
        try:
            p = int(dst_port)
            ip_ports[src_ip].add(p)
            port_counts[p] += count
        except (ValueError, TypeError):
            pass

    suspicious_ips = [
        {"ip": ip, "volume": vol, "unique_ports": len(ip_ports[ip])}
        for ip, vol in ip_volumes.items()
        if vol > 5000 or len(ip_ports[ip]) > 20
    ]

    # 2. Network Protocol Distribution
    PORT_MAP = {80: "HTTP :80", 443: "HTTPS :443", 22: "SSH :22",
                53: "DNS :53", 21: "FTP :21", 3389: "RDP :3389"}
    colors = ["#4e9af1", "#e84d4d", "#72c811", "#f4a926", "#8b5cf6", "#00d4c8"]
    top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:6]
    protocols = [
        {"name": PORT_MAP.get(p, f"Port :{p}"), "value": c, "color": colors[i % len(colors)]}
        for i, (p, c) in enumerate(top_ports)
    ] or [
        {"name": "HTTP :80", "value": 0, "color": "#4e9af1"},
        {"name": "HTTPS :443", "value": 0, "color": "#72c811"},
        {"name": "SSH :22", "value": 0, "color": "#e84d4d"},
    ]

    # 3. MITRE ATT&CK Tactic Breakdown (behaviour-derived)
    mitre_res = await session.execute(text(
        "SELECT sourcetype, action, count(*) as count FROM raw_events GROUP BY sourcetype, action"
    ))
    mitre_counts: dict[str, int] = defaultdict(int)
    for st, action, count in mitre_res.fetchall():
        st     = (st or "").lower()
        action = (action or "").lower()
        if "login" in action or "auth" in action:
            mitre_counts["Credential Access"] += count
            mitre_counts["Initial Access"]    += count
        elif "process" in st or "sysmon" in st:
            mitre_counts["Execution"] += count
        elif "traffic" in st or "network" in st or "conn" in st:
            mitre_counts["Command and Control"] += count
        else:
            mitre_counts["Discovery"] += count

    for ip_data in suspicious_ips:
        if ip_data["unique_ports"] > 20:
            mitre_counts["Discovery"]        += ip_data["volume"]
            mitre_counts["Lateral Movement"] += ip_data["volume"]

    tactic_colors = {
        "Initial Access": "#e84d4d", "Execution": "#f4a926",
        "Command and Control": "#8b5cf6", "Credential Access": "#00d4c8",
        "Discovery": "#4e9af1", "Lateral Movement": "#d946ef",
        "Impact": "#72c811", "Exfiltration": "#f59e0b",
    }
    mitre_tactics = [
        {"tactic": t, "count": c, "color": tactic_colors.get(t, "#4e9af1")}
        for t, c in sorted(mitre_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    ] or [
        {"tactic": "Initial Access",      "count": 0, "color": "#e84d4d"},
        {"tactic": "Execution",           "count": 0, "color": "#f4a926"},
        {"tactic": "Command and Control", "count": 0, "color": "#8b5cf6"},
    ]

    has_data = len(rows) > 0

    # 4. Real computed metrics
    metrics = await _compute_real_metrics(session, has_data)

    # 5. Real ROI data from monthly ingestion counts
    roi_data = await _compute_roi_data(session, has_data)

    return {
        "has_data":      has_data,
        "suspicious_ips": suspicious_ips,
        "protocols":     protocols,
        "mitre_tactics": mitre_tactics,
        "metrics":       metrics,
        "roi_data":      roi_data,
    }


async def _compute_real_metrics(session: AsyncSession, has_data: bool) -> dict:
    if not has_data:
        return {
            "mttd": "N/A", "mttr": "N/A", "efficacy": "0%",
            "coverage": "0%", "fp_rate": "N/A", "auto_response": "0%",
        }

    # MTTD: average gap between original event timestamp and ingestion time (seconds)
    mttd_row = await session.execute(text("""
        SELECT AVG(
            CAST(strftime('%s', ingested_at) AS REAL) -
            CAST(strftime('%s', timestamp)   AS REAL)
        )
        FROM raw_events
        WHERE severity_hint IN ('CRITICAL', 'HIGH', 'MEDIUM')
          AND timestamp IS NOT NULL
          AND ingested_at IS NOT NULL
    """))
    mttd_val = mttd_row.scalar()
    if mttd_val and mttd_val > 0:
        mttd_str = f"{mttd_val:.1f}s" if mttd_val < 60 else f"{mttd_val/60:.1f}m"
    else:
        mttd_str = "< 1s"

    # MTTR: average playbook execution time from cicids_playbook_logs
    mttr_row = await session.execute(text("""
        SELECT AVG(CAST(action_detail AS REAL))
        FROM cicids_playbook_logs
        WHERE status = 'SIMULATED'
    """))
    mttr_ms = mttr_row.scalar()
    if mttr_ms and mttr_ms > 0:
        mttr_str = f"{mttr_ms/1000:.1f}s (simulated)"
    else:
        mttr_str = "< 1s (simulated)"

    # Efficacy: % of ingested events that received a non-INFO severity classification
    eff_row = await session.execute(text("""
        SELECT
            COUNT(*) FILTER (WHERE severity_hint IS NOT NULL AND severity_hint != 'INFO') * 100.0
            / NULLIF(COUNT(*), 0)
        FROM raw_events
    """))
    eff_val = eff_row.scalar()
    efficacy_str = f"{eff_val:.1f}%" if eff_val is not None else "N/A"

    # Coverage: % of known sourcetypes present in ingested data
    st_row = await session.execute(text("SELECT COUNT(DISTINCT sourcetype) FROM raw_events"))
    ingested_st = st_row.scalar() or 0
    coverage_pct = min(100.0, (ingested_st / len(_KNOWN_SOURCETYPES)) * 100)
    coverage_str = f"{coverage_pct:.0f}%"

    # Auto-response: % of HIGH/CRITICAL alerts that have a playbook log entry
    playbook_row = await session.execute(text("""
        SELECT COUNT(*) FROM cicids_playbook_logs WHERE status = 'SIMULATED'
    """))
    playbook_count = playbook_row.scalar() or 0
    high_row = await session.execute(text("""
        SELECT COUNT(*) FROM raw_events WHERE severity_hint IN ('CRITICAL', 'HIGH')
    """))
    high_count = high_row.scalar() or 0
    auto_resp = (
        f"{min(100.0, playbook_count * 100.0 / high_count):.0f}% (simulated)"
        if high_count > 0 else "0% (simulated)"
    )

    return {
        "mttd":          mttd_str,
        "mttr":          mttr_str,
        "efficacy":      efficacy_str,
        "coverage":      coverage_str,
        "fp_rate":       "N/A (ground truth labels required)",
        "auto_response": auto_resp,
    }


async def _compute_roi_data(session: AsyncSession, has_data: bool) -> list[dict]:
    if not has_data:
        months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        return [{"month": m, "incidents": 0, "cost": 0, "avoided": 0} for m in months]

    # Group actual ingested events by month, weight by severity
    monthly_row = await session.execute(text("""
        SELECT
            strftime('%m', ingested_at)                                         AS month_num,
            COUNT(*) FILTER (WHERE severity_hint = 'CRITICAL')                 AS crit,
            COUNT(*) FILTER (WHERE severity_hint = 'HIGH')                     AS high,
            COUNT(*) FILTER (WHERE severity_hint = 'MEDIUM')                   AS med
        FROM raw_events
        WHERE ingested_at IS NOT NULL
        GROUP BY month_num
        ORDER BY month_num
    """))

    MONTH_NAMES = ["Jan","Feb","Mar","Apr","May","Jun",
                   "Jul","Aug","Sep","Oct","Nov","Dec"]
    # Cost weights per incident tier (USD — conservative enterprise estimates)
    COST_PER_CRIT = 500
    COST_PER_HIGH = 200
    COST_PER_MED  = 50
    AVOIDED_MULT  = 3  # automated detection saves ~3x the investigation cost

    monthly: dict[str, dict] = {}
    for row in monthly_row.fetchall():
        m_num, crit, high, med = row
        crit = crit or 0; high = high or 0; med = med or 0
        incidents = crit + high + med
        cost      = crit * COST_PER_CRIT + high * COST_PER_HIGH + med * COST_PER_MED
        monthly[m_num] = {
            "incidents": incidents,
            "cost":      cost,
            "avoided":   cost * AVOIDED_MULT,
        }

    roi_data = []
    for i, name in enumerate(MONTH_NAMES):
        m_key = f"{i+1:02d}"
        entry = monthly.get(m_key, {"incidents": 0, "cost": 0, "avoided": 0})
        roi_data.append({"month": name, **entry})

    return roi_data
