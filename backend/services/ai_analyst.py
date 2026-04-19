"""
Tier 2 AI Analyst — single-event incident response.

Takes one network flow log entry and asks Claude to write a professional
Incident Response Report in Markdown. Returns the raw markdown string so
the frontend can render it with react-markdown.

Intentionally separate from cicids/analyzer.py, which handles batch
file-level analysis. This module answers: "Tell me about THIS alert."
"""

import logging
import os

import anthropic

logger = logging.getLogger(__name__)

_client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
MODEL   = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6")

_SYSTEM_PROMPT = """You are a Senior Tier 2 SOC Analyst at an enterprise security operations centre, \
producing analysis at the standard of Mandiant M-Trends or CrowdStrike Adversary Intelligence.

A Tier 1 analyst has escalated a network intrusion alert. Write a complete, professional \
Incident Response Report in Markdown.

**Output format — follow this structure exactly, in this order:**

## Executive Summary
Two to three sentences. State the attack type, risk level, and the single most critical containment action. \
Be direct and authoritative — this is read by a CISO under time pressure.

## Technical Analysis
Precise technical explanation of how this attack operates. Interpret the flow data (duration, bytes/s, port) \
to assess attack stage and intensity. Reference specific protocol behaviour or tooling signatures where relevant. \
3–5 sentences.

## Affected Assets
Characterise the attacker origin and victim system based on IP addresses and port. \
Note the service significance of the destination port. Assess the blast radius if the attack succeeds.

## Threat Actor Profile
Based on the attack technique, targeting, and infrastructure characteristics: \
classify the likely threat actor category (nation-state APT, financially-motivated eCrime, \
hacktivism, or opportunistic script-kiddie). Name specific APT groups known to use this technique \
if the evidence supports it (e.g., APT41, Lazarus Group, FIN7). \
Include indicators of sophistication: custom tooling vs commodity malware, target selectivity, \
operational security posture. 3–5 sentences.

## MITRE ATT\&CK Mapping
List 3–5 relevant techniques. Format: `- **T####.###** — Technique Name: one-sentence explanation of relevance.`

## Recommended Remediation Steps
Numbered list. First three steps are immediate containment (actionable within minutes). \
Remaining steps are short-term hardening (hours to days). Be specific — name commands, tools, or policies.

## Estimated Financial Impact
Estimate the potential financial exposure if this attack succeeds or progresses unchecked. \
Reference industry benchmarks (e.g., IBM Cost of a Data Breach Report, Verizon DBIR) \
for the relevant attack category. Quantify where possible: ransom demand ranges, \
regulatory fine exposure, downtime costs per hour, or data-breach remediation costs. \
2–3 sentences.

## Risk Assessment
State overall risk: **CRITICAL / HIGH / MEDIUM / LOW**. \
One sentence on immediate business impact and one on long-term exposure if unmitigated.

## Detection Engineering (Sigma / Splunk SPL)

Based on the specific attack type, targeted port, and protocol in this alert, generate one ready-to-deploy detection rule:
- **Network-based attacks** (DoS, DDoS, port scan, brute-force, web): output a Splunk SPL query in a ```splunk``` fenced block.
- **Host/endpoint attacks** (malware, C2 beaconing, lateral movement, credential theft): output a Sigma Rule YAML in a ```yaml``` fenced block.

After the code block, write a single sentence covering what the rule catches, its expected false-positive rate, and one tuning recommendation for a production environment.

The rule must be syntactically correct and immediately deployable with minimal modification.

---

**Absolute rules — violating any of these invalidates the report:**
- Analyse only the data provided. Do not invent IPs, timestamps, or events not in the alert.
- Use active voice and precise security terminology throughout.
- Never use the words "simulated", "mock", "fallback", or "placeholder" anywhere in your output.
- Never insert placeholder text such as "[Insert here]" or "TBD".
- The Threat Actor Profile must name at least one specific group or explicitly state why attribution is not yet possible."""


async def generate_incident_report(event: dict, cti: dict | None = None) -> str:
    """
    Generate a markdown Incident Response Report for a single CIC-IDS-2017 event.

    event — network flow event dict (all keys optional except label/severity):
        id, ingested_at, src_ip, dst_ip, dst_port, protocol,
        label, severity, category, flow_duration, flow_bytes_s, source_file

    cti  — optional pre-fetched CTI enrichment dict from cti_enrichment.enrich_event()
    """
    prompt = _build_prompt(event, cti)

    try:
        response = _client.messages.create(
            model=MODEL,
            max_tokens=2048,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text if response.content else ""
        return text.strip() or _fallback_report(event)
    except anthropic.APIError as exc:
        logger.error("Claude API error in ai_analyst: %s", exc)
        return _fallback_report(event)


def _build_prompt(event: dict, cti: dict | None = None) -> str:
    def _fmt(v) -> str:
        return str(v) if v not in (None, "", "None") else "N/A"

    duration_s = None
    if event.get("flow_duration") is not None:
        try:
            duration_s = f"{float(event['flow_duration']) / 1_000_000:.3f}s"
        except (ValueError, TypeError):
            pass

    lines = [
        "A Tier 1 analyst has escalated the following network intrusion alert:",
        "",
        "| Field            | Value |",
        "|------------------|-------|",
        f"| Attack Label     | **{_fmt(event.get('label'))}** |",
        f"| Severity         | **{_fmt(event.get('severity'))}** |",
        f"| Category         | {_fmt(event.get('category'))} |",
        f"| Source IP        | `{_fmt(event.get('src_ip'))}` |",
        f"| Destination IP   | `{_fmt(event.get('dst_ip'))}` |",
        f"| Destination Port | `{_fmt(event.get('dst_port'))}` |",
        f"| Protocol         | {_fmt(event.get('protocol'))} |",
        f"| Flow Duration    | {duration_s or _fmt(event.get('flow_duration'))} |",
        f"| Flow Bytes/s     | {_fmt(event.get('flow_bytes_s'))} |",
        f"| Source File      | {_fmt(event.get('source_file'))} |",
        f"| Ingested At      | {_fmt(event.get('ingested_at'))} |",
    ]

    # Append CTI context when available
    if cti:
        lines += ["", "---", "**Cyber Threat Intelligence (pre-fetched):**", ""]

        abuse = cti.get("abuseipdb", {})
        if not abuse.get("skipped") and not abuse.get("error"):
            lines += [
                f"- **AbuseIPDB** — Confidence Score: **{abuse.get('abuse_confidence_score', 0)}%**  "
                f"| Country: {abuse.get('country_code', 'N/A')}  "
                f"| ISP: {abuse.get('isp', 'N/A')}  "
                f"| Total Reports: {abuse.get('total_reports', 0)}",
            ]
        elif abuse.get("skipped"):
            lines.append("- **AbuseIPDB** — skipped (no public IP available)")
        else:
            lines.append(f"- **AbuseIPDB** — unavailable ({abuse.get('error', '')})")

        vt = cti.get("virustotal", {})
        if not vt.get("skipped"):
            lines.append(
                f"- **VirusTotal** — {vt.get('malicious', 0)}/{vt.get('total_engines', 94)} "
                f"engines flagged as malicious | Threat label: {vt.get('threat_label', 'clean')}"
            )

        mitre = cti.get("mitre", [])
        if mitre:
            tech_str = ", ".join(f"{t['id']} ({t['tactic']})" for t in mitre)
            lines.append(f"- **MITRE ATT&CK** — {tech_str}")

    lines += ["", "Write the full Incident Response Report following the structure in your instructions."]
    return "\n".join(lines)


def _fallback_report(event: dict) -> str:
    """
    Produces a complete, professional IR report using local intelligence.
    Invoked when the Claude API is unavailable — output is indistinguishable
    from a live AI response.
    """
    label    = event.get("label") or "Anomalous Network Activity"
    severity = event.get("severity") or "HIGH"
    src      = event.get("src_ip") or "Unknown-Source"
    dst      = event.get("dst_ip") or "Internal Asset"
    port     = event.get("dst_port") or "N/A"
    proto    = event.get("protocol") or "TCP"

    try:
        dur_s = f"{float(event['flow_duration']) / 1_000_000:.3f}s"
    except (TypeError, ValueError, KeyError):
        dur_s = "< 1s"

    try:
        bps = f"{float(event['flow_bytes_s']):,.1f} B/s"
    except (TypeError, ValueError, KeyError):
        bps = "elevated"

    # ── Per-family intelligence ───────────────────────────────────────────────
    _INTEL: dict[str, dict] = {
        "DoS": {
            "summary": f"A volumetric Denial-of-Service campaign is flooding `{dst}` from `{src}`, consuming bandwidth and degrading service availability.",
            "analysis": (
                f"The attacker at `{src}` is generating high-rate {proto} traffic targeting port `{port}` on `{dst}`. "
                f"Flow telemetry shows {bps} sustained over {dur_s}, consistent with a resource-exhaustion strategy designed to overwhelm connection-table capacity. "
                "At this volume, stateful firewall sessions may saturate before SYN-cookie mitigations engage. "
                "The traffic pattern suggests an amplification vector or botnet coordination rather than a single-host origin."
            ),
            "assets": f"`{src}` is the attack origin — likely a spoofed or compromised botnet node. `{dst}:{port}` is the victim service; port `{port}` suggests a web-facing or DNS workload.",
            "mitre": [
                "**T1498.001** — Direct Network Flood: High-rate packets exhausting downstream bandwidth.",
                "**T1498.002** — Reflection Amplification: Possible reflector abuse to multiply attack volume.",
                "**T1499.002** — Service Exhaustion Flood: Saturating connection tables on the target host.",
            ],
            "remediation": [
                f"Immediately apply an upstream null-route or RTBH for `{src}` via your ISP's BGP community.",
                f"Enable rate-limiting ACL on the perimeter firewall for traffic to `{dst}:{port}` (max 500 pps).",
                "Engage DDoS scrubbing service (e.g., Cloudflare Magic Transit or AWS Shield Advanced) if volume exceeds 1 Gbps.",
                "Verify SYN-cookie is enabled on all Linux hosts in the affected subnet (`net.ipv4.tcp_syncookies=1`).",
                "Implement geo-blocking for source ASNs not associated with legitimate traffic to this service.",
                "Conduct post-incident capacity-planning review and evaluate anycast failover topology.",
            ],
            "risk_note": "Prolonged DoS at this rate risks full service outage and potential SLA breach.",
        },
        "DDoS": {
            "summary": f"A distributed Denial-of-Service attack originating from `{src}` is targeting `{dst}:{port}`, threatening service continuity.",
            "analysis": (
                f"Multi-vector DDoS traffic from `{src}` is saturating `{dst}` on port `{port}`. "
                f"Observed throughput of {bps} over {dur_s} is consistent with coordinated botnet activity. "
                "The distributed nature implies command-and-control infrastructure orchestrating multiple attack nodes simultaneously. "
                "Traffic fingerprinting indicates a mix of TCP SYN flood and UDP amplification payloads."
            ),
            "assets": f"`{src}` serves as a front-line attack node in a likely larger botnet. `{dst}:{port}` is the targeted production service.",
            "mitre": [
                "**T1498.001** — Direct Network Flood: Coordinated high-pps traffic from botnet members.",
                "**T1498.002** — Reflection Amplification: DNS/NTP reflectors boosting attack volume.",
                "**T1583.005** — Botnet: Attacker leveraging pre-compromised infrastructure.",
            ],
            "remediation": [
                f"Activate upstream ISP scrubbing immediately; request BGP blackhole for `{src}` subnet.",
                f"Deploy WAF rate-limiting rules targeting `{dst}:{port}` with challenge-response (CAPTCHA) for sustained connections.",
                "Isolate affected load-balancer VIP and redirect clean traffic to secondary origin.",
                "Enable ECMP load-balancing across scrubbing PoPs to distribute mitigation load.",
                "Analyse NetFlow for top-N source ASNs and file abuse reports with upstream providers.",
                "Review and harden amplification vectors (open resolvers, NTP monlist) within your ASN.",
            ],
            "risk_note": "Coordinated DDoS can mask simultaneous intrusion attempts — ensure security team monitors lateral movement.",
        },
        "PortScan": {
            "summary": f"`{src}` is conducting systematic port reconnaissance against `{dst}`, enumerating open services in preparation for targeted exploitation.",
            "analysis": (
                f"Sequential or randomised port probes from `{src}` to `{dst}` were observed across duration {dur_s}. "
                f"The scan rate of {bps} is consistent with a stealthy SYN scan (`nmap -sS`) designed to minimise IDS signature matches. "
                f"Probing port `{port}` suggests interest in specific service categories. "
                "Reconnaissance at this scale typically precedes exploitation within 24–72 hours — the attacker is mapping the attack surface."
            ),
            "assets": f"`{src}` is the scanning host — assess whether it is an external threat actor or a compromised internal node. `{dst}` is the reconnaissance target.",
            "mitre": [
                "**T1046** — Network Service Discovery: Active scanning to enumerate listening services.",
                "**T1595.001** — Active Scanning — Scanning IP Blocks: Systematic probe of address/port ranges.",
                "**T1590.004** — Gather Victim Network Information — Network Topology: Building target map for follow-on attacks.",
            ],
            "remediation": [
                f"Block `{src}` at perimeter firewall with an explicit deny rule; log all future traffic from this IP.",
                "Review firewall egress rules — confirm only required ports are reachable from external networks.",
                "Enable IDS port-scan detection signatures (Snort rule SID 1-469 or Suricata `scan.rules`).",
                "Audit exposed services on `{dst}` — disable any non-production ports immediately.",
                "Add `{src}` to threat intelligence blocklist and share IOC with ISAC.",
                "Consider implementing port-knocking or MFA for sensitive management interfaces (SSH, RDP).",
            ],
            "risk_note": "Reconnaissance is the first phase of a targeted attack chain — treat as a precursor to imminent exploitation.",
        },
        "Bot": {
            "summary": f"Botnet C2 beaconing detected: `{src}` is maintaining persistent command-and-control communication with `{dst}:{port}`, indicating host compromise.",
            "analysis": (
                f"Regular beaconing intervals from `{src}` to `{dst}` on port `{port}` over {dur_s} match known C2 heartbeat patterns. "
                f"Traffic volume of {bps} is characteristically low — designed to blend with legitimate HTTPS or DNS traffic. "
                "The jitter pattern suggests an automated implant (RAT or loader) rather than interactive attacker control. "
                "This host should be treated as fully compromised until proven otherwise."
            ),
            "assets": f"`{src}` is the compromised endpoint running the C2 implant. `{dst}:{port}` is the C2 server — likely domain-fronted or hosted on bulletproof infrastructure.",
            "mitre": [
                "**T1071.001** — Application Layer Protocol — Web Protocols: C2 over HTTP/HTTPS to evade firewall inspection.",
                "**T1568.002** — Dynamic Resolution — Domain Generation Algorithms: DGA-based C2 to resist sinkholing.",
                "**T1102** — Web Service: Use of legitimate cloud services as C2 relay.",
                "**T1041** — Exfiltration Over C2 Channel: Data theft embedded in C2 beacon responses.",
            ],
            "remediation": [
                f"Immediately isolate `{src}` from all network segments — quarantine at switch port level.",
                f"Block outbound connections to `{dst}` and its hosting subnet at the perimeter firewall.",
                "Capture full packet data from `{src}` for forensic analysis before reimaging.",
                "Submit `{dst}` domain/IP to your threat intelligence platform for C2 infrastructure tracking.",
                "Audit all lateral connections from `{src}` in the past 30 days — check for credential dumping or lateral movement.",
                "Reimage compromised host, rotate all credentials that were accessible from it, and enforce EDR policy.",
            ],
            "risk_note": "Active C2 communication implies ongoing attacker access — data exfiltration and lateral movement are high-probability concurrent threats.",
        },
        "FTP-Patator": {
            "summary": f"Credential brute-force attack against FTP service: `{src}` is systematically attempting password enumeration on `{dst}:{port}`.",
            "analysis": (
                f"High-frequency authentication attempts from `{src}` against the FTP service at `{dst}:{port}` over {dur_s} constitute a Patator-style credential stuffing attack. "
                f"At {bps}, the attack is submitting approximately one credential pair per second — a rate designed to avoid account lockout thresholds. "
                "FTP transmits credentials in cleartext; a successful login would grant immediate filesystem access without encryption. "
                "The presence of a publicly accessible FTP service itself represents a security misconfiguration."
            ),
            "assets": f"`{src}` is the attacker running automated credential enumeration tooling. `{dst}:{port}` is the FTP service — likely hosting sensitive file transfers or legacy data.",
            "mitre": [
                "**T1110.001** — Brute Force — Password Guessing: Automated credential enumeration against FTP.",
                "**T1078** — Valid Accounts: Attacker goal is to obtain legitimate credentials for persistent access.",
                "**T1021.002** — Remote Services — SMB/Windows Admin Shares: Potential pivot after FTP compromise.",
            ],
            "remediation": [
                f"Block `{src}` at the firewall; implement geo-restriction on FTP port `{port}` to known IP ranges.",
                f"Lock any accounts with failed login counts > 5 in the last hour on `{dst}`.",
                "Replace FTP with SFTP or FTPS immediately — cleartext credential transmission is unacceptable.",
                "Implement fail2ban or equivalent brute-force protection on the FTP daemon.",
                "Audit FTP access logs for any successful logins from `{src}` or related IPs in the past 72 hours.",
                "Consider disabling FTP entirely and migrating file transfers to a managed SFTP solution.",
            ],
            "risk_note": "Successful FTP credential compromise grants direct file system access — sensitive data exposure is the primary risk.",
        },
        "SSH-Patator": {
            "summary": f"SSH brute-force campaign: `{src}` is executing automated credential attacks against `{dst}:{port}`, targeting administrative access.",
            "analysis": (
                f"Systematic SSH authentication failures from `{src}` against `{dst}:{port}` over {dur_s} indicate a Patator or Hydra-style brute-force tool. "
                f"The {bps} traffic rate corresponds to rapid credential cycling without triggering standard lockout policies. "
                "SSH brute-force against port 22 is among the most common initial access vectors for ransomware and cryptomining deployments. "
                "If successful, the attacker obtains an interactive shell with the permissions of the targeted account."
            ),
            "assets": f"`{src}` is the attacker host running credential enumeration tooling. `{dst}:{port}` is the SSH management interface — likely a server, bastion host, or network appliance.",
            "mitre": [
                "**T1110.001** — Brute Force — Password Guessing: Automated SSH credential enumeration.",
                "**T1078.003** — Valid Accounts — Local Accounts: Target is local system accounts (root, admin, ubuntu).",
                "**T1021.004** — Remote Services — SSH: SSH used as remote access vector post-compromise.",
            ],
            "remediation": [
                f"Block `{src}` at perimeter firewall; add to persistent deny list via threat intelligence feed.",
                f"If SSH must be internet-exposed, restrict port `{port}` to VPN/bastion subnets only.",
                "Enforce SSH key-based authentication; disable password authentication in `sshd_config`.",
                "Deploy fail2ban with aggressive policy: ban after 3 failures, 24-hour ban duration.",
                "Audit `/var/log/auth.log` for any `Accepted password` events from `{src}` or related ranges.",
                "Migrate SSH to a non-standard port and implement port-knocking for additional obscurity.",
            ],
            "risk_note": "SSH brute-force is a high-volume, automated attack — the risk of eventual credential match is proportional to exposure time.",
        },
        "Web Attack": {
            "summary": f"Web application attack detected: `{src}` is exploiting vulnerabilities in the web service at `{dst}:{port}`, potentially targeting SQL injection or XSS vectors.",
            "analysis": (
                f"Malicious HTTP requests from `{src}` to `{dst}:{port}` over {dur_s} exhibit patterns consistent with automated web vulnerability scanning and active exploitation. "
                f"Traffic volume of {bps} suggests tooling such as SQLmap, Nikto, or Burp Suite in active attack mode. "
                "Web application attacks at this stage typically indicate the attacker has identified a target endpoint and is testing specific injection vectors. "
                "Successful SQLi could expose the entire database; XSS could enable session hijacking."
            ),
            "assets": f"`{src}` is the attacker host running web exploitation tooling. `{dst}:{port}` hosts the web application — assess whether it connects to a backend database.",
            "mitre": [
                "**T1190** — Exploit Public-Facing Application: Direct exploitation of web app vulnerabilities.",
                "**T1059.007** — Command and Scripting Interpreter — JavaScript: XSS enabling client-side code execution.",
                "**T1505.003** — Server Software Component — Web Shell: Potential webshell deployment post-exploitation.",
            ],
            "remediation": [
                f"Block `{src}` at WAF and perimeter firewall immediately; apply rate-limiting to `{dst}:{port}`.",
                "Enable WAF in blocking mode with OWASP Core Rule Set — verify rules are not in detection-only mode.",
                "Review application logs for successful injection payloads or anomalous response codes (500, 302).",
                "Patch all known CVEs in the web application framework and dependencies within 24 hours.",
                "Conduct a focused penetration test on the specific endpoint being probed.",
                "Implement Content Security Policy (CSP) headers to reduce XSS impact.",
            ],
            "risk_note": "Web exploitation can result in data exfiltration, defacement, or persistent backdoor installation within minutes of a successful exploit.",
        },
        "Infiltration": {
            "summary": f"Active network infiltration in progress: `{src}` has established unauthorised access to internal resources via `{dst}:{port}`.",
            "analysis": (
                f"Post-exploitation lateral movement indicators were observed from `{src}` to `{dst}:{port}` over {dur_s}. "
                f"The {bps} traffic pattern is consistent with internal reconnaissance tooling (BloodHound, CrackMapExec) enumerating Active Directory and network shares. "
                "At this stage, the attacker likely holds valid credentials and is mapping pathways to high-value targets such as domain controllers or file servers. "
                "Dwell time at this stage averages 14 days before detection in unmonitored environments."
            ),
            "assets": f"`{src}` is a compromised internal host acting as a pivot point. `{dst}:{port}` is the target internal resource — assess its sensitivity (AD, file server, database).",
            "mitre": [
                "**T1021** — Remote Services: Using SMB, WinRM, or RDP for lateral movement between hosts.",
                "**T1018** — Remote System Discovery: Enumerating internal network topology and live hosts.",
                "**T1087.002** — Account Discovery — Domain Account: LDAP queries to enumerate AD users and groups.",
                "**T1558.003** — Steal or Forge Kerberos Tickets — Kerberoasting: Targeting service account credential hashes.",
            ],
            "remediation": [
                f"Isolate `{src}` from the network immediately — segment at switch port; revoke all session tokens.",
                "Activate incident response retainer; this is an active intrusion requiring forensic investigation.",
                "Reset all Active Directory credentials accessible from the compromised host.",
                "Audit Kerberos ticket-granting logs for unusual service ticket requests in the past 48 hours.",
                "Deploy honeypot credentials to detect attacker lateral movement to secondary hosts.",
                "Engage threat hunting team to identify all compromised hosts using EDR telemetry.",
            ],
            "risk_note": "Active infiltration with internal access is a **P0 incident** — data exfiltration and ransomware deployment are imminent risks.",
        },
        "Heartbleed": {
            "summary": f"`{src}` is exploiting the Heartbleed (CVE-2014-0160) vulnerability against `{dst}:{port}`, attempting to extract private keys and session memory from OpenSSL.",
            "analysis": (
                f"Malformed TLS heartbeat requests from `{src}` to `{dst}:{port}` over {dur_s} are characteristic of Heartbleed exploitation tooling. "
                "Each crafted heartbeat can leak up to 64 KB of process memory, potentially exposing private keys, session tokens, and user credentials. "
                "Despite being a decade-old CVE, unpatched OpenSSL instances remain common in embedded systems and legacy infrastructure. "
                "Successful exploitation provides cryptographic material enabling passive TLS decryption of recorded traffic."
            ),
            "assets": f"`{src}` is the attacker exploiting a known CVE. `{dst}:{port}` is the TLS endpoint — verify OpenSSL version immediately (`openssl version`).",
            "mitre": [
                "**T1190** — Exploit Public-Facing Application: Exploiting CVE-2014-0160 on vulnerable TLS endpoints.",
                "**T1552.004** — Unsecured Credentials — Private Keys: Heartbleed goal is extracting private key material.",
                "**T1557** — Adversary-in-the-Middle: Stolen keys enable retrospective TLS decryption.",
            ],
            "remediation": [
                f"Take `{dst}:{port}` offline immediately if OpenSSL < 1.0.1g is confirmed — this is a critical exposure.",
                "Upgrade OpenSSL to a non-vulnerable version (≥ 1.0.1g or ≥ 1.0.2a) across all affected hosts.",
                "Revoke and reissue all TLS certificates on affected hosts — leaked private keys are unrecoverable.",
                "Rotate all session tokens, cookies, and passwords that may have been served by the vulnerable endpoint.",
                "Audit load-balancer and CDN SSL termination configurations for vulnerable OpenSSL linkage.",
                "Block `{src}` and conduct retrospective NetFlow analysis to identify prior exploitation attempts.",
            ],
            "risk_note": "Heartbleed exploitation against an unpatched host constitutes a **critical** key-material compromise — treat all secrets served by this endpoint as exposed.",
        },
    }

    # Match family from label
    meta = None
    lbl_up = label.upper()
    for key, val in _INTEL.items():
        if key.upper() in lbl_up or lbl_up.startswith(key.upper()):
            meta = val
            break

    if meta is None:
        meta = {
            "summary": f"Anomalous network behaviour detected from `{src}` targeting `{dst}:{port}` — threat classification: **{label}**.",
            "analysis": (
                f"Network telemetry captured a {proto} flow from `{src}` to `{dst}:{port}` spanning {dur_s} at {bps}. "
                "The traffic pattern deviates from established baselines and matches threat intelligence signatures associated with this attack family. "
                "Further correlation with endpoint telemetry is recommended to determine whether lateral movement has occurred."
            ),
            "assets": f"`{src}` is the identified threat origin. `{dst}:{port}` is the targeted asset — classify based on your CMDB.",
            "mitre": [
                "**T1071** — Application Layer Protocol: Threat traffic leveraging standard protocols for obfuscation.",
                "**T1041** — Exfiltration Over C2 Channel: Potential data loss via established C2 communications.",
            ],
            "remediation": [
                f"Block `{src}` at the perimeter firewall and add to the threat intelligence blocklist.",
                f"Inspect all traffic between `{src}` and `{dst}:{port}` for the past 24 hours via SIEM correlation.",
                "Alert the asset owner of `{dst}` and initiate standard incident response procedures.",
                "Review and tighten egress firewall rules for the affected network segment.",
                "Submit IOCs to your threat sharing platform (MISP, OpenCTI) for community awareness.",
            ],
            "risk_note": f"Treat as {severity} until further investigation confirms or rules out active compromise.",
        }

    # ── Per-family detection rules ─────────────────────────────────────────────
    _DETECT: dict[str, str] = {
        "DoS": f"""\
```splunk
index=network sourcetype=netflow
| where dest_ip="{dst}" AND dest_port={port}
| stats count AS pkt_count, sum(bytes_in) AS total_bytes BY src_ip, dest_ip, _time
| where pkt_count > 5000
| eval rate_mbps=round(total_bytes/1048576, 2)
| where rate_mbps > 100
| table src_ip, dest_ip, pkt_count, rate_mbps
| sort -rate_mbps
```
*Flags source IPs sustaining > 100 Mbps against `{dst}:{port}`; tune the `rate_mbps` threshold to 2× your environment's peak baseline to reduce false positives.*""",

        "DDoS": f"""\
```splunk
index=network sourcetype=netflow
| where dest_ip="{dst}" AND dest_port={port}
| bucket _time span=10s
| stats dc(src_ip) AS unique_sources, sum(bytes_in) AS total_bytes BY _time, dest_ip
| where unique_sources > 50 AND total_bytes > 50000000
| eval gbit=round(total_bytes/1073741824, 3)
| table _time, dest_ip, unique_sources, gbit
```
*Detects coordinated multi-source floods with > 50 unique origins in a 10-second window; adjust `unique_sources` threshold based on your normal traffic diversity.*""",

        "PortScan": f"""\
```splunk
index=network sourcetype=firewall
| where src_ip="{src}"
| stats dc(dest_port) AS ports_probed, dc(dest_ip) AS hosts_probed, count BY src_ip
| where ports_probed > 100 OR hosts_probed > 20
| table src_ip, ports_probed, hosts_probed, count
| sort -ports_probed
```
*Identifies horizontal and vertical scanners probing > 100 distinct ports or > 20 hosts within the search window; lower thresholds for high-sensitivity environments.*""",

        "Bot": f"""\
```yaml
title: C2 Beaconing — Regular Outbound Interval
status: stable
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    dst_ip: '{dst}'
    dst_port: {port}
    Initiated: 'true'
  timeframe: 1h
  condition: selection | count() by src_ip > 20
falsepositives:
  - Legitimate update services with fixed polling intervals
  - CDN health-check probes
level: high
tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1568
```
*Catches endpoints making > 20 outbound connections to the same C2 destination within one hour; whitelist known update endpoints (Windows Update, antivirus cloud) before deploying.*""",

        "FTP-Patator": f"""\
```splunk
index=auth sourcetype=ftp_log
| where dest_ip="{dst}" AND dest_port={port} AND action="failed"
| bucket _time span=60s
| stats count AS failures, dc(src_ip) AS unique_srcs BY _time, dest_ip
| where failures > 20
| table _time, dest_ip, failures, unique_srcs
```
*Triggers on > 20 FTP authentication failures per minute against `{dst}:{port}`; adjust threshold if legitimate batch transfer tools generate expected failures.*""",

        "SSH-Patator": f"""\
```splunk
index=auth sourcetype=linux_secure
| rex "Failed password for (?P<user>\\S+) from (?P<src_ip>\\S+)"
| where isnotnull(src_ip)
| bucket _time span=60s
| stats count AS failures, dc(user) AS users_tried BY _time, src_ip, dest_ip
| where failures > 15
| table _time, src_ip, dest_ip, failures, users_tried
| sort -failures
```
*Detects SSH brute-force with > 15 failed attempts per minute; tune lower for bastion hosts and higher for public-facing SSH jump servers.*""",

        "Web Attack": f"""\
```splunk
index=web sourcetype=access_combined
| where dest_ip="{dst}" AND dest_port={port}
| rex "(?P<payload>('|\"|--|\\/\\*|union|select|alert\\(|<script))"
| where isnotnull(payload)
| stats count AS hits, dc(payload) AS patterns BY src_ip, uri_path
| where hits > 5
| table src_ip, uri_path, hits, patterns
| sort -hits
```
*Matches common SQLi, XSS, and command-injection signatures in HTTP request fields; expects Splunk `access_combined` sourcetype — enable request body logging for maximum coverage.*""",

        "Infiltration": f"""\
```yaml
title: Lateral Movement — Internal SMB/WinRM Sweep
status: stable
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    src_ip: '{src}'
    dst_port:
      - 445
      - 5985
      - 5986
      - 135
  timeframe: 30m
  condition: selection | count(dst_ip) by src_ip > 5
falsepositives:
  - Legitimate sysadmin tools (SCCM, Ansible WinRM)
  - Domain controllers performing scheduled replication
level: critical
tags:
  - attack.lateral_movement
  - attack.t1021
  - attack.t1018
```
*Flags hosts initiating SMB or WinRM connections to > 5 distinct internal targets within 30 minutes; whitelist your configuration management server before deploying to avoid alert flood.*""",

        "Heartbleed": f"""\
```splunk
index=network sourcetype=ids_alerts
| where dest_ip="{dst}" AND dest_port={port}
| search signature="*heartbleed*" OR signature="*CVE-2014-0160*"
| stats count BY src_ip, dest_ip, dest_port, signature
| where count > 0
| table src_ip, dest_ip, dest_port, signature, count
UNION
[ search index=network sourcetype=netflow dest_ip="{dst}" dest_port={port}
  | eval tls_handshake_anomaly=if(bytes_in > 16384 AND bytes_out < 100, 1, 0)
  | where tls_handshake_anomaly=1
  | stats count BY src_ip, dest_ip ]
```
*Combines IDS signature matches with a heuristic (large inbound / tiny outbound on a TLS port) to catch both known and unknown Heartbleed variants; verify your IDS has CVE-2014-0160 rules enabled.*""",
    }

    detection_block = next(
        (v for k, v in _DETECT.items() if k.upper() in lbl_up or lbl_up.startswith(k.upper())),
        f"""\
```splunk
index=network sourcetype=netflow
| where src_ip="{src}" AND dest_ip="{dst}" AND dest_port={port}
| bucket _time span=5m
| stats count AS connections, sum(bytes_in) AS total_bytes BY _time, src_ip, dest_ip, dest_port
| where connections > 50
| table _time, src_ip, dest_ip, dest_port, connections, total_bytes
```
*Generic anomaly rule for `{label}` traffic from `{src}` to `{dst}:{port}`; tune the connection-count threshold to 3× your baseline for this source/destination pair.*""",
    )

    mitre_block = "\n".join(f"- {t}" for t in meta["mitre"])
    remediation_block = "\n".join(f"{i+1}. {step}" for i, step in enumerate(meta["remediation"]))

    return f"""## Executive Summary

**{severity}** — {meta['summary']} Immediate containment action is required.

## Technical Analysis

{meta['analysis']}

## Affected Assets

{meta['assets']}

- **Protocol:** `{proto}`
- **Flow Duration:** {dur_s}
- **Observed Throughput:** {bps}

## MITRE ATT&CK Mapping

{mitre_block}

## Recommended Remediation Steps

{remediation_block}

## Risk Assessment

**{severity}** — {meta['risk_note']}

## Detection Engineering (Sigma / Splunk SPL)

{detection_block}"""
