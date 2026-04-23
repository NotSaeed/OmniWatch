"""
OmniWatch Log Simulator
Generates realistic security log entries into backend/logs/*.log
Covers SSH brute force, port scans, malware C2, data exfiltration, and normal traffic.

Run: python backend/log_simulator.py
     python backend/log_simulator.py --count 200 --attack-ratio 0.4
"""

import argparse
import random
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

SYSLOG_PATH  = LOGS_DIR / "syslog.log"
NETWORK_PATH = LOGS_DIR / "network.log"
AUTH_PATH    = LOGS_DIR / "auth.log"

# ── Realistic data pools ───────────────────────────────────────────────────────
ATTACKER_IPS = [
    "203.0.113.42", "198.51.100.17", "185.220.101.55",
    "91.108.4.200",  "45.33.32.156",  "162.247.74.200",
]
INTERNAL_IPS = [
    "10.0.1.10", "10.0.1.20", "10.0.1.30",
    "192.168.1.100", "192.168.1.101", "192.168.1.50",
]
HOSTNAMES = ["web-srv-01", "db-srv-02", "app-srv-03", "dc-01", "workstation-14"]
USERNAMES = ["root", "admin", "ubuntu", "deploy", "jenkins", "test"]
SERVICES  = ["sshd", "nginx", "apache2", "mysqld", "systemd", "kernel", "cron", "sudo"]
C2_DOMAINS = ["update-service.net", "cdn-static.io", "telemetry-api.com"]

# ── Timestamp helper ───────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%b %d %H:%M:%S")


def _append(path: Path, line: str) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


# ── Attack scenario generators ────────────────────────────────────────────────

def generate_ssh_brute_force(
    target_ip: str | None = None,
    attacker_ip: str | None = None,
    count: int = 20,
) -> list[str]:
    """Generate SSH brute-force log entries across auth.log and syslog."""
    target   = target_ip   or random.choice(INTERNAL_IPS)
    attacker = attacker_ip or random.choice(ATTACKER_IPS)
    user     = random.choice(USERNAMES)
    hostname = random.choice(HOSTNAMES)
    lines    = []

    for i in range(count):
        port   = random.randint(40000, 65000)
        ts     = _now()
        auth_line = (
            f"{ts} {hostname} sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {'invalid user ' if i % 3 == 0 else ''}{user} "
            f"from {attacker} port {port} ssh2"
        )
        lines.append(auth_line)
        _append(AUTH_PATH, auth_line)

        if i % 5 == 0:
            sys_line = (
                f"{ts} {hostname} sshd[{random.randint(1000,9999)}]: "
                f"error: maximum authentication attempts exceeded for {user} "
                f"from {attacker} port {port} ssh2 [preauth]"
            )
            lines.append(sys_line)
            _append(SYSLOG_PATH, sys_line)

    return lines


def generate_port_scan(
    scanner_ip: str | None = None,
    target_subnet: str = "10.0.1",
    count: int = 30,
) -> list[str]:
    """Generate TCP SYN port scan entries in network.log and syslog."""
    scanner  = scanner_ip or random.choice(ATTACKER_IPS)
    hostname = random.choice(HOSTNAMES)
    lines    = []

    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080]
    scan_ports   = random.sample(range(1, 65535), count - len(common_ports)) + common_ports

    for port in scan_ports[:count]:
        target = f"{target_subnet}.{random.randint(1, 50)}"
        ts     = _now()
        net_line = (
            f"{ts} NETWORK {scanner} -> {target}:{port} "
            f"TCP SYN flags=S seq={random.randint(100000,999999)} "
            f"bytes=0 duration=0.001s action=REJECT"
        )
        lines.append(net_line)
        _append(NETWORK_PATH, net_line)

    ts = _now()
    sys_line = (
        f"{ts} {hostname} kernel: "
        f"[UFW BLOCK] IN=eth0 SRC={scanner} DST={target_subnet}.1 "
        f"PROTO=TCP SPT={random.randint(40000,65000)} DPT=22 SYN"
    )
    lines.append(sys_line)
    _append(SYSLOG_PATH, sys_line)

    return lines


def generate_malware_c2(
    infected_ip: str | None = None,
    count: int = 15,
) -> list[str]:
    """Generate C2 beaconing traffic in network.log."""
    source  = infected_ip or random.choice(INTERNAL_IPS)
    c2_host = random.choice(C2_DOMAINS)
    c2_ip   = f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    lines   = []

    # Regular beaconing interval (suspicious uniformity)
    for _ in range(count):
        ts       = _now()
        net_line = (
            f"{ts} NETWORK {source} -> {c2_ip}:443 "
            f"TCP ESTABLISHED bytes_out={random.randint(200,800)} "
            f"bytes_in={random.randint(50,200)} duration=30.0s "
            f"hostname={c2_host} action=ALLOW"
        )
        lines.append(net_line)
        _append(NETWORK_PATH, net_line)

    hostname = random.choice(HOSTNAMES)
    ts = _now()
    sys_line = (
        f"{ts} {hostname} syslog: suspicious process "
        f"'update_helper' established persistent outbound connection to {c2_ip}"
    )
    lines.append(sys_line)
    _append(SYSLOG_PATH, sys_line)

    return lines


def generate_data_exfiltration(
    source_ip: str | None = None,
    count: int = 10,
) -> list[str]:
    """Generate large outbound data transfer entries suggesting exfiltration."""
    source = source_ip or random.choice(INTERNAL_IPS)
    dest   = f"104.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    lines  = []

    for _ in range(count):
        ts       = _now()
        # Large outbound transfers — red flag
        bytes_out = random.randint(50_000_000, 500_000_000)
        net_line  = (
            f"{ts} NETWORK {source} -> {dest}:443 "
            f"TCP ESTABLISHED bytes_out={bytes_out} bytes_in={random.randint(1000,5000)} "
            f"duration={random.randint(30,300)}.0s action=ALLOW"
        )
        lines.append(net_line)
        _append(NETWORK_PATH, net_line)

    hostname = random.choice(HOSTNAMES)
    ts = _now()
    sys_line = (
        f"{ts} {hostname} kernel: "
        f"unusual outbound data volume detected from {source}: "
        f">500MB transferred in last 5 minutes"
    )
    lines.append(sys_line)
    _append(SYSLOG_PATH, sys_line)

    return lines


def generate_failed_sudo(user: str | None = None, count: int = 5) -> list[str]:
    """Generate failed sudo attempts in auth.log."""
    u        = user or random.choice(USERNAMES)
    hostname = random.choice(HOSTNAMES)
    lines    = []

    for _ in range(count):
        ts      = _now()
        command = random.choice(["/bin/bash", "/usr/bin/passwd", "/sbin/shutdown"])
        line    = (
            f"{ts} {hostname} sudo: {u} : "
            f"command not allowed ; TTY=pts/0 ; PWD=/home/{u} ; "
            f"USER=root ; COMMAND={command}"
        )
        lines.append(line)
        _append(AUTH_PATH, line)

    return lines


def generate_normal_traffic(count: int = 20) -> list[str]:
    """Generate benign background traffic to create realistic noise."""
    lines = []
    benign_dests = ["8.8.8.8", "1.1.1.1", "142.250.80.46", "151.101.1.69"]

    for _ in range(count):
        source = random.choice(INTERNAL_IPS)
        dest   = random.choice(benign_dests)
        port   = random.choice([80, 443, 53])
        ts     = _now()
        line   = (
            f"{ts} NETWORK {source} -> {dest}:{port} "
            f"TCP ESTABLISHED bytes_out={random.randint(500,50000)} "
            f"bytes_in={random.randint(1000,100000)} "
            f"duration={random.uniform(0.1, 5.0):.2f}s action=ALLOW"
        )
        lines.append(line)
        _append(NETWORK_PATH, line)

    for _ in range(count // 4):
        ts       = _now()
        hostname = random.choice(HOSTNAMES)
        service  = random.choice(SERVICES)
        sys_line = (
            f"{ts} {hostname} {service}[{random.randint(100,9999)}]: "
            f"normal operation — heartbeat ok"
        )
        lines.append(sys_line)
        _append(SYSLOG_PATH, sys_line)

    return lines


# ── Scenario orchestrator ─────────────────────────────────────────────────────

SCENARIOS = {
    "ssh_brute_force":    lambda: generate_ssh_brute_force(),
    "port_scan":          lambda: generate_port_scan(),
    "malware_c2":         lambda: generate_malware_c2(),
    "data_exfiltration":  lambda: generate_data_exfiltration(),
    "failed_sudo":        lambda: generate_failed_sudo(),
}

ATTACK_SCENARIOS  = ["ssh_brute_force", "port_scan", "malware_c2", "data_exfiltration", "failed_sudo"]
BENIGN_SCENARIOS  = ["normal_traffic"]


def run_simulation(total_entries: int = 150, attack_ratio: float = 0.35) -> None:
    """
    Write `total_entries` log lines to disk.
    `attack_ratio` controls what fraction are attack events (0.0–1.0).
    """
    attack_count = int(total_entries * attack_ratio)
    benign_count = total_entries - attack_count

    print(f"Generating {total_entries} log entries ({attack_count} attack, {benign_count} benign)...")

    # Attacks
    generated = 0
    while generated < attack_count:
        scenario = random.choice(ATTACK_SCENARIOS)
        lines    = SCENARIOS[scenario]()
        generated += len(lines)

    # Benign fill
    generated = 0
    while generated < benign_count:
        lines     = generate_normal_traffic(min(20, benign_count - generated))
        generated += len(lines)

    print(f"Done. Logs written to {LOGS_DIR}/")
    for name, path in {"syslog": SYSLOG_PATH, "network": NETWORK_PATH, "auth": AUTH_PATH}.items():
        size = path.stat().st_size if path.exists() else 0
        print(f"  {name:10s}: {size:,} bytes")


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OmniWatch log simulator")
    parser.add_argument("--count",        type=int,   default=150,  help="Total log entries to generate")
    parser.add_argument("--attack-ratio", type=float, default=0.35, help="Fraction that are attack events (0.0–1.0)")
    parser.add_argument("--continuous",   action="store_true",       help="Keep generating entries every 10 seconds")
    args = parser.parse_args()

    if args.continuous:
        print("Continuous mode — Ctrl+C to stop")
        try:
            while True:
                run_simulation(total_entries=30, attack_ratio=args.attack_ratio)
                time.sleep(10)
        except KeyboardInterrupt:
            print("Stopped.")
    else:
        run_simulation(total_entries=args.count, attack_ratio=args.attack_ratio)
