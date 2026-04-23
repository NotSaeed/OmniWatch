#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Sprint 4 — Zeek Network TAP Script for Raspberry Pi 4
#
# Deploys on the Pi 4 edge node.  Starts Zeek with the CISA ICSNPP Modbus
# plugin on the passive monitoring interface, then pipes new Modbus log
# entries through the bincode serializer to the OmniWatch Command Node.
#
# Prerequisites (on the Pi 4):
#   sudo apt install zeek
#   zkg install icsnpp-modbus
#   pip3 install requests
#
# Usage:
#   sudo ./zeek_tap.sh             # default: eth1, POST to omniwatch.local:8443
#   sudo ./zeek_tap.sh eth0        # specify a different interface
#   sudo ./zeek_tap.sh eth1 stdout # write bincode to stdout instead of POSTing
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

IFACE="${1:-eth1}"
MODE="${2:-post}"
BACKEND_URL="${OMNIWATCH_URL:-https://omniwatch.local:8443/api/edge/ingest}"
ZEEK_LOG_DIR="/opt/zeek/logs/current"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[zeek_tap] Interface : $IFACE"
echo "[zeek_tap] Mode      : $MODE"
echo "[zeek_tap] Backend   : $BACKEND_URL"
echo "[zeek_tap] Log dir   : $ZEEK_LOG_DIR"

# ── Ensure Zeek is installed ──────────────────────────────────────────────────
if ! command -v zeek &>/dev/null; then
    echo "[zeek_tap] ERROR: zeek is not installed. Run: sudo apt install zeek"
    exit 1
fi

# ── Ensure ICSNPP Modbus plugin is loaded ─────────────────────────────────────
if ! zeek -e 'event zeek_init() { }' 2>&1 | grep -qi "error"; then
    echo "[zeek_tap] Zeek OK — checking for ICSNPP Modbus..."
fi

# ── Start Zeek on the monitoring interface ────────────────────────────────────
echo "[zeek_tap] Starting Zeek on $IFACE (passive mode)..."
mkdir -p "$ZEEK_LOG_DIR"

# Kill any existing Zeek instance on this interface
pkill -f "zeek.*-i $IFACE" 2>/dev/null || true
sleep 1

# Start Zeek with JSON log output and ICSNPP Modbus
zeek -i "$IFACE" \
    LogAscii::use_json=T \
    Modbus::log_modbus=T \
    &

ZEEK_PID=$!
echo "[zeek_tap] Zeek PID: $ZEEK_PID"

# Wait for the modbus log file to appear
echo "[zeek_tap] Waiting for modbus.log to appear..."
for i in $(seq 1 30); do
    if [ -f "$ZEEK_LOG_DIR/modbus.log" ]; then
        echo "[zeek_tap] modbus.log detected"
        break
    fi
    sleep 1
done

if [ ! -f "$ZEEK_LOG_DIR/modbus.log" ]; then
    echo "[zeek_tap] WARNING: modbus.log not found after 30s — no Modbus traffic on $IFACE?"
    echo "[zeek_tap] Falling back to conn.log (generic network flows)"
    LOG_FILE="$ZEEK_LOG_DIR/conn.log"
else
    LOG_FILE="$ZEEK_LOG_DIR/modbus.log"
fi

# ── Pipe logs through the bincode serializer ──────────────────────────────────
echo "[zeek_tap] Tailing $LOG_FILE → serialize_bincode.py..."

if [ "$MODE" = "post" ]; then
    tail -n +1 -F "$LOG_FILE" 2>/dev/null \
        | python3 "$SCRIPT_DIR/serialize_bincode.py" --post --url "$BACKEND_URL"
else
    tail -n +1 -F "$LOG_FILE" 2>/dev/null \
        | python3 "$SCRIPT_DIR/serialize_bincode.py"
fi

# Cleanup on exit
trap "kill $ZEEK_PID 2>/dev/null; echo '[zeek_tap] Stopped'" EXIT
