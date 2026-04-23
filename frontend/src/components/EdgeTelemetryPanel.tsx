/**
 * Sprint 4 — Edge Telemetry Panel
 *
 * Shows the live Modbus ingestion feed from the Pi 4 edge node (or PCAP replay).
 * Polls /api/edge/status and /api/edge/logs to display the data.
 */


import { useQuery } from "@tanstack/react-query";
import axios from "axios";
import { Wifi, WifiOff, Radio, AlertTriangle, Activity, Zap, Loader2 } from "lucide-react";

const http = axios.create({ baseURL: "/api" });

interface EdgeStatus {
  connected: boolean;
  last_heartbeat: number | null;
  records_received: number;
  last_record: {
    id: number;
    severity: string;
    src_ip: string;
    dst_ip: string;
    dst_port: number;
    modbus_fc: number;
    modbus_fc_name: string;
  } | null;
}

interface EdgeLog {
  id: number;
  ingested_at: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  protocol: number;
  flow_bytes_s: number;
  packet_count: number;
  modbus_func_code: number;
  modbus_unit_id: number;
  severity: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#f4a926",
  INFO:     "#4d5060",
};

function modbusLabel(fc: number): string {
  const names: Record<number, string> = {
    1: "Read Coils", 2: "Read Disc. Inputs", 3: "Read Hold. Regs",
    4: "Read Input Regs", 5: "Write Coil", 6: "Write Reg",
    15: "Write Multi Coils", 16: "Write Multi Regs",
  };
  return names[fc] || (fc > 0 ? `FC ${fc}` : "N/A");
}

interface EdgeTelemetryPanelProps {
  onProve?: (recordId: number, modbusLabel: string, srcIp: string) => void;
  isProvingRecordId?: number | null;
}

export function EdgeTelemetryPanel({ onProve, isProvingRecordId }: EdgeTelemetryPanelProps) {
  const { data: status } = useQuery<EdgeStatus>({
    queryKey:        ["edge-status"],
    queryFn:         () => http.get("/edge/status").then(r => r.data),
    refetchInterval: 3000,
  });

  const { data: logs } = useQuery<EdgeLog[]>({
    queryKey:        ["edge-logs"],
    queryFn:         () => http.get("/edge/logs?limit=20").then(r => r.data),
    refetchInterval: 5000,
  });

  const connected = status?.connected ?? false;
  const totalRecords = status?.records_received ?? 0;

  return (
    <div
      className="rounded-xl overflow-hidden"
      style={{ background: "#0d0d10", border: "1px solid #1a1a1f" }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-3"
        style={{ borderBottom: "1px solid #1a1a1f" }}
      >
        <div className="flex items-center gap-2.5">
          <Radio
            style={{
              width: 14, height: 14,
              color: connected ? "#22c55e" : "#4d5060",
            }}
          />
          <span className="text-xs font-bold text-white/90 tracking-wide">
            Edge Telemetry
          </span>
          <span className="text-[10px] font-mono" style={{ color: "#6b6e80" }}>
            Pi 4 · Modbus TCP
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5">
            {connected ? (
              <Wifi style={{ width: 11, height: 11, color: "#22c55e" }} />
            ) : (
              <WifiOff style={{ width: 11, height: 11, color: "#4d5060" }} />
            )}
            <span className="text-[10px]" style={{ color: connected ? "#22c55e" : "#4d5060" }}>
              {connected ? "Connected" : "Offline"}
            </span>
          </span>
          <span className="text-[10px] font-mono" style={{ color: "#6b6e80" }}>
            {totalRecords.toLocaleString()} records
          </span>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-auto" style={{ maxHeight: 320 }}>
        {(!logs || logs.length === 0) ? (
          <div className="flex flex-col items-center justify-center py-10 gap-2">
            <Activity style={{ width: 28, height: 28, color: "#2e3038" }} />
            <p className="text-[11px]" style={{ color: "#4d5060" }}>
              No edge telemetry yet — run the PCAP replay or connect the Pi 4
            </p>
            <code className="text-[9px] font-mono px-2 py-1 rounded" style={{ background: "#14141a", color: "#6b6e80" }}>
              python edge/replay/pcap_replay.py --instant
            </code>
          </div>
        ) : (
          <table className="w-full text-[10px]" style={{ fontFamily: "JetBrains Mono, monospace" }}>
            <thead>
              <tr style={{ color: "#4d5060", borderBottom: "1px solid #1a1a1f" }}>
                <th className="text-left px-3 py-2 font-semibold">#</th>
                <th className="text-left px-3 py-2 font-semibold">TIME</th>
                <th className="text-left px-3 py-2 font-semibold">SOURCE</th>
                <th className="text-left px-3 py-2 font-semibold">DESTINATION</th>
                <th className="text-left px-3 py-2 font-semibold">MODBUS FC</th>
                <th className="text-left px-3 py-2 font-semibold">UNIT</th>
                <th className="text-left px-3 py-2 font-semibold">SEVERITY</th>
                <th className="text-right px-3 py-2 font-semibold">ACTION</th>
              </tr>
            </thead>
            <tbody>
              {logs.map(log => {
                const isWrite = [5, 6, 15, 16].includes(log.modbus_func_code);
                const severityColor = SEVERITY_COLORS[log.severity] ?? "#4d5060";
                return (
                  <tr
                    key={log.id}
                    className="transition-colors hover:bg-white/[0.02]"
                    style={{ borderBottom: "1px solid #14141a" }}
                  >
                    <td className="px-3 py-1.5" style={{ color: "#4d5060" }}>{log.id}</td>
                    <td className="px-3 py-1.5" style={{ color: "#6b6e80" }}>
                      {log.ingested_at ? new Date(log.ingested_at + "Z").toLocaleTimeString() : "—"}
                    </td>
                    <td className="px-3 py-1.5" style={{ color: "#c5c7d4" }}>{log.src_ip}</td>
                    <td className="px-3 py-1.5" style={{ color: "#c5c7d4" }}>
                      {log.dst_ip}:{log.dst_port}
                    </td>
                    <td className="px-3 py-1.5">
                      <span
                        className="inline-flex items-center gap-1"
                        style={{ color: isWrite ? "#ef4444" : "#6b6e80" }}
                      >
                        {isWrite && <AlertTriangle style={{ width: 9, height: 9 }} />}
                        FC {log.modbus_func_code} · {modbusLabel(log.modbus_func_code)}
                      </span>
                    </td>
                    <td className="px-3 py-1.5" style={{ color: "#6b6e80" }}>{log.modbus_unit_id}</td>
                    <td className="px-3 py-1.5">
                      <span
                        className="inline-block px-1.5 py-0.5 rounded text-[9px] font-semibold"
                        style={{
                          background: `${severityColor}18`,
                          color: severityColor,
                          border: `1px solid ${severityColor}30`,
                        }}
                      >
                        {log.severity}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-right">
                      {isWrite && (
                        <button
                          onClick={() => onProve?.(log.id, modbusLabel(log.modbus_func_code), log.src_ip)}
                          disabled={isProvingRecordId != null}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded text-[9px] font-bold
                                     tracking-wide transition-colors hover:bg-cyan-500/20
                                     active:bg-cyan-500/30 disabled:opacity-40 disabled:cursor-not-allowed"
                          style={{ color: "#06b6d4", border: "1px solid #06b6d440" }}
                        >
                          {isProvingRecordId === log.id
                            ? <><Loader2 style={{ width: 9, height: 9 }} className="animate-spin" />PROVING</>
                            : <><Zap style={{ width: 9, height: 9 }} />PROVE</>}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
