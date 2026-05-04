import { useQuery } from "@tanstack/react-query";
import axios from "axios";
import { Wifi, WifiOff, Radio, AlertTriangle, Activity, Zap, Loader2, ServerOff } from "lucide-react";

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
  const {
    data: status,
    isLoading: statusLoading,
    isError: statusError,
  } = useQuery<EdgeStatus>({
    queryKey:        ["edge-status"],
    queryFn:         () => http.get("/edge/status").then(r => r.data),
    refetchInterval: 3000,
  });

  const connected    = status?.connected ?? false;
  const totalRecords = status?.records_received ?? 0;

  // Only fetch logs when the sensor is confirmed online. This prevents stale
  // DB rows from previous sessions from appearing as "ghost alerts" when the
  // sensor is offline or has 0 records in the current session.
  const {
    data: logs,
    isLoading: logsLoading,
    isError: logsError,
  } = useQuery<EdgeLog[]>({
    queryKey:        ["edge-logs"],
    queryFn:         () => http.get("/edge/logs?limit=20").then(r => r.data),
    refetchInterval: 5000,
    enabled:         connected,
  });

  const isLoading = statusLoading || (connected && logsLoading);
  const isError   = statusError || logsError;

  function renderBody() {
    if (isLoading) {
      return (
        <div className="flex flex-col items-center justify-center py-10 gap-3">
          <Loader2 className="animate-spin" style={{ width: 22, height: 22, color: "#4d5060" }} />
          <p className="text-[11px]" style={{ color: "#4d5060" }}>Polling edge node…</p>
        </div>
      );
    }

    if (isError) {
      return (
        <div className="flex flex-col items-center justify-center py-10 gap-2">
          <AlertTriangle style={{ width: 24, height: 24, color: "#ef4444" }} />
          <p className="text-[11px] font-semibold" style={{ color: "#ef4444" }}>Edge API Error</p>
          <p className="text-[10px]" style={{ color: "#4d5060" }}>
            Could not reach /api/edge/status or /api/edge/logs
          </p>
        </div>
      );
    }

    // Sensor offline — never show stale DB rows. Ghost alerts waste triage time.
    if (!connected) {
      return (
        <div className="flex flex-col items-center justify-center py-10 gap-3">
          <div
            className="flex items-center justify-center rounded-full"
            style={{ width: 44, height: 44, background: "rgba(239,68,68,0.10)", border: "1px solid rgba(239,68,68,0.25)" }}
          >
            <ServerOff style={{ width: 20, height: 20, color: "#ef4444" }} />
          </div>
          <div className="text-center">
            <p className="text-[12px] font-bold" style={{ color: "#ef4444" }}>Sensor Offline</p>
            <p className="text-[10px] mt-1" style={{ color: "#4d5060" }}>No telemetry available — Pi 4 is not connected</p>
          </div>
          <div
            className="flex flex-col gap-1 px-3 py-2 rounded-lg text-[10px] font-mono"
            style={{ background: "#0a0a0d", border: "1px solid #1a1a1f", color: "#6b6e80" }}
          >
            <span style={{ color: "#4d5060" }}># Start live capture</span>
            <span>python edge/replay/pcap_replay.py --instant</span>
          </div>
        </div>
      );
    }

    // Sensor online but no records in this session
    if (!logs || logs.length === 0) {
      return (
        <div className="flex flex-col items-center justify-center py-10 gap-2">
          <Activity style={{ width: 28, height: 28, color: "#2e3038" }} />
          <p className="text-[11px]" style={{ color: "#4d5060" }}>No Telemetry Records Found</p>
          <p className="text-[10px]" style={{ color: "#2e3038" }}>
            Sensor is connected — waiting for first Modbus frame
          </p>
        </div>
      );
    }

    // Live data present
    return (
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
            const isWrite      = [5, 6, 15, 16].includes(log.modbus_func_code);
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
    );
  }

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
              color: connected ? "#22c55e" : "#ef4444",
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
              <WifiOff style={{ width: 11, height: 11, color: "#ef4444" }} />
            )}
            <span
              className="text-[10px] font-semibold"
              style={{ color: connected ? "#22c55e" : "#ef4444" }}
            >
              {connected ? "Connected" : "Offline"}
            </span>
          </span>
          {connected && (
            <span className="text-[10px] font-mono" style={{ color: "#6b6e80" }}>
              {totalRecords.toLocaleString()} records
            </span>
          )}
        </div>
      </div>

      {/* Body */}
      <div className="overflow-auto" style={{ maxHeight: 320 }}>
        {renderBody()}
      </div>
    </div>
  );
}
