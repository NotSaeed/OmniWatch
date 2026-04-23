import { useEffect, useRef, useState } from "react";
import type { WsMessage } from "../lib/types";

export function useWebSocket(onMessage: (msg: WsMessage) => void) {
  const [connected, setConnected] = useState(false);
  const wsRef   = useRef<WebSocket | null>(null);
  const cbRef   = useRef(onMessage);
  cbRef.current = onMessage;

  useEffect(() => {
    let reconnectTimer: ReturnType<typeof setTimeout>;
    let isUnmounted = false;

    function connect() {
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(`${proto}://${window.location.host}/ws/alerts`);
      wsRef.current = ws;

      ws.onopen  = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!isUnmounted) {
          reconnectTimer = setTimeout(connect, 3000);
        }
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (e) => {
        try {
          if (!isUnmounted) cbRef.current(JSON.parse(e.data) as WsMessage);
        } catch { /* ignore malformed messages */ }
      };
    }

    connect();
    return () => {
      isUnmounted = true;
      clearTimeout(reconnectTimer);
      wsRef.current?.close();
    };
  }, []);

  return connected;
}
