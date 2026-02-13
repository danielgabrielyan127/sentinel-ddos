import { useEffect, useRef, useState, useCallback } from "react";
import type { TrafficUpdate, SecurityEvent } from "../api/client";

export interface TrafficPoint {
  timestamp: number;
  rps: number;
  blocked: number;
  rateLimited: number;
  total: number;
}

export function useWebSocket(path: string) {
  const [dataPoints, setDataPoints] = useState<TrafficPoint[]>([]);
  const [liveStats, setLiveStats] = useState<TrafficUpdate | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>();

  const connect = useCallback(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${protocol}//${window.location.host}${path}`;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const update: TrafficUpdate = JSON.parse(event.data);
        setLiveStats(update);

        // Add to RPS chart data
        setDataPoints((prev) => {
          const point: TrafficPoint = {
            timestamp: update.timestamp,
            rps: update.rps,
            blocked: update.blocked_requests,
            rateLimited: update.rate_limited_requests,
            total: update.total_requests,
          };
          const next = [...prev, point];
          return next.length > 120 ? next.slice(-120) : next;
        });

        // Append new security events
        if (update.new_events && update.new_events.length > 0) {
          setEvents((prev) => {
            const merged = [...update.new_events, ...prev];
            return merged.slice(0, 50);
          });
        }
      } catch {
        console.error("Failed to parse WS message");
      }
    };

    ws.onclose = () => {
      setConnected(false);
      reconnectTimer.current = setTimeout(connect, 3000);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [path]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { dataPoints, liveStats, events, connected };
}
