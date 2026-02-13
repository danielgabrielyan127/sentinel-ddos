import React from "react";
import type { TrafficUpdate } from "../api/client";

interface Props {
  stats: TrafficUpdate | null;
}

function fmtNum(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
  return n.toFixed(0);
}

const cards = [
  {
    label: "Requests / sec",
    key: "rps" as const,
    color: "text-blue-400",
    bg: "bg-blue-500/10",
    border: "border-blue-500/20",
    fmt: (v: number) => v.toFixed(1),
  },
  {
    label: "Total Requests",
    key: "total_requests" as const,
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/20",
    fmt: fmtNum,
  },
  {
    label: "Forwarded",
    key: "forwarded_requests" as const,
    color: "text-sky-400",
    bg: "bg-sky-500/10",
    border: "border-sky-500/20",
    fmt: fmtNum,
  },
  {
    label: "Rate Limited",
    key: "rate_limited_requests" as const,
    color: "text-yellow-400",
    bg: "bg-yellow-500/10",
    border: "border-yellow-500/20",
    fmt: fmtNum,
  },
  {
    label: "Blocked",
    key: "blocked_requests" as const,
    color: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/20",
    fmt: fmtNum,
  },
  {
    label: "Active IPs",
    key: "active_ips" as const,
    color: "text-purple-400",
    bg: "bg-purple-500/10",
    border: "border-purple-500/20",
    fmt: fmtNum,
  },
];

export const StatsCards: React.FC<Props> = ({ stats }) => {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map((c) => {
        const value = stats ? (stats as unknown as Record<string, number>)[c.key] ?? 0 : 0;
        return (
          <div
            key={c.key}
            className={`${c.bg} ${c.border} border rounded-xl p-4 transition-all`}
          >
            <div className={`text-xs font-medium text-gray-400 mb-1`}>
              {c.label}
            </div>
            <div className={`text-2xl font-bold ${c.color} tabular-nums`}>
              {c.fmt(value)}
            </div>
          </div>
        );
      })}
    </div>
  );
};
