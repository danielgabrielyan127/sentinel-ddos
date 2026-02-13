import React from "react";
import type { SecurityEvent } from "../api/client";

interface Props {
  events: SecurityEvent[];
}

const actionColor: Record<string, string> = {
  blocked: "text-red-400 bg-red-500/10",
  rate_limited: "text-yellow-400 bg-yellow-500/10",
  challenged: "text-orange-400 bg-orange-500/10",
  monitored: "text-blue-400 bg-blue-500/10",
  forwarded: "text-green-400 bg-green-500/10",
};

export const ThreatFeed: React.FC<Props> = ({ events }) => {
  return (
    <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-4 flex flex-col h-full">
      <h2 className="text-sm font-semibold text-gray-400 mb-3">
        Threat Feed
      </h2>
      <div className="flex-1 overflow-y-auto space-y-1.5 max-h-72 pr-1 custom-scrollbar">
        {events.length === 0 && (
          <div className="text-gray-600 text-sm text-center py-8">
            No events yet
          </div>
        )}
        {events.map((evt, i) => {
          const colorCls =
            actionColor[evt.action] ?? "text-gray-400 bg-gray-500/10";
          const time = new Date(evt.time * 1000).toLocaleTimeString();
          return (
            <div
              key={`${evt.time}-${evt.ip}-${i}`}
              className="flex items-center gap-2 text-xs py-1.5 px-2 rounded-lg bg-gray-800/40 hover:bg-gray-800/80 transition-colors"
            >
              <span className="text-gray-500 w-16 shrink-0 tabular-nums">
                {time}
              </span>
              <span
                className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${colorCls}`}
              >
                {evt.action}
              </span>
              <span className="text-gray-300 font-mono">{evt.ip}</span>
              <span className="text-gray-500 truncate">
                {evt.method} {evt.path}
              </span>
              {evt.score !== undefined && (
                <span className="ml-auto text-gray-500 tabular-nums">
                  {evt.score.toFixed(2)}
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
