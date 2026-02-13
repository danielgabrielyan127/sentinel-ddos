import React from "react";
import { toggleUnderAttack } from "../api/client";

interface Props {
  underAttack: boolean;
  connected: boolean;
  onToggle: () => void;
}

export const Header: React.FC<Props> = ({
  underAttack,
  connected,
  onToggle,
}) => {
  const handleToggle = async () => {
    try {
      await toggleUnderAttack(!underAttack);
      onToggle();
    } catch {
      console.error("Failed to toggle under-attack mode");
    }
  };

  return (
    <header className="flex items-center justify-between px-6 py-4 bg-gray-900 border-b border-gray-800">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
          <span className="text-white font-bold text-sm">S</span>
        </div>
        <h1 className="text-xl font-bold text-white tracking-tight">
          Sentinel DDoS
        </h1>
        <span
          className={`ml-2 text-xs px-2 py-0.5 rounded-full font-medium ${
            connected
              ? "bg-green-500/20 text-green-400"
              : "bg-red-500/20 text-red-400"
          }`}
        >
          {connected ? "Live" : "Disconnected"}
        </span>
      </div>
      <button
        onClick={handleToggle}
        className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all ${
          underAttack
            ? "bg-red-600 hover:bg-red-700 text-white shadow-red-500/25 shadow-lg"
            : "bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700"
        }`}
      >
        {underAttack ? "🛡️ Under Attack — ON" : "Under Attack Mode"}
      </button>
    </header>
  );
};
