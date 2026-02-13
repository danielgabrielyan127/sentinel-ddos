import React, { useState, useEffect } from "react";
import { fetchBlockedIPs, blockIP, unblockIP } from "../api/client";

export const BlockedIPs: React.FC = () => {
  const [ips, setIPs] = useState<string[]>([]);
  const [newIP, setNewIP] = useState("");
  const [reason, setReason] = useState("");
  const [loading, setLoading] = useState(false);

  const load = async () => {
    try {
      const data = await fetchBlockedIPs();
      setIPs(data.blocked_ips);
    } catch {
      console.error("Failed to fetch blocked IPs");
    }
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIP.trim()) return;
    setLoading(true);
    try {
      await blockIP(newIP.trim(), reason.trim() || "Manual block");
      setNewIP("");
      setReason("");
      await load();
    } catch {
      console.error("Failed to block IP");
    }
    setLoading(false);
  };

  const handleUnblock = async (ip: string) => {
    try {
      await unblockIP(ip);
      await load();
    } catch {
      console.error("Failed to unblock IP");
    }
  };

  return (
    <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-4 flex flex-col h-full">
      <h2 className="text-sm font-semibold text-gray-400 mb-3">
        Blocked IPs ({ips.length})
      </h2>

      {/* Add form */}
      <form onSubmit={handleBlock} className="flex gap-2 mb-3">
        <input
          type="text"
          placeholder="IP address"
          value={newIP}
          onChange={(e) => setNewIP(e.target.value)}
          className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        <input
          type="text"
          placeholder="Reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        <button
          type="submit"
          disabled={loading || !newIP.trim()}
          className="px-4 py-1.5 bg-red-600 hover:bg-red-700 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg text-sm font-medium text-white transition-colors"
        >
          Block
        </button>
      </form>

      {/* List */}
      <div className="flex-1 overflow-y-auto space-y-1 max-h-48 pr-1 custom-scrollbar">
        {ips.length === 0 && (
          <div className="text-gray-600 text-sm text-center py-4">
            No blocked IPs
          </div>
        )}
        {ips.map((ip) => (
          <div
            key={ip}
            className="flex items-center justify-between py-1.5 px-3 rounded-lg bg-gray-800/40 hover:bg-gray-800/80 transition-colors"
          >
            <span className="text-sm text-gray-300 font-mono">{ip}</span>
            <button
              onClick={() => handleUnblock(ip)}
              className="text-xs text-gray-500 hover:text-red-400 transition-colors"
            >
              Unblock
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};
