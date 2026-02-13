import { useState, useEffect } from "react";
import { Header } from "./components/Header";
import { StatsCards } from "./components/StatsCards";
import { TrafficChart } from "./components/TrafficChart";
import { ThreatFeed } from "./components/ThreatFeed";
import { BlockedIPs } from "./components/BlockedIPs";
import { AttackMap } from "./components/AttackMap";
import { MLStatusCard } from "./components/MLStatusCard";
import { useWebSocket } from "./hooks/useWebSocket";
import { fetchStats } from "./api/client";

function App() {
  const { dataPoints, liveStats, events, connected } = useWebSocket("/ws");
  const [underAttack, setUnderAttack] = useState(false);

  // Fetch initial stats to get under_attack_mode
  useEffect(() => {
    fetchStats()
      .then((s) => setUnderAttack(s.under_attack_mode))
      .catch(() => {});
  }, []);

  return (
    <div className="min-h-screen bg-gray-950 text-white flex flex-col">
      <Header
        underAttack={underAttack}
        connected={connected}
        onToggle={() => setUnderAttack((v) => !v)}
      />

      <main className="flex-1 p-6 space-y-4 max-w-7xl mx-auto w-full">
        {/* Stats Row */}
        <StatsCards stats={liveStats} />

        {/* Chart */}
        <TrafficChart data={dataPoints} />

        {/* Attack Map */}
        <AttackMap />

        {/* Bottom grid: Threat Feed + Blocked IPs + ML Status */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <ThreatFeed events={events} />
          <BlockedIPs />
          <MLStatusCard />
        </div>
      </main>

      <footer className="text-center text-xs text-gray-700 py-3 border-t border-gray-900">
        Sentinel DDoS &mdash; AI-Powered Anti-DDoS L7 Firewall
      </footer>
    </div>
  );
}

export default App;
