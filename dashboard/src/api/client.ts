const API_BASE = "/api";

export interface Stats {
  uptime: number;
  protection_level: string;
  under_attack_mode: boolean;
  baseline_ready: boolean;
  observation_count: number;
  blocked_ips_count: number;
  target_url: string;
  total_requests: number;
  forwarded_requests: number;
  blocked_requests: number;
  rate_limited_requests: number;
  requests_per_second: number;
  active_ips_count: number;
}

export interface SecurityEvent {
  time: number;
  ip: string;
  action: string;
  path: string;
  method: string;
  score?: number;
}

export interface TrafficUpdate {
  type: string;
  timestamp: number;
  rps: number;
  total_requests: number;
  blocked_requests: number;
  rate_limited_requests: number;
  forwarded_requests: number;
  active_ips: number;
  observation_count: number;
  baseline_ready: boolean;
  mean_rps: number;
  new_events: SecurityEvent[];
}

export async function fetchStats(): Promise<Stats> {
  const res = await fetch(`${API_BASE}/stats`);
  if (!res.ok) throw new Error("Failed to fetch stats");
  return res.json();
}

export async function fetchBlockedIPs(): Promise<{
  blocked_ips: string[];
  count: number;
}> {
  const res = await fetch(`${API_BASE}/blocked`);
  if (!res.ok) throw new Error("Failed to fetch blocked IPs");
  return res.json();
}

export async function fetchEvents(): Promise<{
  events: SecurityEvent[];
  count: number;
}> {
  const res = await fetch(`${API_BASE}/events`);
  if (!res.ok) throw new Error("Failed to fetch events");
  return res.json();
}

export async function blockIP(
  ip: string,
  reason: string = "",
  durationSec?: number
): Promise<void> {
  await fetch(`${API_BASE}/block`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, reason, duration_sec: durationSec }),
  });
}

export async function unblockIP(ip: string): Promise<void> {
  await fetch(`${API_BASE}/unblock`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip }),
  });
}

export async function setProtectionLevel(level: string): Promise<void> {
  await fetch(`${API_BASE}/protection-level`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ level }),
  });
}

export async function toggleUnderAttack(enabled: boolean): Promise<void> {
  await fetch(`${API_BASE}/under-attack`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled }),
  });
}

export interface AttackMapPoint {
  ip: string;
  action: string;
  latitude: number;
  longitude: number;
  country_code: string;
  country_name: string;
  score?: number;
  attack_type?: string;
}

export interface AttackMapData {
  points: AttackMapPoint[];
  by_country: { code: string; count: number }[];
  total_attacking_ips: number;
}

export interface MLStatus {
  is_ready: boolean;
  train_count: number;
  buffer_size: number;
  min_train_samples: number;
  last_trained: number | null;
  n_estimators: number;
  contamination: number;
}

export async function fetchAttackMap(): Promise<AttackMapData> {
  const res = await fetch(`${API_BASE}/attack-map`);
  if (!res.ok) throw new Error("Failed to fetch attack map");
  return res.json();
}

export async function fetchMLStatus(): Promise<MLStatus> {
  const res = await fetch(`${API_BASE}/ml/status`);
  if (!res.ok) throw new Error("Failed to fetch ML status");
  return res.json();
}
