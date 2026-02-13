# Architecture / Архитектура

## System Overview

Sentinel DDoS is composed of several layers that work together to detect and mitigate Layer 7 DDoS attacks.

```
Internet Traffic
       │
       ▼
┌─────────────────────┐
│  Reverse Proxy Layer │  ← FastAPI catch-all route
│  (src/proxy/)        │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐     ┌──────────────────┐
│  Detection Engine    │────▶│  Rules Engine     │
│  (src/detection/)    │     │  (src/rules/)     │
│                      │     └──────────────────┘
│  • Baseline model    │
│  • Anomaly scorer    │
│  • Attack classifier │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐     ┌──────────────────┐
│  Mitigation Layer    │────▶│  Alert System     │
│  (src/mitigation/)   │     │  (src/alerts/)    │
│                      │     └──────────────────┘
│  • Rate limiter      │
│  • IP blocker        │
│  • JS challenge      │
└────────┬────────────┘
         │
         ▼
   Target Application
```

## Data Flow

1. **Request arrives** → Reverse proxy extracts client IP and fingerprint
2. **Blocklist check** → Is the IP already blocked?
3. **Rate limit check** → Redis sliding-window counter
4. **Detection scoring** → AI engine produces threat score (0.0 – 1.0)
5. **Mitigation decision** → Based on protection level and rules
6. **Forward or block** → Legitimate traffic reaches upstream; attacks are stopped

## Storage

| Store | Purpose |
|-------|---------|
| **Redis** | Real-time counters, rate limits, blocklists, session data |
| **SQLite** | Attack logs, traffic snapshots, persistent config |

## Components

### Reverse Proxy (`src/proxy/`)
- `handler.py` — catch-all FastAPI route, async httpx forwarding
- `fingerprint.py` — JA3/header-order fingerprinting

### Detection Engine (`src/detection/`)
- `engine.py` — orchestrator, background baseline learning
- `baseline.py` — sliding-window traffic model (mean/std RPS, headers, etc.)
- `scorer.py` — multi-signal anomaly scorer (z-scores + heuristics)
- `classifier.py` — attack-type classification (rule-based → ML in Phase 3)

### Mitigation (`src/mitigation/`)
- `rate_limiter.py` — Redis sorted-set sliding window (per-IP, per-subnet, global)
- `blocker.py` — IP/subnet block & allow lists
- `challenge.py` — JS challenge / proof-of-browser page

### Rules Engine (`src/rules/`)
- `engine.py` — YAML rule loader, path matching, escalation

### API (`src/api/`)
- `routes.py` — REST endpoints for dashboard (stats, blocking, settings)
- `websocket.py` — real-time traffic feed for dashboard

### Alerts (`src/alerts/`)
- `dispatcher.py` — Telegram + Webhook notification system

### Dashboard (`dashboard/`)
- React + TypeScript + Vite + Tailwind CSS
- Real-time traffic charts, blocked IPs management, Under Attack button
