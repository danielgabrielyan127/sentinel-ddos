# Roadmap / План развития

## Phase 1 — Core (MVP) ✨
- [x] Project structure and documentation
- [ ] Async reverse proxy (FastAPI + httpx)
- [ ] Redis-based rate limiter (per IP, per subnet)
- [ ] Basic dashboard with real-time traffic graph
- [ ] Manual IP blocking via UI
- [ ] Docker Compose deployment

## Phase 2 — Smart Detection 🧠
- [ ] JA3/JA4 TLS fingerprinting
- [ ] Baseline learning engine
- [ ] Anomaly detection (deviation from baseline)
- [ ] JS Challenge / Proof of Work
- [ ] YAML rules engine
- [ ] Behavioral analysis (bot vs human)

## Phase 3 — AI Layer 🤖
- [ ] ML attack classifier (HTTP Flood, Slowloris, etc.)
- [ ] Automated graduated response
- [ ] Live attack map (GeoIP + WebSocket)
- [ ] Telegram alerts
- [ ] Built-in attack simulator
- [ ] Attack history and analytics

## Phase 4 — Advanced 🚀
- [ ] Distributed mode (multiple nodes sharing threat data)
- [ ] Community threat intelligence feed
- [ ] Plugin system for custom detectors
- [ ] API for external integrations
- [ ] Performance optimizations (XDP/eBPF)
