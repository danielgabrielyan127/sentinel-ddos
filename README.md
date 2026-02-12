<div align="center">

```
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                    ██████╗ ██████╗  ██████╗ ███████╗
                    ██╔══██╗██╔══██╗██╔═══██╗██╔════╝
                    ██║  ██║██║  ██║██║   ██║███████╗
                    ██║  ██║██║  ██║██║   ██║╚════██║
                    ██████╔╝██████╔╝╚██████╔╝███████║
                    ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝
```

# 🛡️ Sentinel DDoS

### AI-Powered Anti-DDoS L7 Firewall

Self-hosted intelligent reverse proxy with ML-based threat detection, real-time traffic analysis, and beautiful dashboard.

Самостоятельный интеллектуальный обратный прокси с ML-детекцией угроз, анализом трафика в реальном времени и красивым дашбордом.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-blue.svg)](https://www.docker.com/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

[English](#-overview) • [Русский](#-обзор) • [Quick Start](#-quick-start) • [Documentation](#-documentation)

</div>

---

## 🌍 Overview

**Sentinel DDoS** is a self-hosted AI-powered Layer 7 Anti-DDoS firewall that sits as a reverse proxy in front of your application and intelligently filters malicious traffic.

Think of it as **self-hosted Cloudflare** — but you control everything, your traffic stays on your servers, and it's completely free and open source.

### Why Sentinel?

| Problem | Solution |
|---------|----------|
| Cloudflare is expensive and you send all traffic through a third party | Self-hosted, your data stays with you |
| nginx + fail2ban is primitive | ML-based anomaly detection + behavioral analysis |
| No visibility into attacks | Beautiful real-time dashboard with attack map |
| Manual IP blocking | Automated graduated response system |
| Hard to test DDoS protection | Built-in attack simulator |

---

## 🌍 Обзор

**Sentinel DDoS** — это self-hosted AI-файрвол уровня L7, который работает как обратный прокси перед вашим приложением и интеллектуально фильтрует вредоносный трафик.

Это **self-hosted Cloudflare** — но вы контролируете всё, ваш трафик остаётся на ваших серверах, и это полностью бесплатно и с открытым исходным кодом.

### Почему Sentinel?

| Проблема | Решение |
|----------|---------|
| Cloudflare дорогой и весь трафик идёт через третью сторону | Self-hosted, данные остаются у вас |
| nginx + fail2ban — примитив | ML-детекция аномалий + поведенческий анализ |
| Нет видимости атак | Красивый real-time дашборд с картой атак |
| Ручная блокировка IP | Автоматическая градуированная система ответа |
| Сложно тестировать защиту | Встроенный симулятор атак |

---

## ✨ Key Features / Ключевые возможности

### 🧠 AI Detection Engine
- **Baseline Learning** — learns your "normal" traffic pattern over 24-72 hours
- **Anomaly Detection** — detects deviations from baseline in real-time
- **Attack Classification** — identifies attack type: HTTP Flood, Slowloris, API abuse, credential stuffing

### 🔍 Traffic Fingerprinting
- **JA3/JA4 TLS Fingerprinting** — identifies clients by their TLS handshake
- **Behavioral Analysis** — distinguishes bots from humans by navigation patterns and timing
- **Request Scoring** — every request gets a threat score based on multiple signals

### 🚦 Graduated Response / Градуированный ответ
```
🟢 Level 0: Monitor     — наблюдение, сбор данных
🟡 Level 1: JS Challenge — proof of browser (JavaScript challenge)
🟠 Level 2: Rate Limit   — ограничение частоты запросов
🔴 Level 3: Block        — блокировка IP/подсети
⛔ Level 4: Blackhole    — полная блокировка + уведомление
```

### 📊 Real-Time Dashboard
- **Live Attack Map** — world map with attack sources in real-time
- **Traffic Graphs** — normal traffic vs attack visualization
- **Threat Feed** — live stream of blocked threats
- **Top Attackers** — table of most active attackers
- **Under Attack Button** — one-click maximum protection mode

### ⚙️ Rules Engine
```yaml
rules:
  - name: "API Login Protection"
    match:
      path: "/api/login"
      method: "POST"
    limits:
      per_ip: 5/minute
      per_subnet: 50/minute
    escalation:
      - threshold: 80%
        action: js_challenge
      - threshold: 95%
        action: block
        duration: 1h
```

### 🧪 Built-in Attack Simulator
- Test your protection without external tools
- Scenarios: HTTP Flood, Slowloris, distributed simulation, mixed traffic
- Detailed reports: detection time, false positives, blocked percentage

### 🔔 Alerts
- Telegram bot notifications
- Webhook integration
- Configurable alert thresholds

---

## 🏗️ Architecture / Архитектура

```
                         ┌──────────────────────────────────────┐
                         │          Dashboard (TS/React)         │
                         │   Live graphs • Attack map • Controls │
                         └────────────────┬─────────────────────┘
                                          │ API + WebSocket
                         ┌────────────────▼─────────────────────┐
                         │          FastAPI Core                 │
                         │                                       │
                         │  ┌─────────────────────────────┐     │
                         │  │    AI Detection Engine       │     │
                         │  │  • Baseline model            │     │
                         │  │  • Anomaly scorer            │     │
                         │  │  • Attack classifier         │     │
                         │  │  • JA3/JA4 fingerprinting    │     │
                         │  └─────────────────────────────┘     │
                         │  ┌─────────────────────────────┐     │
                         │  │    Rules Engine              │     │
                         │  │  • YAML rules parser         │     │
                         │  │  • Escalation manager        │     │
                         │  └─────────────────────────────┘     │
                         │  ┌─────────────────────────────┐     │
                         │  │    Mitigation Controller     │     │
                         │  │  • Rate limiter (Redis)      │     │
                         │  │  • JS Challenge server       │     │
                         │  │  • IP/Subnet blocker         │     │
                         │  └─────────────────────────────┘     │
                         └────────────────┬─────────────────────┘
                                          │
Incoming Traffic ─────────►  Reverse Proxy Layer  ─────────► Target App
                                          │
                         ┌────────────────▼─────────────────────┐
                         │          Storage Layer                │
                         │  • Redis — real-time counters,       │
                         │    rate limits, IP reputation         │
                         │  • SQLite — config, rules, history   │
                         └──────────────────────────────────────┘
```

---

## 📁 Project Structure / Структура проекта

```
sentinel-ddos/
├── src/                          # Backend (FastAPI)
│   ├── main.py                   # Application entry point
│   ├── config.py                 # Settings (Pydantic)
│   ├── proxy/                    # Reverse proxy core
│   ├── detection/                # AI detection engine
│   ├── mitigation/               # Rate limiting, blocking, challenges
│   ├── rules/                    # YAML rules engine
│   ├── alerts/                   # Telegram, webhooks
│   ├── api/                      # REST API + WebSocket
│   └── storage/                  # Redis, database
├── dashboard/                    # Frontend (React + TypeScript)
│   └── src/
│       └── components/           # UI components
├── simulator/                    # Built-in attack simulator
├── rules/                        # YAML rule definitions
├── tests/                        # Test suite
├── docs/                         # Documentation
├── docker-compose.yml            # Production deployment
├── docker-compose.test.yml       # Testing lab
├── Dockerfile                    # Container build
└── Makefile                      # Dev commands
```

---

## 🚀 Quick Start

### Prerequisites / Требования
- Docker & Docker Compose
- Git

### 1. Clone the repository / Клонирование
```bash
git clone https://github.com/danielgabrielyan127/sentinel-ddos.git
cd sentinel-ddos
```

### 2. Configure / Настройка
```bash
cp .env.example .env
# Edit .env with your settings / Отредактируйте .env
```

### 3. Start Sentinel / Запуск
```bash
docker-compose up -d
```

### 4. Open Dashboard / Открыть дашборд
```
http://localhost:8080
```

### 5. Test with Attack Simulator / Тестирование
```bash
# Start the test lab / Запуск тестовой лаборатории
docker-compose -f docker-compose.test.yml up -d

# Run HTTP Flood simulation / Симуляция HTTP Flood
make attack-test
```

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| **Backend / API** | Python 3.11+, FastAPI, Uvicorn |
| **AI/ML** | scikit-learn, NumPy |
| **Real-time Storage** | Redis |
| **Dashboard** | TypeScript, React, Vite, D3.js |
| **Reverse Proxy** | httpx (async) |
| **Firewall Control** | nftables / iptables |
| **Alerts** | Telegram Bot API, Webhooks |
| **Config** | YAML, Pydantic Settings |
| **Deployment** | Docker, Docker Compose |
| **Testing** | pytest, Locust |

---

## 📋 Roadmap

### Phase 1 — Core (MVP) ✨
- [x] Project structure and documentation
- [ ] Async reverse proxy (FastAPI + httpx)
- [ ] Redis-based rate limiter (per IP, per subnet)
- [ ] Basic dashboard with real-time traffic graph
- [ ] Manual IP blocking via UI
- [ ] Docker Compose deployment

### Phase 2 — Smart Detection 🧠
- [ ] JA3/JA4 TLS fingerprinting
- [ ] Baseline learning engine
- [ ] Anomaly detection (deviation from baseline)
- [ ] JS Challenge / Proof of Work
- [ ] YAML rules engine
- [ ] Behavioral analysis (bot vs human)

### Phase 3 — AI Layer 🤖
- [ ] ML attack classifier (HTTP Flood, Slowloris, etc.)
- [ ] Automated graduated response
- [ ] Live attack map (GeoIP + WebSocket)
- [ ] Telegram alerts
- [ ] Built-in attack simulator
- [ ] Attack history and analytics

### Phase 4 — Advanced 🚀
- [ ] Distributed mode (multiple nodes sharing threat data)
- [ ] Community threat intelligence feed
- [ ] Plugin system for custom detectors
- [ ] API for external integrations
- [ ] Performance optimizations (XDP/eBPF)

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | Detailed system architecture / Детальная архитектура |
| [Configuration](docs/CONFIGURATION.md) | Configuration guide / Руководство по настройке |
| [Roadmap](docs/ROADMAP.md) | Detailed roadmap / Подробный план развития |
| [Contributing](docs/CONTRIBUTING.md) | Contribution guide / Руководство для контрибьюторов |

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](docs/CONTRIBUTING.md) for details.

Мы рады вкладу в проект! Ознакомьтесь с [руководством для контрибьюторов](docs/CONTRIBUTING.md).

---

## 🏢 Partners / Партнёры

> We are actively looking for infrastructure partners for testing and development.
>
> Мы активно ищем партнёров по инфраструктуре для тестирования и разработки.

*Partner logos will appear here / Логотипы партнёров появятся здесь*

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with ❤️ for sysadmins, by sysadmins**

**Создано с ❤️ для сисадминов, сисадминами**

[⬆ Back to top](#-sentinel-ddos)

</div>
