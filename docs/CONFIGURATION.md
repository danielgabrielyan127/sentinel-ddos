# Configuration / Настройка

## Environment Variables

All settings are loaded from environment variables with prefix `SENTINEL_`.
You can also set them in a `.env` file.

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_DEBUG` | `false` | Enable debug mode (API docs, reload) |
| `SENTINEL_HOST` | `0.0.0.0` | Bind host |
| `SENTINEL_PORT` | `8000` | Bind port |
| `SENTINEL_LOG_LEVEL` | `info` | Logging level |
| `SENTINEL_TARGET_URL` | `http://localhost:3000` | Upstream app URL |
| `SENTINEL_PROXY_TIMEOUT` | `30.0` | Upstream request timeout (sec) |
| `SENTINEL_REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| `SENTINEL_DATABASE_URL` | `sqlite+aiosqlite:///./sentinel.db` | Database |
| `SENTINEL_PROTECTION_LEVEL` | `monitor` | Default level |
| `SENTINEL_RATE_LIMIT_PER_IP` | `100` | Requests/min per IP |
| `SENTINEL_RATE_LIMIT_PER_SUBNET` | `1000` | Requests/min per /24 |
| `SENTINEL_RATE_LIMIT_GLOBAL` | `10000` | Requests/min global |
| `SENTINEL_BASELINE_LEARNING_HOURS` | `24` | Hours before baseline is ready |
| `SENTINEL_ANOMALY_THRESHOLD` | `0.75` | Score to trigger mitigation |
| `SENTINEL_TELEGRAM_BOT_TOKEN` | — | Telegram bot token |
| `SENTINEL_TELEGRAM_CHAT_ID` | — | Telegram chat ID |
| `SENTINEL_WEBHOOK_URL` | — | Alert webhook URL |
| `SENTINEL_DASHBOARD_USERNAME` | `admin` | Dashboard login |
| `SENTINEL_DASHBOARD_PASSWORD` | `sentinel` | Dashboard password |
| `SENTINEL_JWT_SECRET` | `change-me-in-production` | JWT signing key |

## Protection Levels

| Level | Name | Behavior |
|-------|------|----------|
| 0 | `monitor` | Observe and collect data only |
| 1 | `js_challenge` | Serve JS challenge to suspicious clients |
| 2 | `rate_limit` | Enforce rate limits |
| 3 | `block` | Block IPs with high threat scores |
| 4 | `blackhole` | Full block + alert notifications |

## YAML Rules

Place `.yml` files in the `rules/` directory. See `rules/custom.example.yml` for format.
