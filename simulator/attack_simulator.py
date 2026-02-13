"""
Sentinel DDoS — Built-in Attack Simulator.

Generates synthetic attack traffic for testing the detection engine.
Supports: HTTP Flood, Slowloris, Distributed simulation, Mixed traffic.
"""

from __future__ import annotations

import asyncio
import logging
import random
import string
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx

logger = logging.getLogger("sentinel.simulator")

# Realistic browser user-agents for legitimate traffic simulation
_REAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

# Bot-like user-agents for attack simulation
_BOT_UAS = [
    "",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "curl/7.88.1",
    "Java/17.0.1",
]

# Paths for realistic browsing patterns
_LEGIT_PATHS = [
    "/", "/about", "/contact", "/products", "/blog",
    "/blog/post-1", "/blog/post-2", "/faq", "/pricing",
    "/static/css/style.css", "/static/js/app.js",
    "/static/images/logo.png", "/api/products",
]

# Paths that attackers target
_ATTACK_PATHS = [
    "/", "/api/login", "/api/search", "/api/data",
    "/admin", "/wp-login.php", "/xmlrpc.php",
]


class AttackScenario(str, Enum):
    HTTP_FLOOD = "http_flood"
    SLOWLORIS = "slowloris"
    DISTRIBUTED = "distributed"
    MIXED = "mixed"


@dataclass
class SimulatorConfig:
    """Configuration for an attack simulation."""
    target_url: str = "http://localhost:8000"
    scenario: AttackScenario = AttackScenario.HTTP_FLOOD
    duration_sec: int = 30
    concurrency: int = 50
    rps: int = 500
    source_ips: int = 10  # simulated unique IPs (via X-Forwarded-For)


@dataclass
class SimulatorReport:
    """Results from a simulation run."""
    scenario: str
    duration_sec: float
    total_requests: int = 0
    successful: int = 0
    blocked: int = 0
    rate_limited: int = 0
    challenged: int = 0
    errors: int = 0
    avg_latency_ms: float = 0.0
    detection_time_sec: float = 0.0  # time until first block/rate-limit
    unique_ips_used: int = 0

    @property
    def block_rate(self) -> float:
        return (self.blocked + self.rate_limited) / max(1, self.total_requests) * 100

    def summary(self) -> str:
        return (
            f"\n{'='*55}\n"
            f"   Simulation Report: {self.scenario}\n"
            f"{'='*55}\n"
            f"  Duration:        {self.duration_sec:.1f}s\n"
            f"  Total Requests:  {self.total_requests}\n"
            f"  Successful:      {self.successful}\n"
            f"  Blocked:         {self.blocked}\n"
            f"  Rate Limited:    {self.rate_limited}\n"
            f"  Challenged:      {self.challenged}\n"
            f"  Errors:          {self.errors}\n"
            f"  Block Rate:      {self.block_rate:.1f}%\n"
            f"  Avg Latency:     {self.avg_latency_ms:.1f}ms\n"
            f"  Detection Time:  {self.detection_time_sec:.2f}s\n"
            f"  Unique IPs:      {self.unique_ips_used}\n"
            f"{'='*55}\n"
        )


class AttackSimulator:
    """Generates synthetic attack traffic against Sentinel."""

    def __init__(self, config: SimulatorConfig) -> None:
        self.config = config
        self.report = SimulatorReport(
            scenario=config.scenario.value,
            duration_sec=config.duration_sec,
        )
        self._stop = False
        self._latencies: list[float] = []
        self._first_block_time: float = 0.0
        self._start_time: float = 0.0
        self._ips_used: set[str] = set()

    def _record_response(self, status_code: int, latency_ms: float) -> None:
        """Record response stats."""
        self.report.total_requests += 1
        self._latencies.append(latency_ms)

        if status_code == 200:
            self.report.successful += 1
        elif status_code == 403:
            self.report.blocked += 1
            if not self._first_block_time:
                self._first_block_time = time.time()
        elif status_code == 429:
            self.report.rate_limited += 1
            if not self._first_block_time:
                self._first_block_time = time.time()
        elif status_code == 503:
            self.report.challenged += 1
        else:
            self.report.errors += 1

    def _random_ip(self, pool_size: int | None = None) -> str:
        """Generate a random simulated IP."""
        n = pool_size or self.config.source_ips
        ip = f"10.{random.randint(0, 255)}.{random.randint(0, min(n, 255))}.{random.randint(1, 254)}"
        self._ips_used.add(ip)
        return ip

    async def run(self) -> SimulatorReport:
        """Run the selected attack scenario."""
        self._start_time = time.time()
        logger.info(
            "Starting %s simulation (%ds, %d RPS, %d concurrent)",
            self.config.scenario.value,
            self.config.duration_sec,
            self.config.rps,
            self.config.concurrency,
        )

        runners = {
            AttackScenario.HTTP_FLOOD: self._http_flood,
            AttackScenario.SLOWLORIS: self._slowloris,
            AttackScenario.DISTRIBUTED: self._distributed,
            AttackScenario.MIXED: self._mixed,
        }

        runner = runners.get(self.config.scenario, self._http_flood)
        await runner()

        if self._latencies:
            self.report.avg_latency_ms = sum(self._latencies) / len(self._latencies)
        if self._first_block_time:
            self.report.detection_time_sec = self._first_block_time - self._start_time
        self.report.unique_ips_used = len(self._ips_used)

        return self.report

    # ── Scenario 1: HTTP Flood ───────────────────────────

    async def _http_flood(self) -> None:
        """
        HTTP GET flood from a small pool of IPs.

        Characteristics:
          - Empty or bot-like User-Agent
          - High RPS from few IPs
          - Same path repeated
          - No cookies, no referer
        """
        async with httpx.AsyncClient(timeout=5) as client:
            end_time = time.time() + self.config.duration_sec
            sem = asyncio.Semaphore(self.config.concurrency)

            async def send():
                async with sem:
                    if time.time() > end_time:
                        return
                    ip = self._random_ip()
                    path = random.choice(_ATTACK_PATHS[:4])
                    start = time.monotonic()
                    try:
                        resp = await client.get(
                            f"{self.config.target_url}{path}",
                            headers={
                                "X-Forwarded-For": ip,
                                "User-Agent": random.choice(_BOT_UAS),
                            },
                        )
                        latency = (time.monotonic() - start) * 1000
                        self._record_response(resp.status_code, latency)
                    except Exception:
                        self.report.errors += 1
                        self.report.total_requests += 1

            while time.time() < end_time:
                tasks = [asyncio.create_task(send()) for _ in range(self.config.rps)]
                await asyncio.gather(*tasks)
                await asyncio.sleep(1)

    # ── Scenario 2: Slowloris ────────────────────────────

    async def _slowloris(self) -> None:
        """
        Slowloris attack — opens many connections and sends data very slowly,
        tying up server resources with incomplete requests.

        Characteristics:
          - POST requests with no body or trickled body
          - Very slow sending (partial headers/data)
          - Maintains many concurrent connections
          - Moderate number of IPs
        """
        end_time = time.time() + self.config.duration_sec
        connections = min(self.config.concurrency, 200)

        async def slow_connection(conn_id: int):
            """Maintain a single slow connection."""
            while time.time() < end_time:
                ip = self._random_ip()
                start = time.monotonic()
                try:
                    # Use raw httpx stream to simulate slow sending
                    async with httpx.AsyncClient(timeout=30) as client:
                        # Send a POST with trickled content
                        path = random.choice(["/", "/api/data", "/upload", "/submit"])

                        # First: try a slow POST with minimal body
                        resp = await client.post(
                            f"{self.config.target_url}{path}",
                            headers={
                                "X-Forwarded-For": ip,
                                "User-Agent": random.choice(_BOT_UAS),
                                "Content-Type": "application/x-www-form-urlencoded",
                                "Content-Length": "10000",  # claim large body
                            },
                            content=b"x=1",  # send tiny body vs claimed size
                        )
                        latency = (time.monotonic() - start) * 1000
                        self._record_response(resp.status_code, latency)

                    # Slowloris pacing — wait 2-5 seconds between reconnects
                    await asyncio.sleep(random.uniform(2, 5))

                except Exception:
                    self.report.errors += 1
                    self.report.total_requests += 1
                    await asyncio.sleep(1)

        logger.info(
            "Slowloris: %d slow connections for %ds",
            connections, self.config.duration_sec,
        )
        tasks = [asyncio.create_task(slow_connection(i)) for i in range(connections)]
        await asyncio.gather(*tasks)

    # ── Scenario 3: Distributed ──────────────────────────

    async def _distributed(self) -> None:
        """
        Distributed DDoS — many unique IPs sending moderate traffic each.

        Characteristics:
          - Thousands of unique IPs (simulates botnet)
          - Each IP sends few requests (below per-IP rate limit)
          - Mix of bot and real-looking user agents
          - Targets multiple paths
          - Harder to detect: no single IP triggers rate limit
        """
        async with httpx.AsyncClient(timeout=5) as client:
            end_time = time.time() + self.config.duration_sec
            sem = asyncio.Semaphore(self.config.concurrency)
            # Use a large pool of unique IPs
            ip_pool_size = max(500, self.config.source_ips * 50)

            async def send():
                async with sem:
                    if time.time() > end_time:
                        return
                    # Each request from a different IP
                    ip = self._random_ip(pool_size=ip_pool_size)
                    path = random.choice(_ATTACK_PATHS)
                    # Mix: 60% bot-like UA, 40% real-looking UA
                    if random.random() < 0.6:
                        ua = random.choice(_BOT_UAS)
                    else:
                        ua = random.choice(_REAL_UAS)

                    headers = {
                        "X-Forwarded-For": ip,
                        "User-Agent": ua,
                    }
                    # Some requests include accept-language (look more human)
                    if random.random() < 0.3:
                        headers["Accept-Language"] = "en-US,en;q=0.9"

                    start = time.monotonic()
                    try:
                        resp = await client.get(
                            f"{self.config.target_url}{path}",
                            headers=headers,
                        )
                        latency = (time.monotonic() - start) * 1000
                        self._record_response(resp.status_code, latency)
                    except Exception:
                        self.report.errors += 1
                        self.report.total_requests += 1

            logger.info(
                "Distributed DDoS: ~%d unique IPs, %d RPS for %ds",
                ip_pool_size, self.config.rps, self.config.duration_sec,
            )
            while time.time() < end_time:
                tasks = [asyncio.create_task(send()) for _ in range(self.config.rps)]
                await asyncio.gather(*tasks)
                await asyncio.sleep(1)

    # ── Scenario 4: Mixed Traffic ────────────────────────

    async def _mixed(self) -> None:
        """
        Mixed traffic — realistic blend of legitimate users and attack traffic.

        Runs two streams concurrently:
          1. Legitimate user traffic (real UAs, diverse paths, human timing)
          2. Attack traffic (bot UAs, targeted paths, high rate)

        This tests false-positive rates — legitimate traffic should pass
        while attack traffic gets blocked.
        """
        end_time = time.time() + self.config.duration_sec
        # Split: 30% legitimate, 70% attack
        legit_rps = max(5, self.config.rps // 3)
        attack_rps = self.config.rps - legit_rps

        legit_report = {"total": 0, "passed": 0, "blocked": 0}

        async def legit_user(user_id: int):
            """Simulate a single human user browsing the site."""
            async with httpx.AsyncClient(timeout=10) as client:
                ip = f"192.168.{user_id // 256}.{user_id % 256 + 1}"
                self._ips_used.add(ip)
                ua = random.choice(_REAL_UAS)
                pages = list(_LEGIT_PATHS)
                random.shuffle(pages)
                referer = None

                for path in pages:
                    if time.time() > end_time:
                        return
                    headers = {
                        "X-Forwarded-For": ip,
                        "User-Agent": ua,
                        "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
                        "Accept": "text/html,application/xhtml+xml",
                    }
                    if referer:
                        headers["Referer"] = f"{self.config.target_url}{referer}"
                    headers["Cookie"] = f"session=usr{user_id}"

                    start = time.monotonic()
                    try:
                        resp = await client.get(
                            f"{self.config.target_url}{path}",
                            headers=headers,
                        )
                        latency = (time.monotonic() - start) * 1000
                        self._record_response(resp.status_code, latency)
                        legit_report["total"] += 1
                        if resp.status_code == 200:
                            legit_report["passed"] += 1
                        elif resp.status_code in (403, 429):
                            legit_report["blocked"] += 1
                    except Exception:
                        self.report.errors += 1
                        self.report.total_requests += 1

                    referer = path
                    # Human-like timing: 1-5 second pauses
                    await asyncio.sleep(random.uniform(1.0, 5.0))

        async def attack_stream():
            """Concurrent attack traffic (HTTP Flood)."""
            async with httpx.AsyncClient(timeout=5) as client:
                sem = asyncio.Semaphore(self.config.concurrency)

                async def send():
                    async with sem:
                        if time.time() > end_time:
                            return
                        ip = self._random_ip()
                        path = random.choice(_ATTACK_PATHS[:4])
                        start = time.monotonic()
                        try:
                            resp = await client.get(
                                f"{self.config.target_url}{path}",
                                headers={
                                    "X-Forwarded-For": ip,
                                    "User-Agent": random.choice(_BOT_UAS),
                                },
                            )
                            latency = (time.monotonic() - start) * 1000
                            self._record_response(resp.status_code, latency)
                        except Exception:
                            self.report.errors += 1
                            self.report.total_requests += 1

                while time.time() < end_time:
                    tasks = [asyncio.create_task(send()) for _ in range(attack_rps)]
                    await asyncio.gather(*tasks)
                    await asyncio.sleep(1)

        # Launch legitimate users and attack stream concurrently
        n_users = max(5, legit_rps)
        logger.info(
            "Mixed: %d legit users + %d attack RPS for %ds",
            n_users, attack_rps, self.config.duration_sec,
        )
        user_tasks = [asyncio.create_task(legit_user(i)) for i in range(n_users)]
        attack_task = asyncio.create_task(attack_stream())

        await asyncio.gather(attack_task, *user_tasks)

        # Append false-positive stats to report summary
        fp_rate = (
            legit_report["blocked"] / max(1, legit_report["total"]) * 100
        )
        logger.info(
            "Mixed results — Legit: %d total, %d passed, %d blocked (FP rate: %.1f%%)",
            legit_report["total"], legit_report["passed"],
            legit_report["blocked"], fp_rate,
        )


async def run_simulation(
    scenario: str = "http_flood",
    target: str = "http://localhost:8000",
    duration: int = 30,
    rps: int = 100,
    concurrency: int = 50,
    source_ips: int = 10,
) -> SimulatorReport:
    """Convenience function to run a simulation."""
    config = SimulatorConfig(
        target_url=target,
        scenario=AttackScenario(scenario),
        duration_sec=duration,
        rps=rps,
        concurrency=concurrency,
        source_ips=source_ips,
    )
    sim = AttackSimulator(config)
    report = await sim.run()
    print(report.summary())
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Sentinel DDoS Attack Simulator")
    parser.add_argument("scenario", nargs="?", default="http_flood",
                        choices=["http_flood", "slowloris", "distributed", "mixed"])
    parser.add_argument("--target", default="http://localhost:8000")
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--rps", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=50)
    parser.add_argument("--source-ips", type=int, default=10)
    args = parser.parse_args()

    asyncio.run(run_simulation(
        scenario=args.scenario,
        target=args.target,
        duration=args.duration,
        rps=args.rps,
        concurrency=args.concurrency,
        source_ips=args.source_ips,
    ))
