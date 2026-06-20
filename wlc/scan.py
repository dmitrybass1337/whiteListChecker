"""Движок скана: пул воркеров + token-bucket рейт-лимит, стрим в JSONL.

Используется обоими режимами. В режиме ноута на вход обычно подаётся уже
отфильтрованный zmap'ом список откликнувшихся адресов (быстрее), в Termux —
сразу список целей по 1 IP/24.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from typing import Iterator, TextIO

from .probe import probe_ip


class _RateLimiter:
    """Простой token bucket: не более `rate` проб/сек (rate<=0 — без лимита)."""

    def __init__(self, rate: float):
        self.rate = rate
        self.tokens = rate
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.rate <= 0:
            return
        async with self._lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.rate, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                await asyncio.sleep((1 - self.tokens) / self.rate)


def iter_targets(fh: TextIO) -> Iterator[str]:
    for line in fh:
        ip = line.strip()
        if ip and not ip.startswith("#"):
            yield ip


async def run_scan(
    targets: Iterator[str],
    ports: list[int],
    concurrency: int,
    rate: float,
    out: TextIO,
    timeout: float = 4.0,
    progress_every: int = 5000,
) -> dict:
    queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=concurrency * 4)
    limiter = _RateLimiter(rate)
    stats = {"probed": 0, "open": 0, "started": time.monotonic()}
    write_lock = asyncio.Lock()

    async def worker() -> None:
        while True:
            ip = await queue.get()
            if ip is None:
                queue.task_done()
                return
            try:
                await limiter.acquire()
                res = await probe_ip(ip, ports, timeout)
                line = json.dumps(res.to_dict(), separators=(",", ":"))
                async with write_lock:
                    out.write(line + "\n")
                    stats["probed"] += 1
                    if any(p.state == "OPEN" for p in res.ports):
                        stats["open"] += 1
                    if stats["probed"] % progress_every == 0:
                        _print_progress(stats)
            except Exception as e:  # noqa: BLE001 — воркер не должен падать
                sys.stderr.write(f"[err] {ip}: {e}\n")
            finally:
                queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]

    fed = 0
    for ip in targets:
        await queue.put(ip)
        fed += 1
    for _ in workers:
        await queue.put(None)
    await queue.join()
    await asyncio.gather(*workers)

    stats["elapsed"] = time.monotonic() - stats["started"]
    stats["fed"] = fed
    _print_progress(stats, final=True)
    return stats


def _print_progress(stats: dict, final: bool = False) -> None:
    elapsed = time.monotonic() - stats["started"]
    pps = stats["probed"] / elapsed if elapsed else 0
    tag = "DONE " if final else "scan "
    sys.stderr.write(
        f"\r[{tag}] probed={stats['probed']} open={stats['open']} "
        f"{pps:.0f} pps elapsed={elapsed:.0f}s" + ("\n" if final else "")
    )
    sys.stderr.flush()
