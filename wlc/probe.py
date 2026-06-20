"""Асинхронный TCP/HTTP/TLS-проб одного адреса.

Работает только на stdlib (asyncio + ssl) — значит, одинаково запускается и в
Termux без root, и на ноуте. Никаких raw-сокетов: исход пробы определяется
поведением обычного `connect()`, чего достаточно для модели whitelist'а.

Состояния (`state`) на порт:
    OPEN     — TCP-хендшейк прошёл (для 443 — ещё и TLS); порт открыт
    PORTAL   — соединение прошло, но HTTP-ответ похож на заглушку оператора
               (это решает уже классификатор; probe лишь собирает признаки)
    REFUSED  — пришёл RST (ConnectionRefusedError)
    TIMEOUT  — нет ответа за timeout
    ERROR    — прочая сетевая ошибка
"""

from __future__ import annotations

import asyncio
import hashlib
import ssl
import time
from dataclasses import dataclass, field, asdict
from typing import Any

OPEN = "OPEN"
REFUSED = "REFUSED"
TIMEOUT = "TIMEOUT"
ERROR = "ERROR"

# TLS-контекст, который НЕ валидирует сертификат: нам нужно снять то, что отдают,
# в т.ч. подменный cert оператора, а не отбросить его.
_TLS = ssl.create_default_context()
_TLS.check_hostname = False
_TLS.verify_mode = ssl.CERT_NONE
_TLS.set_ciphers("DEFAULT@SECLEVEL=1")


@dataclass
class PortResult:
    port: int
    state: str
    latency_ms: float | None = None
    http_status: int | None = None
    http_location: str | None = None
    body_sha1: str | None = None      # хэш первых КБ тела (фингерпринт заглушки)
    server: str | None = None         # заголовок Server
    tls_subject: str | None = None    # CN/Subject сертификата (для :443)
    error: str | None = None


@dataclass
class ProbeResult:
    ip: str
    ports: list[PortResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


async def _http_fingerprint(reader, writer, ip: str) -> dict[str, Any]:
    """Шлём минимальный GET и снимаем статус/Location/Server/хэш тела."""
    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        f"User-Agent: wlc/0.1\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    writer.write(req)
    await writer.drain()
    raw = await asyncio.wait_for(reader.read(8192), timeout=5)
    out: dict[str, Any] = {}
    try:
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        if lines and lines[0].startswith(b"HTTP/"):
            parts = lines[0].split(b" ", 2)
            if len(parts) >= 2 and parts[1].isdigit():
                out["http_status"] = int(parts[1])
        for ln in lines[1:]:
            k, _, v = ln.partition(b":")
            key = k.strip().lower()
            val = v.strip().decode("latin1", "replace")
            if key == b"location":
                out["http_location"] = val
            elif key == b"server":
                out["server"] = val
        if body:
            out["body_sha1"] = hashlib.sha1(body[:2048]).hexdigest()
    except Exception:
        pass
    return out


async def probe_port(ip: str, port: int, timeout: float) -> PortResult:
    start = time.monotonic()
    use_tls = port == 443
    try:
        if use_tls:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=_TLS, server_hostname=None),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
    except asyncio.TimeoutError:
        return PortResult(port=port, state=TIMEOUT)
    except ConnectionRefusedError:
        return PortResult(
            port=port, state=REFUSED, latency_ms=(time.monotonic() - start) * 1000
        )
    except (ssl.SSLError, OSError) as e:
        # TLS-ошибка = хендшейк начался, но не завершился; считаем порт открытым,
        # но фиксируем причину (часто это подменный/битый cert на блоке).
        return PortResult(port=port, state=ERROR, error=type(e).__name__)

    res = PortResult(
        port=port, state=OPEN, latency_ms=(time.monotonic() - start) * 1000
    )
    try:
        if use_tls:
            sslobj = writer.get_extra_info("ssl_object")
            if sslobj is not None:
                try:
                    cert = sslobj.getpeercert()
                    if cert:
                        subj = dict(x[0] for x in cert.get("subject", []))
                        res.tls_subject = subj.get("commonName")
                except Exception:
                    pass
        fp = await _http_fingerprint(reader, writer, ip)
        res.http_status = fp.get("http_status")
        res.http_location = fp.get("http_location")
        res.server = fp.get("server")
        res.body_sha1 = fp.get("body_sha1")
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
        except Exception:
            pass
    return res


async def probe_ip(ip: str, ports: list[int], timeout: float) -> ProbeResult:
    results = await asyncio.gather(*(probe_port(ip, p, timeout) for p in ports))
    return ProbeResult(ip=ip, ports=list(results))
