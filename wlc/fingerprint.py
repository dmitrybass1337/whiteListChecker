"""Калибровка и классификация.

Калибровка: пробиваем заведомо РАЗРЕШЁННЫЕ и заведомо ЗАПРЕЩЁННЫЕ адреса,
строим «отпечаток» того, как оператор режет неразрешённый трафик.

Классификатор: применяет отпечаток к результатам массового скана и помечает
каждый адрес как allowed / blocked / unknown.

Логика дискриминатора (от самого надёжного к слабому):
  1. PORTAL  — blocked-адреса отдают заглушку (одинаковый body_sha1 / Location /
               подменный TLS-subject). Если такой признак есть — это золото:
               точная классификация и allowed, и blocked.
  2. REFUSED — blocked = RST. Тогда REFUSED=blocked, OPEN=allowed.
  3. TIMEOUT — blocked = тихий drop. Различить blocked и «allowed, но хост спит»
               нельзя; полагаемся только на положительный сигнал:
               OPEN (реальный ответ) = allowed, остальное = unknown.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any, Iterable

ALLOWED = "allowed"
BLOCKED = "blocked"
UNKNOWN = "unknown"


def _port_states(rec: dict, port: int | None = None) -> list[dict]:
    ports = rec.get("ports", [])
    if port is None:
        return ports
    return [p for p in ports if p.get("port") == port]


def _signatures(records: Iterable[dict]) -> dict[str, Counter]:
    """Сводим наблюдения по группе адресов в счётчики признаков."""
    sig = {
        "state": Counter(),
        "body_sha1": Counter(),
        "location": Counter(),
        "tls_subject": Counter(),
        "http_status": Counter(),
    }
    for rec in records:
        for p in rec.get("ports", []):
            sig["state"][p.get("state")] += 1
            if p.get("body_sha1"):
                sig["body_sha1"][p["body_sha1"]] += 1
            if p.get("http_location"):
                sig["location"][p["http_location"]] += 1
            if p.get("tls_subject"):
                sig["tls_subject"][p["tls_subject"]] += 1
            if p.get("http_status"):
                sig["http_status"][p["http_status"]] += 1
    return sig


def build_fingerprint(allowed_recs: list[dict], blocked_recs: list[dict]) -> dict[str, Any]:
    a = _signatures(allowed_recs)
    b = _signatures(blocked_recs)

    fp: dict[str, Any] = {
        "method": None,
        "blocked_markers": {"body_sha1": [], "location": [], "tls_subject": []},
        "stats": {
            "allowed": {k: dict(v) for k, v in a.items()},
            "blocked": {k: dict(v) for k, v in b.items()},
        },
    }

    def _block_specific(counter_key: str) -> list[str]:
        """Значения, характерные для блока и не встречающиеся у разрешённых."""
        return [val for val, _ in b[counter_key].most_common()
                if val and a[counter_key].get(val, 0) == 0]

    portal_body = _block_specific("body_sha1")
    portal_loc = _block_specific("location")
    portal_tls = _block_specific("tls_subject")

    if portal_body or portal_loc or portal_tls:
        fp["method"] = "PORTAL"
        fp["blocked_markers"]["body_sha1"] = portal_body
        fp["blocked_markers"]["location"] = portal_loc
        fp["blocked_markers"]["tls_subject"] = portal_tls
        return fp

    # Доминирующее состояние у заблокированных
    blk_state = b["state"].most_common(1)[0][0] if b["state"] else None
    alw_state = a["state"].most_common(1)[0][0] if a["state"] else None
    if blk_state == "REFUSED" and alw_state != "REFUSED":
        fp["method"] = "REFUSED"
    else:
        fp["method"] = "TIMEOUT"  # тихий drop — слабый режим
    return fp


def classify_record(rec: dict, fp: dict) -> str:
    method = fp.get("method")
    markers = fp.get("blocked_markers", {})
    states = [p.get("state") for p in rec.get("ports", [])]
    has_open = "OPEN" in states

    if method == "PORTAL":
        for p in rec.get("ports", []):
            if p.get("body_sha1") in markers.get("body_sha1", []):
                return BLOCKED
            if p.get("http_location") in markers.get("location", []):
                return BLOCKED
            if p.get("tls_subject") in markers.get("tls_subject", []):
                return BLOCKED
        # не заглушка, но живой ответ -> разрешено
        return ALLOWED if has_open else UNKNOWN

    if method == "REFUSED":
        if has_open:
            return ALLOWED
        if all(s == "REFUSED" for s in states) and states:
            return BLOCKED
        return UNKNOWN

    # TIMEOUT-режим: доверяем только положительному сигналу
    return ALLOWED if has_open else UNKNOWN


def load_jsonl(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out
