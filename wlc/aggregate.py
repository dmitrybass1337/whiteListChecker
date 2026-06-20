"""Сворачивание разрешённых адресов в CIDR и diff со старым whitelist'ом.

Каждый разрешённый адрес (по 1 на /24) превращаем в его /24, затем схлопываем
смежные сети в более крупные CIDR. Результат сравниваем со старым списком.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable

from .fingerprint import ALLOWED, classify_record


def _to_network24(ip: str) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(f"{ip}/24", strict=False)


def allowed_networks(classified: Iterable[dict]) -> list[ipaddress.IPv4Network]:
    nets: set[ipaddress.IPv4Network] = set()
    for rec in classified:
        if rec.get("verdict") == ALLOWED:
            try:
                nets.add(_to_network24(rec["ip"]))
            except ValueError:
                continue
    return list(ipaddress.collapse_addresses(nets))


def classify_and_aggregate(records: list[dict], fp: dict) -> tuple[list[dict], list[ipaddress.IPv4Network]]:
    classified = []
    for rec in records:
        rec = dict(rec)
        rec["verdict"] = classify_record(rec, fp)
        classified.append(rec)
    return classified, allowed_networks(classified)


def load_cidrs(path: str) -> list[ipaddress.IPv4Network]:
    out = []
    with open(path, encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                out.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                continue
    return out


def diff(new: list[ipaddress.IPv4Network], old: list[ipaddress.IPv4Network]) -> dict:
    """Грубый diff по охвату адресов (через collapse для нормализации)."""
    new_set = set(ipaddress.collapse_addresses(new))
    old_set = set(ipaddress.collapse_addresses(old))
    # сравнение по точным сетям + по охвату /24
    def to24(nets):
        s = set()
        for n in nets:
            if n.prefixlen <= 24:
                s.update(n.subnets(new_prefix=24))
            else:
                s.add(ipaddress.ip_network(f"{n.network_address}/24", strict=False))
        return s
    new24, old24 = to24(new_set), to24(old_set)
    return {
        "added": sorted(new24 - old24, key=int_key),
        "removed": sorted(old24 - new24, key=int_key),
        "kept": len(new24 & old24),
    }


def int_key(net: ipaddress.IPv4Network) -> int:
    return int(net.network_address)
