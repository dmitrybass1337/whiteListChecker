"""Генерация целей и загрузка таблицы анонсированных префиксов.

Стратегия: по 1 адресу на /24 (whitelist'ы такого типа работают на гранулярности
/24 и крупнее — точнее семплить незачем). Префиксы крупнее /24 разбиваем на /24,
мельче — берём один адрес.

Выбор адреса в /24 детерминированный, но «не .1/.0»: некоторые сети по-разному
ведут себя на сетевом/широковещательном адресе, поэтому берём .37.
"""

from __future__ import annotations

import bisect
import ipaddress
import sys
import urllib.request
from typing import Iterator

# Какие октеты /24 пробивать (1..254). По умолчанию один «обычный» хост .37;
# при whitelist'е на гранулярности /24 несколько октетов ловят сети, где .37 пуст.
_DEFAULT_HOSTS = (37,)

# Публичная таблица анонсированных префиксов (требует свой User-Agent).
_TABLE_URL = "https://bgp.tools/table.txt"
_UA = "wlc/0.1 (+whitelist self-connectivity audit)"


def fetch_table(out_path: str) -> int:
    """Скачать список анонсированных IPv4-префиксов в файл (CIDR на строку)."""
    req = urllib.request.Request(_TABLE_URL, headers={"User-Agent": _UA})
    count = 0
    with urllib.request.urlopen(req, timeout=60) as resp, open(out_path, "w") as out:
        for raw in resp:
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            # формат bgp.tools: "<префикс> <ASN>" — берём только префикс
            cidr = line.split()[0]
            if ":" in cidr:  # пропускаем IPv6
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if net.version != 4:
                continue
            out.write(f"{net}\n")
            count += 1
    return count


def _sample_prefix(net: ipaddress.IPv4Network,
                   hosts: tuple[int, ...]) -> Iterator[str]:
    if net.prefixlen >= 24:
        # /24 или мельче: берём заданные октеты, зажав их в диапазон живых хостов
        addrs = list(net.hosts())
        if not addrs:
            yield str(net.network_address)
            return
        lo, hi = int(addrs[0]), int(addrs[-1])
        seen_off: set[int] = set()
        for h in hosts:
            cand = min(max(int(net.network_address) + h, lo), hi)
            if cand not in seen_off:
                seen_off.add(cand)
                yield str(ipaddress.ip_address(cand))
        return
    # разбить на /24 и взять заданные октеты из каждой
    for sub in net.subnets(new_prefix=24):
        base = int(sub.network_address)
        for h in hosts:
            if 1 <= h <= 254:
                yield str(ipaddress.ip_address(base + h))


def gen_targets(prefixes_path: str, out_path: str,
                hosts: tuple[int, ...] = _DEFAULT_HOSTS) -> int:
    count = 0
    seen: set[str] = set()
    with open(prefixes_path, encoding="utf-8-sig") as fh, open(out_path, "w") as out:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                sys.stderr.write(f"[skip] неверный префикс: {line}\n")
                continue
            if net.version != 4:
                continue
            for ip in _sample_prefix(net, hosts):
                if ip not in seen:
                    seen.add(ip)
                    out.write(ip + "\n")
                    count += 1
    return count


def _load_found_24(whitelist_path: str) -> list[int]:
    """Индексы /24 (network_address >> 8) из найденного whitelist'а."""
    idx: set[int] = set()
    with open(whitelist_path, encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                continue
            if net.version != 4:
                continue
            # сеть может быть крупнее /24 (после collapse) — разворачиваем в /24
            lo = int(net.network_address) >> 8
            hi = int(net.broadcast_address) >> 8
            idx.update(range(lo, hi + 1))
    return sorted(idx)


def expand_targets(whitelist_path: str, prefixes_path: str, out_path: str,
                   hosts: tuple[int, ...] = _DEFAULT_HOSTS,
                   cap_prefixlen: int = 16) -> int:
    """Фаза 2: вокруг подтверждённых /24 досканировать целиком анонсированные
    сети, в которых они лежат. Анонс крупнее /cap_prefixlen разворачиваем не весь,
    а блоками /cap_prefixlen вокруг каждого найденного /24 (чтобы не раздуло)."""
    found = _load_found_24(whitelist_path)
    if not found:
        return 0
    cap_block = 1 << (24 - cap_prefixlen)  # сколько /24 в /cap (cap=16 -> 256)
    count = 0
    seen: set[str] = set()
    with open(prefixes_path, encoding="utf-8-sig") as fh, open(out_path, "w") as out:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cidr = line.split()[0]
            if ":" in cidr:
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if net.version != 4:
                continue
            s24 = int(net.network_address) >> 8
            e24 = int(net.broadcast_address) >> 8
            i = bisect.bisect_left(found, s24)
            if i >= len(found) or found[i] > e24:
                continue  # в этой сети нет подтверждённых /24
            # диапазоны /24-индексов для разворота
            if net.prefixlen >= cap_prefixlen:
                ranges = [(s24, e24)]
            else:
                ranges = []
                j = i
                while j < len(found) and found[j] <= e24:
                    b = (found[j] // cap_block) * cap_block
                    ranges.append((max(b, s24), min(b + cap_block - 1, e24)))
                    j += 1
            for bs, be in ranges:
                for blk in range(bs, be + 1):
                    base = blk << 8
                    for h in hosts:
                        if 1 <= h <= 254:
                            ip = str(ipaddress.ip_address(base + h))
                            if ip not in seen:
                                seen.add(ip)
                                out.write(ip + "\n")
                                count += 1
    return count
