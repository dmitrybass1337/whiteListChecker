"""CLI: python -m wlc <команда>."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from . import __version__
from . import targets as targets_mod
from . import fingerprint as fp_mod
from . import aggregate as agg_mod
from .scan import run_scan, iter_targets


def _wait_for_network(action: str) -> None:
    """Пауза перед сетевым шагом: дать переключиться на мобильный интернет."""
    sys.stderr.write(
        "\n"
        "  ┌──────────────────────────────────────────────────────────┐\n"
        "  │  ПЕРЕКЛЮЧИСЬ НА МОБИЛЬНЫЙ ИНТЕРНЕТ                          │\n"
        "  │  выключи Wi-Fi и VPN, включи мобильные данные.             │\n"
        f"  │  Шаг «{action}» должен идти через симку оператора.\n"
        "  └──────────────────────────────────────────────────────────┘\n"
        "  Enter — продолжить, Ctrl-C — отмена: ")
    sys.stderr.flush()
    try:
        input()
    except EOFError:
        pass  # неинтерактивный запуск (пайп) — просто продолжаем


def _cmd_fetch_table(args) -> int:
    n = targets_mod.fetch_table(args.out)
    if n == 0:
        sys.stderr.write(
            f"[err] 0 префиксов записано в {args.out} — источник вернул пусто "
            f"или формат не распознан. Проверь доступ к bgp.tools.\n")
        return 1
    print(f"[ok] сохранено {n} IPv4-префиксов -> {args.out}")
    return 0


def _cmd_gen_targets(args) -> int:
    hosts = tuple(int(h) for h in args.hosts.split(",") if h.strip())
    n = targets_mod.gen_targets(args.prefixes, args.out, hosts=hosts)
    print(f"[ok] сгенерировано {n} целей ({len(hosts)} хост(ов)/24) -> {args.out}")
    return 0


def _read_ips(path: str) -> list[str]:
    with open(path, encoding="utf-8-sig") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def _cmd_calibrate(args) -> int:
    if args.pause:
        _wait_for_network("калибровка")
    ports = [int(p) for p in args.ports.split(",")]
    allowed_ips = _read_ips(args.allowed)
    blocked_ips = _read_ips(args.blocked)

    async def _probe_all(ips):
        from .probe import probe_ip
        recs = []
        sem = asyncio.Semaphore(args.concurrency)

        async def one(ip):
            async with sem:
                r = await probe_ip(ip, ports, args.timeout)
                recs.append(r.to_dict())
        await asyncio.gather(*(one(ip) for ip in ips))
        return recs

    allowed_recs = asyncio.run(_probe_all(allowed_ips))
    blocked_recs = asyncio.run(_probe_all(blocked_ips))
    fp = fp_mod.build_fingerprint(allowed_recs, blocked_recs)
    with open(args.out, "w", encoding="utf-8") as out:
        json.dump(fp, out, ensure_ascii=False, indent=2)
    print(f"[ok] метод детекции блока: {fp['method']}")
    if fp["method"] == "TIMEOUT":
        print("[warn] оператор режет тихим drop'ом — точная классификация blocked "
              "невозможна, опираемся только на положительный сигнал (OPEN).")
    print(f"[ok] отпечаток сохранён -> {args.out}")
    return 0


def _cmd_scan(args) -> int:
    if args.pause:
        _wait_for_network("скан")
    ports = [int(p) for p in args.ports.split(",")]
    with open(args.targets, encoding="utf-8-sig") as fh_in, \
            open(args.out, "w", encoding="utf-8") as fh_out:
        stats = asyncio.run(run_scan(
            iter_targets(fh_in), ports,
            concurrency=args.concurrency, rate=args.rate,
            out=fh_out, timeout=args.timeout,
        ))
    # грубая оценка трафика: ~120 байт исх + ~600 байт вх на пробу-порт
    est_mb = stats["probed"] * len(ports) * 720 / 1e6
    print(f"[ok] результаты -> {args.out}  (~{est_mb:.1f} MB трафика, оценка)")
    return 0


def _cmd_classify(args) -> int:
    with open(args.fingerprint, encoding="utf-8-sig") as fh:
        fp = json.load(fh)
    records = fp_mod.load_jsonl(args.results)
    n = {"allowed": 0, "blocked": 0, "unknown": 0}
    with open(args.out, "w", encoding="utf-8") as out:
        for rec in records:
            v = fp_mod.classify_record(rec, fp)
            rec["verdict"] = v
            n[v] += 1
            out.write(json.dumps(rec, separators=(",", ":")) + "\n")
    print(f"[ok] allowed={n['allowed']} blocked={n['blocked']} unknown={n['unknown']} -> {args.out}")
    return 0


def _cmd_aggregate(args) -> int:
    records = fp_mod.load_jsonl(args.classified)
    nets = agg_mod.allowed_networks(records)
    nets.sort(key=agg_mod.int_key)
    with open(args.out, "w", encoding="utf-8") as out:
        for n in nets:
            out.write(str(n) + "\n")
    print(f"[ok] {len(nets)} CIDR-блоков -> {args.out}")
    if args.old:
        d = agg_mod.diff(nets, agg_mod.load_cidrs(args.old))
        print(f"[diff vs {args.old}] +{len(d['added'])} /24 новых, "
              f"-{len(d['removed'])} /24 пропало, {d['kept']} /24 совпало")
        if args.diff_out:
            with open(args.diff_out, "w", encoding="utf-8") as out:
                json.dump({k: [str(x) for x in v] if isinstance(v, list) else v
                           for k, v in d.items()}, out, indent=2)
            print(f"[ok] подробный diff -> {args.diff_out}")
    return 0


def _cmd_sni_test(args) -> int:
    """Проверка SNI-фильтрации: один IP, разные SNI на :443."""
    import ssl
    import socket
    hosts = args.sni.split(",")
    print(f"[sni-test] {args.ip}:443")
    for h in hosts:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((args.ip, 443), timeout=args.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=h) as ss:
                    cert = ss.getpeercert()
                    cn = dict(x[0] for x in cert.get("subject", [])).get("commonName") if cert else "?"
                    print(f"  SNI={h:<30} OK  cert.CN={cn}")
        except Exception as e:
            print(f"  SNI={h:<30} FAIL  {type(e).__name__}: {e}")
    print("[hint] если результат зависит от SNI — фильтрация по имени, не по IP.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wlc", description="whiteListChecker")
    p.add_argument("--version", action="version", version=f"wlc {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("fetch-table", help="скачать анонсированные префиксы")
    sp.add_argument("--out", default="data/prefixes.txt")
    sp.set_defaults(func=_cmd_fetch_table)

    sp = sub.add_parser("gen-targets", help="по 1 IP на /24 из префиксов")
    sp.add_argument("--prefixes", required=True)
    sp.add_argument("--out", default="data/targets.txt")
    sp.add_argument("--hosts", default="37",
                    help="октеты для пробы в каждой /24 через запятую "
                         "(напр. 1,37,100,150,200,254). Больше = шире охват, но ×N трафика")
    sp.set_defaults(func=_cmd_gen_targets)

    sp = sub.add_parser("calibrate", help="снять отпечаток блокировки")
    sp.add_argument("--allowed", required=True)
    sp.add_argument("--blocked", required=True)
    sp.add_argument("--ports", default="80,443")
    sp.add_argument("--concurrency", type=int, default=50)
    sp.add_argument("--timeout", type=float, default=4.0)
    sp.add_argument("--out", default="data/fingerprint.json")
    sp.add_argument("--pause", action="store_true",
                    help="ждать Enter перед стартом (переключиться на симку)")
    sp.set_defaults(func=_cmd_calibrate)

    sp = sub.add_parser("scan", help="массовый проб целей -> JSONL")
    sp.add_argument("--targets", required=True)
    sp.add_argument("--ports", default="80,443")
    sp.add_argument("--concurrency", type=int, default=200)
    sp.add_argument("--rate", type=float, default=500,
                    help="проб/сек, 0 = без лимита")
    sp.add_argument("--timeout", type=float, default=4.0)
    sp.add_argument("--out", default="data/results.jsonl")
    sp.add_argument("--pause", action="store_true",
                    help="ждать Enter перед стартом (переключиться на симку)")
    sp.set_defaults(func=_cmd_scan)

    sp = sub.add_parser("classify", help="разметить результаты по отпечатку")
    sp.add_argument("--results", required=True)
    sp.add_argument("--fingerprint", required=True)
    sp.add_argument("--out", default="data/classified.jsonl")
    sp.set_defaults(func=_cmd_classify)

    sp = sub.add_parser("aggregate", help="свернуть в CIDR + diff")
    sp.add_argument("--classified", required=True)
    sp.add_argument("--old", help="старый whitelist для diff (CIDR на строку)")
    sp.add_argument("--diff-out")
    sp.add_argument("--out", default="data/whitelist.txt")
    sp.set_defaults(func=_cmd_aggregate)

    sp = sub.add_parser("sni-test", help="проверить SNI-фильтрацию")
    sp.add_argument("--ip", required=True)
    sp.add_argument("--sni", default="vk.com,google.com,example.com")
    sp.add_argument("--timeout", type=float, default=5.0)
    sp.set_defaults(func=_cmd_sni_test)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        sys.stderr.write("\n[abort]\n")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
