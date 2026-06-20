#!/usr/bin/env bash
# Быстрый SYN-скан zmap'ом: на вход список целей (1 IP/24), на выход —
# адреса, ответившие SYN-ACK на указанный порт. Эти OPEN-адреса потом
# докручиваем HTTP/TLS-фингерпринтом через `python -m wlc scan`.
#
#   bash laptop/scan_zmap.sh data/targets.txt 443 data/zmap_open.txt
set -euo pipefail

TARGETS="${1:?usage: scan_zmap.sh <targets.txt> <port> <out.txt> [rate_pps] [iface]}"
PORT="${2:?порт, напр. 443}"
OUT="${3:?файл результата}"
RATE="${4:-2000}"          # пакетов/сек; на мобильном лучше скромно
IFACE="${5:-}"             # напр. usb0; пусто = авто

ARGS=(-p "$PORT" -r "$RATE" -w "$TARGETS" -o "$OUT" -q)
if [[ -n "$IFACE" ]]; then
  ARGS+=(-i "$IFACE")
fi

echo "[*] zmap -p $PORT -r $RATE  (iface=${IFACE:-auto})"
echo "[!] zmap нужен root/CAP_NET_RAW:"
echo "    sudo zmap ${ARGS[*]}"
sudo zmap "${ARGS[@]}"
echo "[ok] открытые адреса -> $OUT  ($(wc -l < "$OUT") шт.)"
echo "    дальше: python -m wlc scan --targets $OUT --ports 80,443 --out data/results.jsonl"
