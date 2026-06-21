#!/usr/bin/env bash
# wlc — установка «под ключ» и полный прогон whitelist'а на свежем Termux.
#
# Запуск (на Wi-Fi, GitHub должен быть доступен):
#   pkg install -y git && \
#   git clone https://github.com/dmitrybass1337/whiteListChecker.git && \
#   bash whiteListChecker/termux/run_all.sh
#
# Установка идёт на Wi-Fi; перед калибровкой/сканом скрипт ПОПРОСИТ переключиться
# на мобильный интернет (выключить Wi-Fi/VPN) — там и есть фильтр оператора.

set -e

REPO_URL="https://github.com/dmitrybass1337/whiteListChecker.git"
DIR="$HOME/whiteListChecker"

# ===== НАСТРОЙКИ ПРОГОНА (правь под себя) =====
# Октеты, которые пробуем в каждой /24. "37" — быстрый полный обзор (176k целей).
# "1,37,100,150,200,254" — в 6 раз больше охват и времени (ловит /24, где .37 пуст).
HOSTS="37"
PORTS="80,443"
CONCURRENCY=150      # одновременных проб
RATE=0               # проб/сек, 0 = без лимита (потолок = concurrency/timeout)
TIMEOUT=3            # сек на пробу
# Если посреди скана ВСЁ начнёт уходить в таймаут (оператор включил антифрод) —
# прерви (Ctrl-C), снизь CONCURRENCY до ~60 и поставь RATE=30, перезапусти.
# ==============================================

echo "=== [1/7] пакеты (python, git) ==="
pkg update -y || true
pkg install -y python git

echo "=== [2/7] репозиторий ==="
if [ -d "$DIR/.git" ]; then
  git -C "$DIR" fetch origin && git -C "$DIR" reset --hard origin/main
else
  git clone "$REPO_URL" "$DIR"
fi
cd "$DIR"

# не дать Android усыпить процесс (если есть termux-api)
command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock || true

echo
echo "  ┌──────────────────────────────────────────────────────────┐"
echo "  │  ПЕРЕКЛЮЧИСЬ НА МОБИЛЬНЫЙ ИНТЕРНЕТ                          │"
echo "  │  выключи Wi-Fi и VPN, включи мобильные данные.             │"
echo "  └──────────────────────────────────────────────────────────┘"
read -r -p "  Enter — продолжить калибровку и скан на симке: " _

echo "=== [3/7] калибровка (отпечаток блокировки оператора) ==="
# known_allowed.txt — RU-сервисы (VK/Яндекс), known_blocked.txt — зарубежные DNS.
# Если калибровка покажет странное — отредактируй эти файлы под свою симку.
python -m wlc calibrate --allowed data/known_allowed.txt \
    --blocked data/known_blocked.txt --out data/fingerprint.json

echo "=== [4/7] цели по всей РФ (октеты на /24: $HOSTS) ==="
python -m wlc gen-targets --prefixes data/prefixes_ru.txt \
    --out data/targets.txt --hosts "$HOSTS"

echo "=== [5/7] СКАН (conc=$CONCURRENCY rate=$RATE timeout=$TIMEOUT) — это надолго ==="
echo "    прогресс печатается каждые 5000 проб; Ctrl-C сохранит частичный результат."
python -m wlc scan --targets data/targets.txt --ports "$PORTS" \
    --concurrency "$CONCURRENCY" --rate "$RATE" --timeout "$TIMEOUT" \
    --out data/results.jsonl

echo "=== [6/7] классификация по отпечатку ==="
python -m wlc classify --results data/results.jsonl \
    --fingerprint data/fingerprint.json --out data/classified.jsonl

echo "=== [7/7] свёртка в CIDR ==="
python -m wlc aggregate --classified data/classified.jsonl --out data/whitelist.txt

command -v termux-wake-unlock >/dev/null 2>&1 && termux-wake-unlock || true

echo
echo "========================================================"
echo " ГОТОВО. Разрешённые сети -> $DIR/data/whitelist.txt"
echo " Всего CIDR-блоков:"
wc -l < data/whitelist.txt
echo "========================================================"
echo " Проверить доступность списка с канала:"
echo "   python -m wlc check --cidrs data/whitelist.txt"
echo " Доскан вокруг найденного (фаза 2):"
echo "   python -m wlc expand --whitelist data/whitelist.txt --prefixes data/prefixes_ru.txt --out data/targets_expand.txt"
echo "   python -m wlc scan --targets data/targets_expand.txt --concurrency 80 --rate 40 --out data/results_expand.jsonl"
