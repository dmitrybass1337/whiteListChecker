#!/usr/bin/env bash
# Termux (Android), без root. Сканер на чистом stdlib — никаких сборок.
set -euo pipefail

echo "[*] Установка Python в Termux..."
pkg update -y
pkg install -y python

echo
echo "[*] Особенности on-device режима:"
echo "    - нет raw-сокетов (root недоступен) -> используется TCP-connect скан"
echo "      (zmap не нужен), команды те же, что в README, кроме шага zmap."
echo "    - держи телефон на зарядке: долгий скан греет и сажает батарею"
echo "    - Android может усыплять процесс: termux-wake-lock перед запуском"
echo "      pkg install termux-api  &&  termux-wake-lock"
echo "    - снизь --concurrency (50-150) и --rate (100-300): радиомодем не любит"
echo "      тысячи параллельных сокетов"
echo
echo "[ok] Готово. Дальше — README.md, 'режим Termux'."
