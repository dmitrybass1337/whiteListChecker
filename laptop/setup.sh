#!/usr/bin/env bash
# Ноут (Debian/Ubuntu): телефон раздаёт интернет на ноут, скан идёт через
# мобильный интерфейс. Ставит python3 + zmap.
set -euo pipefail

echo "[*] Установка зависимостей..."
sudo apt-get update
sudo apt-get install -y python3 python3-pip zmap

echo
echo "[*] Проверь, что трафик идёт через мобильный интерфейс телефона:"
echo "    1) USB-tethering или Wi-Fi hotspot с телефона"
echo "    2) ip route get 8.8.8.8   # default dev должен быть usb0/wwan0/wlan"
echo "    3) при нескольких интерфейсах задай маршрут/метрику на мобильный"
echo
echo "[ok] Готово. Дальше — README.md, 'режим ноута'."
