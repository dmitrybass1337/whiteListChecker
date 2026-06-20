# wlc на Termux (on-device)

Полный прогон прямо на телефоне, без ноута и без root. Сканер на чистом Python
(TCP-connect), zmap не нужен.

> Реалистичные ожидания: connect-скан с телефона — это сотни проб/сек, не десятки
> тысяч. Полный список «по 1 IP на /24» (~16 млн целей) телефон будет жевать
> **сутками**. Поэтому ниже сначала прогоняем по **семплу** (быстро убедиться, что
> метод работает на твоей симке), и только потом — полный список фоном.

---

## 0. Установка Termux

Ставь Termux **из F-Droid или GitHub**, не из Play Market (там версия старая и
битая): https://f-droid.org/packages/com.termux/

Затем:
```bash
pkg update -y && pkg upgrade -y
pkg install -y python git termux-api
```

Скопируй проект на телефон (любой способ):
```bash
# вариант через git, если зальёшь репозиторий:
git clone <твой-репозиторий> whiteListChecker
cd whiteListChecker

# или закинь папку whiteListChecker в ~/storage/shared и:
# termux-setup-storage   # дать доступ к памяти
# cp -r ~/storage/shared/whiteListChecker ~/  &&  cd ~/whiteListChecker
```

Проверка:
```bash
python -m wlc --version
```

---

## 1. Не дать Android усыпить скан

Долгий скан Android прибьёт в фоне. Перед запуском:
```bash
termux-wake-lock
```
И держи телефон на зарядке (скан греет модем и сажает батарею). Снять блокировку
после: `termux-wake-unlock`.

---

## 2. Калибровка — снять отпечаток блокировки

Это **самый важный шаг**. Заполни два файла реальными IP:

- [../data/known_allowed.txt](../data/known_allowed.txt) — адреса, которые на этой
  симке **точно открываются** (сервисы из текущего whitelist'а).
- [../data/known_blocked.txt](../data/known_blocked.txt) — адреса, которые **точно
  не открываются** (зарубежные сервисы вне списка; удобны `1.1.1.1`, `8.8.8.8`).

Как быстро набрать allowed-IP прямо в Termux (резолвим известные открытые хосты):
```bash
for h in vk.com yandex.ru gosuslugi.ru ok.ru mail.ru; do
  python -c "import socket,sys; print(socket.gethostbyname(sys.argv[1]))" "$h"
done >> data/known_allowed.txt
```
Чем больше и разнообразнее адреса — тем надёжнее отпечаток (10–50 каждого вида).

Запуск:
```bash
python -m wlc calibrate \
    --allowed data/known_allowed.txt \
    --blocked data/known_blocked.txt \
    --concurrency 50 \
    --out data/fingerprint.json
```

Смотри на вывод `метод детекции блока`:

| Метод | Что значит | Качество |
|-------|-----------|----------|
| `PORTAL` | блок отдаёт заглушку/редирект оператора | отличное — точно видно и allowed, и blocked |
| `REFUSED`| блок шлёт RST | хорошее |
| `TIMEOUT`| блок — тихий drop | слабое: blocked не отличить от «хост спит», список строится только по `OPEN` |

Если `TIMEOUT` — это не тупик, просто список будет по положительному сигналу
(адреса, которые реально ответили). Для контентных сетей этого почти всегда
достаточно.

---

## 3. Цели — сначала маленький семпл

Скачай таблицу анонсированных префиксов:
```bash
python -m wlc fetch-table --out data/prefixes.txt
```

Сгенерируй полный список целей (1 IP на /24):
```bash
python -m wlc gen-targets --prefixes data/prefixes.txt --out data/targets.txt
wc -l data/targets.txt        # ~16 млн — это на потом
```

Для первого прогона возьми **случайные 20 000 целей**, чтобы за минуты убедиться,
что классификация работает:
```bash
shuf data/targets.txt | head -n 20000 > data/targets_sample.txt
```

---

## 4. Пробный скан по семплу

Консервативные настройки для радиомодема (не тысячи сокетов!):
```bash
python -m wlc scan \
    --targets data/targets_sample.txt \
    --ports 80,443 \
    --concurrency 100 \
    --rate 200 \
    --timeout 4 \
    --out data/results_sample.jsonl
```
Прогресс идёт в stderr (`probed / open / pps`). Если телефон греется или сеть
залипает — снижай `--concurrency` и `--rate`.

Классификация и сборка:
```bash
python -m wlc classify \
    --results data/results_sample.jsonl \
    --fingerprint data/fingerprint.json \
    --out data/classified_sample.jsonl

python -m wlc aggregate \
    --classified data/classified_sample.jsonl \
    --old data/old_whitelist.txt \
    --out data/whitelist_sample.txt
```

Глянь `data/whitelist_sample.txt` и счётчики `allowed/blocked/unknown`. Если в
allowed попали ожидаемые сети (VK/Yandex/…), а мусор — нет, метод рабочий →
запускай полный прогон.

---

## 5. Полный прогон (фоном)

Запусти на полном `data/targets.txt`, но в живучем режиме: `nohup` + лог, чтобы
скан пережил закрытие сессии. Перед этим — `termux-wake-lock`.

```bash
termux-wake-lock
nohup python -m wlc scan \
    --targets data/targets.txt \
    --ports 80,443 \
    --concurrency 100 \
    --rate 200 \
    --out data/results.jsonl \
    > data/scan.log 2>&1 &
echo "PID: $!"
```

Следить за ходом:
```bash
tail -f data/scan.log
wc -l data/results.jsonl       # сколько уже пробито
```

При `--rate 200` полный список (~16 млн) идёт ориентировочно **~22 часа** чистого
времени (по факту дольше из-за таймаутов и троттлинга). Можно гонять кусками
(см. ниже).

Финал — как в шаге 4, но по `data/results.jsonl`:
```bash
python -m wlc classify --results data/results.jsonl \
    --fingerprint data/fingerprint.json --out data/classified.jsonl
python -m wlc aggregate --classified data/classified.jsonl \
    --old data/old_whitelist.txt --out data/whitelist.txt --diff-out data/diff.json
```

---

## Полезное

**Гонять кусками / докачивать.** Бей цели на части и сканируй по одной — удобно
прерывать и не терять прогресс:
```bash
split -l 1000000 data/targets.txt data/part_      # part_aa, part_ab, ...
python -m wlc scan --targets data/part_aa --out data/results_aa.jsonl --rate 200
# results_*.jsonl потом просто склеить:  cat data/results_*.jsonl > data/results.jsonl
```

**Следи за трафиком.** `wlc scan` в конце печатает грубую оценку (МБ). «Безлимит»
часто троттлится по объёму — если скорость резко упала, возможно, ты в лимите.

**Аккуратнее с нагрузкой.** Это скан собственной связности, но высокий `--rate`
может ловить антифрод оператора. Начинай со скромных значений.

**SNI-проверка.** Если подозреваешь фильтрацию по имени, а не по IP:
```bash
python -m wlc sni-test --ip <разрешённый-IP>
```
Если результат зависит от SNI — IP-скан покажет не всю картину.
