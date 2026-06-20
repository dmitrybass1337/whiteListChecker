# whiteListChecker (wlc)

Эмпирическая пересборка whitelist'а мобильного интернета (модель «запрещено всё,
что не разрешено»). Инструмент пробивает адресное пространство **через мобильный
канал** и определяет, какие подсети реально пропускаются фильтром оператора.

Один и тот же код работает в двух режимах:

| Режим | Где | Скорость | Требования |
|-------|-----|----------|------------|
| **Termux (on-device)** | прямо на Android | медленно | Python, без root |
| **Ноут + Linux (рекомендуется)** | телефон раздаёт интернет на ноут | быстро | + `zmap` для скана |

Пайплайн идентичен; отличается только шаг скана (чистый Python vs zmap).

---

## Идея в двух словах

При whitelist'е проба к IP даёт один из исходов:

1. **Разрешён + хост живой** → TCP-хендшейк проходит (`OPEN`)
2. **Разрешён + хост молчит** → таймаут (`TIMEOUT`)
3. **Запрещён** → фильтр режет: `RST` (`REFUSED`), редирект на портал (`PORTAL`)
   или тихий drop (`TIMEOUT`)

Случаи 2 и 3 могут совпасть (оба `TIMEOUT`). Поэтому **сначала калибровка**: на
заведомо разрешённых и заведомо запрещённых IP снимаем «отпечаток блокировки».
Дальше классификатор знает, как оператор режет, и сканирует осознанно.

Сканировать весь IPv4 в лоб не нужно: пробиваем **по 1 адресу на /24** из
анонсированных BGP-префиксов (~16 млн проб вместо 3.7 млрд), а интересные /24
при желании досканируем целиком.

---

## Установка

### Ноут (Debian/Ubuntu)
```bash
bash laptop/setup.sh        # python3 + zmap + pip-зависимости
```

### Termux (Android)
```bash
bash termux/setup.sh        # pkg install python; stdlib-only сканер
```

---

## Полный прогон

> **Префиксы.** На whitelist-симке `bgp.tools` обычно сам недоступен, поэтому
> `fetch-table` с телефона не сработает. В репозитории уже лежит готовый список
> российских префиксов `data/prefixes_ru.txt` (~8.6k блоков → ~176k целей по /24).
> Используй его и пропусти шаг 0. `fetch-table` нужен только с открытого интернета
> (ноут на чистом WiFi) или если хочешь не-RU адресацию.

```bash
# 0. (опционально, нужен открытый интернет) скачать таблицу префиксов
python -m wlc fetch-table --out data/prefixes.txt

# 1. КАЛИБРОВКА — снять отпечаток блокировки
python -m wlc calibrate \
    --allowed data/known_allowed.txt \
    --blocked data/known_blocked.txt \
    --out data/fingerprint.json

# 2. ЦЕЛИ — по 1 IP на /24 из префиксов (RU-список из репозитория)
python -m wlc gen-targets --prefixes data/prefixes_ru.txt --out data/targets.txt

# 3. СКАН -> data/results.jsonl  (Termux-режим; режим ноута см. ниже)
python -m wlc scan --targets data/targets.txt --ports 80,443 \
    --concurrency 200 --rate 500 --out data/results.jsonl

# 4. КЛАССИФИКАЦИЯ по отпечатку
python -m wlc classify \
    --results data/results.jsonl \
    --fingerprint data/fingerprint.json \
    --out data/classified.jsonl

# 5. АГРЕГАЦИЯ в CIDR + diff со старым репо
python -m wlc aggregate \
    --classified data/classified.jsonl \
    --old data/old_whitelist.txt \
    --out data/whitelist.txt
```

### Шаг 3 — режим Termux (чистый Python)
```bash
python -m wlc scan \
    --targets data/targets.txt \
    --ports 80,443 \
    --concurrency 200 \
    --rate 500 \
    --out data/results.jsonl
```

### Шаг 3 — режим ноута (zmap → верификация)
```bash
# быстрый SYN-скан zmap'ом (открытые порты)
bash laptop/scan_zmap.sh data/targets.txt 443 data/zmap_open.txt
# HTTP/TLS-фингерпринт только по откликнувшимся
python -m wlc scan \
    --targets data/zmap_open.txt \
    --ports 80,443 \
    --concurrency 1000 \
    --out data/results.jsonl
```

---

## Важно
- Это разведка **собственной связности** (что пропускает твой канал) — легитимно,
  но массовый скан может нарушать ToS оператора и ловить антифрод. Держи
  умеренный `--rate`.
- «Безлимит» часто троттлится по объёму — следи за трафиком (`wlc scan` пишет
  оценку в конце).
- Часть фильтрации может быть по **SNI**, а не IP: проверь
  `python -m wlc sni-test --ip <allowed-ip>` (один IP, разные SNI).
- CGNAT: у тебя серый IP, входящих нет — для исходящего скана не помеха.
