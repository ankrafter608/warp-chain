# warp-chain

Генератор конфигов **WARP-in-WARP** (AmneziaWG снаружи → WireGuard внутри) для
[NekoBox for Windows](https://github.com/qr243vbi/nekobox): находит рабочую пару
эндпоинтов Cloudflare WARP и выдаёт готовые профили с правильными ключами,
Reserved и junk-параметрами — то, что в ручной инструкции делается час, здесь
занимает одну команду.

Программа **не является VPN-клиентом**. Вся тяжёлая работа — в
[warpscout](https://github.com/vernette/warpscout); warp-chain только
оркестрирует его и генерирует конфиги.

## Что делает warp-chain

1. **Аккаунты.** Загружает `warpscout-account.json` (два устройства: `main` и
   `outer`). Если файла нет — запускает `warpscout register`, который сам
   регистрирует оба устройства (с фолбэками через релей/прокси/туннель для РФ).
2. **Reserved (client_id).** warpscout не сохраняет `reserved`, а без него
   upload в цепочке падает до нуля. warp-chain запрашивает
   `GET /v0a4005/reg/{id}` (поле `config.client_id`, 3 байта) — сначала через
   релей `edge-client-api.vercel.app` (работает из РФ), потом напрямую.
   Полученное значение кэшируется в `warp-chain-state.json`: дальнейшие запуски
   в Cloudflare API не ходят.
3. **Фаза 1 — базовый эндпоинт.** `warpscout scan -p awg -exclude-node DME
   -country FI,SE,DE -best` → чистый `ip:port` на stdout.
4. **Фаза 2 — exit-эндпоинт.** `warpscout scan -p awg -through <base>
   -country FI,SE,DE -best`. Если `-best` не сработал, warp-chain запускает
   полный скан с отчётом и парсит текстовую таблицу.
5. **Генерация** трёх файлов (см. ниже).

Маппинг аккаунтов соответствует тому, что warpscout реально проверяет сканом
`-through`: внешний туннель (AWG-BASE) строится на устройстве `outer`,
внутренний (WARP-EXIT) — на `main`.

## Что нужно рядом

Ничего — warpscout скачивается автоматически при первом запуске.

```
warp-chain.exe          ← сама программа
data/
  warpscout.exe         ← скачивается с GitHub Releases при первом запуске
  warpscout-account.json← аккаунты (создаётся автоматически через warpscout register)
  state.json            ← кэш (Reserved, эндпоинты)
out/                    ← сюда складываются сгенерированные конфиги
```

Если warpscout скачать не удалось (GitHub недоступен), warp-chain соберёт его
из исходников через `go install github.com/vernette/warpscout@latest` — для
этого нужен установленный Go 1.25+. Бинарник можно положить и вручную: в
`data/`, рядом с программой, в `./warpscout/`, в PATH, или указать путь через
`-warpscout`.

## Использование

```cmd
warp-chain.exe                 :: интерактивный мастер (спросит страны/ноды)
warp-chain.exe -plain          :: неинтерактивно, все значения по умолчанию
warp-chain.exe -rescan         :: пересканировать эндпоинты
warp-chain.exe -node HEL       :: фаза 1 только на финской ноде
warp-chain.exe -no-ipv6        :: профили только с IPv4 (см. Troubleshooting)
```

Прогон со сканами занимает ~2–5 минут; повторный запуск без `-rescan`
использует кэш и мгновенно перегенерирует конфиги.

### Основные флаги

| Флаг | По умолчанию | Что делает |
|------|--------------|------------|
| `-version` | — | напечатать версию и выйти |
| `-warpscout` | авто | путь к warpscout (иначе ищется/скачивается в `data/`) |
| `-account` | `data/warpscout-account.json` | путь к warpscout-account.json |
| `-out` | `out/` (рядом с программой) | каталог для сгенерированных конфигов |
| `-country` | `FI,SE,DE` | страны выхода (ISO, через запятую) |
| `-exclude-node` | `DME` | ноды, исключаемые в фазе 1 |
| `-node` | — | наоборот: только эти ноды в фазе 1 (HEL, ARN, FRA) |
| `-base-endpoint` / `-exit-endpoint` | — | задать эндпоинты вручную, пропустить сканы |
| `-mtu-tun` / `-mtu-base` / `-mtu-exit` | `1200/1280/1200` | MTU |
| `-jc` / `-jmin` / `-jmax` | `6/21/56` | junk-параметры AmneziaWG |
| `-i1` | iCloud-проба warpscout | I1-пакет (`-i1 none` — выключить) |
| `-no-ipv6` | off | генерировать профили только с IPv4 (машины без IPv6) |
| `-rescan` | off | пересканировать, игнорируя кэш |
| `-plain` | off | без интерактивных вопросов |
| `-relay` | `edge-client-api.vercel.app` | релей для Cloudflare API (`direct` — только напрямую) |

## Результат

Все сгенерированные файлы складываются в каталог `out/` рядом с программой
(меняется флагом `-out`). Имена фиксированные, каждый запуск перезаписывает
результат:

| Файл | Что это |
|------|---------|
| `out/warp-chain.json` | полный sing-box конфиг (цепочка + TUN + DNS + route). Провалидирован `sing-box check` ядра NekoBox. |
| `out/warp-chain-links.txt` | две share-ссылки `awg://` и `wg://` — импорт профиля из буфера обмена |
| `out/warp-chain-card.md` | карточка со всеми полями для ручного ввода + чек-лист + troubleshooting |
| `out/warp-chain-test.json` + `test-chain.bat` | автономный тест цепочки: тот же двойной туннель с socks-входом `127.0.0.1:17890` вместо TUN — позволяет доказать, что туннели работают, не трогая настройки NekoBox (запустить bat, в браузере прокси socks5 127.0.0.1:17890) |
| `data/state.json` | кэш (Reserved, эндпоинты) — общий для всех запусков |

### Импорт в NekoBox

**Вариант А (профили + цепочка):**
1. Скопируйте строку AWG-BASE из `out/warp-chain-links.txt` →
   NekoBox: *Сервер → Добавить профиль из буфера обмена*. Повторите для WARP-EXIT.
2. *Сервер → Добавить профиль вручную → Тип: Цепочка прокси*, узлы по порядку:
   `AWG-BASE`, затем `WARP-EXIT`.
3. Включите **Режим TUN**, MTU TUN = 1200, DNS — по карточке.

**Вариант Б (одним файлом):**
*Сервер → Добавить профиль вручную → Тип: Custom Config*, ядро sing-box,
режим «Полный конфиг» — вставьте `warp-chain.json`. TUN/DNS при этом
управляются настройками самого NekoBox (задайте MTU 1200 и DNS по карточке).

## Технические детали (почему конфиг выглядит именно так)

- Формат JSON повторяет сериализацию профиля AmneziaWG в qr243vbi/nekobox
  (`src/gharqad/configs/proxy/WireguardBean.cpp`): тип `awg` в массиве
  `endpoints`, junk-параметры плоско (`jc/jmin/jmax/s1-s4`, строки `h1-h4`,
  `i1`), `useIntegratedTun`, peer с `address/port/public_key`.
- Ядро форка (`qr243vbi/sing-box`, опция `awg`) **не имеет поля `reserved`**
  для AmneziaWG — Reserved критичен только для внутреннего обычного
  WireGuard-эндпоинта (`WireGuardPeer.reserved`).
- Цепочка строится полем `detour` на exit-эндпоинте; exit назван тегом
  `proxy`, чтобы встроенная нормализация DNS в NekoBox (`detour: "proxy"`)
  и его правила маршрутизации указывали на выход цепочки.
- I1 по умолчанию — та же iCloud-проба, которой warpscout проверял эндпоинты
  при сканировании.
- В share-ссылках пробелы кодируются как `%20`, а не как `+`: Go кодирует
  query в form-urlencoded (пробел → `+`), но NekoBox парсит ссылки через
  Qt `QUrlQuery`, который `+` пробелом не считает. Без этого I1 доходит до
  ядра как `<r+2><b+0x...>` и amnezia-go отбивает конфиг с
  `IPC error -22 ... unknown tag`.
- В share-ссылки добавлен параметр `use_system_interface=true`. Это обход бага
  парсера ссылок форка (`From_Link::set_boolean` в
  `src/gharqad/configs/proxy/Link2Bean.cpp` инвертирует флаг): при импорте
  ссылки **без** этого параметра галочка «Использовать системный интерфейс»
  включается, AWG уходит в путь реального Wintun-адаптера и на машинах с
  отключённым IPv6 падает с `create tunnel: set ipv6 options: The parameter
  is incorrect`. Со значением `true` этот парсер выставляет галочку в false
  (netstack-режим, как надо). После импорта стоит убедиться, что галочка в
  обоих профилях снята. `-no-ipv6` — дополнительная страховка: профили без
  IPv6-адресов вообще не затрагивают ветку настройки IPv6.

## Troubleshooting

| Симптом | Причина | Решение |
|---------|---------|---------|
| `create service: initialize endpoint[0]: create tunnel: set ipv6 options: The parameter is incorrect` | профиль импортирован с включённым «Использовать системный интерфейс» (баг импорта ссылок), а в Windows отключён IPv6 | снять галочку в профилях AWG-BASE и WARP-EXIT и заново активировать цепочку; либо перегенерировать конфиги с `-no-ipv6` и переимпортировать; либо включить IPv6 в Windows |

## Сборка

Windows (PowerShell):

```powershell
.\build.ps1               # windows amd64 -> build\warp-chain-windows-amd64.exe
.\build.ps1 win,android   # цели: win, linux, arm64, android
```

Linux / macOS / Termux:

```sh
./build.sh                # linux amd64
./build.sh win android    # цели: win, linux, arm64, android
```

Сборка чистая Go (без cgo), с `-trimpath -ldflags "-s -w -X main.version=..."`.
Версия берётся из последнего git-тега (`git describe --tags`), без тега — `dev`
(проверка: `warp-chain.exe -version`).
Вручную то же самое: `GOOS=android GOARCH=arm64 go build -o warp-chain-android .`
Go ≥ 1.26, зависимостей кроме стандартной библиотеки нет.

## Android (Termux)

Генератор — обычная консольная Go-программа, под Android собирается целью
`android` (`GOOS=android GOARCH=arm64`, результат
`build/warp-chain-android-arm64`). Запускать в Termux; warpscout при первом
запуске скачивается сам (релиз `android_arm64` с GitHub Releases), либо его
можно собрать из исходников (`go install github.com/vernette/warpscout@latest`
или `GOOS=android GOARCH=arm64 go build` из исходников
[warpscout](https://github.com/vernette/warpscout)) и указать путь через
`-warpscout`.

Смысл запуска с телефона: сканы идут с той же сети, которую будет
использовать устройство, поэтому найденные эндпоинты сразу для неё валидны.
Форматы `warp-chain-links.txt` и `warp-chain.json` те же; при импорте в
NekoBox for Android ссылка `wg://` распознаётся, поддержка `awg://` зависит
от версии приложения — в крайнем случае используйте вариант Б (Custom Config
с полным конфигом).

Два нюанса Android:

- **DNS.** В сборке без cgo чистый Go-резолвер не знает системный DNS
  Android (нет `/etc/resolv.conf`). warp-chain это обходит: при провале
  системного резолва запросы к Cloudflare API идут через публичные DNS
  (1.1.1.1 / 8.8.8.8 / 9.9.9.9).
- **Регистрация аккаунта.** `warpscout register` на Android может упереться
  в ту же особенность DNS — если аккаунта ещё нет, проще один раз
  зарегистрировать его на ПК и скопировать `warpscout-account.json` на
  телефон (укажите путь через `-account`). Сканы эндпоинтов DNS не требуют
  и на Android работают.

## Приватность

Всё, что содержит реальные приватные ключи и токены, живёт в `data/` и
`out/` — оба каталога исключены из git (см. `.gitignore`), и ничего из них не
должно попадать в репозиторий или в публичную сборку.
