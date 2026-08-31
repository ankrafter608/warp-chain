package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Profile/endpoint mapping mirrors what warpscout verifies with its own
// `-through` scan: the OUTER tunnel (AWG-BASE) is built with the account's
// "outer" device, the INNER tunnel (WARP-EXIT) with the main device.
//
// The generated sing-box JSON follows the qr243vbi NekoBox fork:
//   - WG/AWG are endpoints (the "endpoints" array), not outbounds;
//   - "awg" endpoint has flat junk params (jc/jmin/jmax, s1-s4, string h1-h4, i1-i5)
//     and NO reserved field at all (the core ignores client_id for AWG);
//   - "wireguard" endpoint carries reserved (the WARP client_id) — critical for upload;
//   - the exit is tagged "proxy" so NekoBox's full-config DNS normalization
//     (detour: "proxy") and its routing rules point at the chain exit.

type sbPeer struct {
	Address             string   `json:"address"`
	Port                int      `json:"port"`
	PublicKey           string   `json:"public_key"`
	PreSharedKey        string   `json:"pre_shared_key"`
	Reserved            []int    `json:"reserved,omitempty"`
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive_interval"`
}

type sbAwgEndpoint struct {
	Type             string   `json:"type"`
	Tag              string   `json:"tag"`
	Address          []string `json:"address"`
	PrivateKey       string   `json:"private_key"`
	MTU              int      `json:"mtu"`
	UseIntegratedTun bool     `json:"useIntegratedTun"`
	Peers            []sbPeer `json:"peers"`
	JC               int      `json:"jc"`
	Jmin             int      `json:"jmin"`
	Jmax             int      `json:"jmax"`
	S1               int      `json:"s1"`
	S2               int      `json:"s2"`
	S3               int      `json:"s3"`
	S4               int      `json:"s4"`
	H1               string   `json:"h1"`
	H2               string   `json:"h2"`
	H3               string   `json:"h3"`
	H4               string   `json:"h4"`
	I1               string   `json:"i1,omitempty"`
	I2               string   `json:"i2,omitempty"`
	I3               string   `json:"i3,omitempty"`
	I4               string   `json:"i4,omitempty"`
	I5               string   `json:"i5,omitempty"`
}

type sbWgEndpoint struct {
	Type       string   `json:"type"`
	Tag        string   `json:"tag"`
	Detour     string   `json:"detour,omitempty"`
	Name       string   `json:"name,omitempty"`
	Address    []string `json:"address"`
	PrivateKey string   `json:"private_key"`
	MTU        int      `json:"mtu"`
	System     bool     `json:"system"`
	Peers      []sbPeer `json:"peers"`
}

type sbLog struct {
	Level     string `json:"level"`
	Timestamp bool   `json:"timestamp"`
}

type sbDNSServer struct {
	Tag            string `json:"tag"`
	Type           string `json:"type"`
	Server         string `json:"server,omitempty"`
	Detour         string `json:"detour,omitempty"`
	DomainResolver string `json:"domain_resolver,omitempty"`
}

type sbDNS struct {
	Servers          []sbDNSServer `json:"servers"`
	Final            string        `json:"final"`
	Strategy         string        `json:"strategy,omitempty"`
	IndependentCache bool          `json:"independent_cache"`
}

type sbTunInbound struct {
	Type          string   `json:"type"`
	Tag           string   `json:"tag"`
	InterfaceName string   `json:"interface_name"`
	Address       []string `json:"address"`
	MTU           int      `json:"mtu"`
	AutoRoute     bool     `json:"auto_route"`
	StrictRoute   bool     `json:"strict_route"`
	Stack         string   `json:"stack"`
}

type sbOutbound struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
}

type sbRouteRule struct {
	Inbound  []string `json:"inbound,omitempty"`
	Action   string   `json:"action,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
}

type sbResolver struct {
	Server   string `json:"server"`
	Strategy string `json:"strategy,omitempty"`
}

type sbRoute struct {
	Rules                 []sbRouteRule `json:"rules"`
	Final                 string        `json:"final"`
	AutoDetectInterface   bool          `json:"auto_detect_interface"`
	DefaultDomainResolver *sbResolver   `json:"default_domain_resolver,omitempty"`
}

type sbConfig struct {
	Log       sbLog          `json:"log"`
	DNS       sbDNS          `json:"dns"`
	Inbounds  []sbTunInbound `json:"inbounds"`
	Outbounds []sbOutbound   `json:"outbounds"`
	Endpoints []any          `json:"endpoints"`
	Route     sbRoute        `json:"route"`
}

const (
	tagBase = "awg-base"
	tagExit = "proxy" // NekoBox full-config DNS detour hardcodes "proxy"
)

// the GUI appends a throwaway ULA to a WG hop carried inside another WG
const nestedULA = "fdfe:dcba:9876::1/128"

func localAddrs(o options, a *account) []string {
	var out []string
	if a.IPv4 != "" {
		out = append(out, a.IPv4+"/32")
	}
	if a.IPv6 != "" && !o.noIPv6 {
		out = append(out, a.IPv6+"/128")
	}
	return out
}

func allowedIPs(o options) []string {
	if o.noIPv6 {
		return []string{"0.0.0.0/0"}
	}
	return []string{"0.0.0.0/0", "::/0"}
}

// tunInAddrs is the standalone TUN inbound address list (Variant B full config).
func tunInAddrs(o options) []string {
	if o.noIPv6 {
		return []string{"172.19.0.1/28"}
	}
	return []string{"172.19.0.1/28", nestedULA}
}

func buildAwgBase(o options, acc *account, endpoint string) *sbAwgEndpoint {
	ip, port := splitEndpoint(endpoint, 2408)
	ep := &sbAwgEndpoint{
		Type:             "awg",
		Tag:              tagBase,
		Address:          localAddrs(o, acc),
		PrivateKey:       acc.PrivateKey,
		MTU:              o.mtuBase,
		UseIntegratedTun: false,
		Peers: []sbPeer{{
			Address:             ip,
			Port:                port,
			PublicKey:           cloudflarePeerKey,
			PreSharedKey:        "",
			AllowedIPs:          allowedIPs(o),
			PersistentKeepalive: 25,
		}},
		JC:   o.jc,
		Jmin: o.jmin,
		Jmax: o.jmax,
		H1:   "1",
		H2:   "2",
		H3:   "3",
		H4:   "4",
	}
	if i1 := strings.TrimSpace(o.i1); i1 != "" && !strings.EqualFold(i1, "none") {
		ep.I1 = i1
	}
	return ep
}

func buildWgExit(o options, acc *account, endpoint string, reserved string) *sbWgEndpoint {
	ip, port := splitEndpoint(endpoint, 2408)
	addr := localAddrs(o, acc)
	if !o.noIPv6 {
		addr = append(addr, nestedULA)
	}
	return &sbWgEndpoint{
		Type:       "wireguard",
		Tag:        tagExit,
		Detour:     tagBase,
		Name:       "wg_warpexit",
		Address:    addr,
		PrivateKey: acc.PrivateKey,
		MTU:        o.mtuExit,
		Peers: []sbPeer{{
			Address:             ip,
			Port:                port,
			PublicKey:           cloudflarePeerKey,
			PreSharedKey:        "",
			Reserved:            reservedList(reserved),
			AllowedIPs:          allowedIPs(o),
			PersistentKeepalive: 25,
		}},
	}
}

func buildConfig(o options, acc account, base, exit, reservedMain string) *sbConfig {
	return &sbConfig{
		Log: sbLog{Level: "info", Timestamp: true},
		DNS: sbDNS{
			Servers: []sbDNSServer{
				{Tag: "dns-remote", Type: "https", Server: "1.1.1.1", Detour: tagExit},
				{Tag: "dns-local", Type: "local"},
			},
			Final:            "dns-remote",
			Strategy:         "prefer_ipv4",
			IndependentCache: true,
		},
		Inbounds: []sbTunInbound{{
			Type:          "tun",
			Tag:           "tun-in",
			InterfaceName: "warpchain",
			Address:       tunInAddrs(o),
			MTU:           o.mtuTun,
			AutoRoute:     true,
			StrictRoute:   true,
			Stack:         "mixed",
		}},
		Outbounds: []sbOutbound{{Type: "direct", Tag: "direct"}},
		Endpoints: []any{
			buildAwgBase(o, acc.Outer, base),
			buildWgExit(o, &acc, exit, reservedMain),
		},
		Route: sbRoute{
			Rules: []sbRouteRule{
				{Inbound: []string{"tun-in"}, Action: "sniff"},
				{Protocol: "dns", Action: "hijack-dns"},
			},
			Final:                 tagExit,
			AutoDetectInterface:   true,
			DefaultDomainResolver: &sbResolver{Server: "dns-local"},
		},
	}
}

// buildTestConfig is the same chain with a local socks/mixed inbound instead of
// TUN — lets the user prove the tunnels work (browser proxy 127.0.0.1:17890)
// without admin rights and without touching NekoBox's own TUN/DNS settings.
func buildTestConfig(o options, acc account, base, exit, reservedMain string) map[string]any {
	return map[string]any{
		"log": map[string]any{"level": "info", "timestamp": true},
		"dns": map[string]any{
			"servers": []map[string]any{
				{"tag": "dns-remote", "type": "https", "server": "1.1.1.1", "detour": tagExit},
				{"tag": "dns-local", "type": "local"},
			},
			"final":             "dns-remote",
			"strategy":          "prefer_ipv4",
			"independent_cache": true,
		},
		"inbounds": []map[string]any{{
			"type": "mixed", "tag": "mixed-in",
			"listen": "127.0.0.1", "listen_port": 17890,
		}},
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"endpoints": []any{
			buildAwgBase(o, acc.Outer, base),
			buildWgExit(o, &acc, exit, reservedMain),
		},
		"route": map[string]any{
			"rules": []map[string]any{
				{"inbound": []string{"mixed-in"}, "action": "sniff"},
				{"protocol": "dns", "action": "hijack-dns"},
			},
			"final":                   tagExit,
			"auto_detect_interface":   true,
			"default_domain_resolver": map[string]any{"server": "dns-remote"},
		},
	}
}

func splitEndpoint(ep string, defPort int) (string, int) {
	i := strings.LastIndex(ep, ":")
	if i < 0 {
		return ep, defPort
	}
	ip := strings.Trim(ep[:i], "[]")
	port, err := strconv.Atoi(ep[i+1:])
	if err != nil || port <= 0 {
		return ep, defPort
	}
	return ip, port
}

// --- share links -------------------------------------------------------------

func buildLinks(o options, acc account, base, exit, reservedMain, reservedOuter string) (string, string) {
	awgExtra := map[string]string{
		"enable_amnezia":                "true",
		"junk_packet_count":             strconv.Itoa(o.jc),
		"junk_packet_min_size":          strconv.Itoa(o.jmin),
		"junk_packet_max_size":          strconv.Itoa(o.jmax),
		"init_packet_magic_header":      "1",
		"response_packet_magic_header":  "2",
		"cookie_reply_magic_header":     "3",
		"transport_packet_magic_header": "4",
		"i1":                            strings.TrimSpace(o.i1),
	}
	baseLink := profileLink("awg", "AWG-BASE", acc.Outer.PrivateKey, cloudflarePeerKey,
		localAddrs(o, acc.Outer), o.mtuBase, reservedList(reservedOuter), awgExtra, base)
	exitLink := profileLink("wg", "WARP-EXIT", acc.PrivateKey, cloudflarePeerKey,
		localAddrs(o, &acc), o.mtuExit, reservedList(reservedMain), nil, exit)
	return baseLink, exitLink
}

func profileLink(scheme, name, privKey, pubKey string, addrs []string, mtu int, reserved []int, extra map[string]string, endpoint string) string {
	ip, port := splitEndpoint(endpoint, 2408)
	u := url.URL{
		Scheme:   scheme,
		Host:     fmt.Sprintf("%s:%d", ip, port),
		Fragment: name,
	}
	q := url.Values{}
	q.Set("private_key", privKey)
	q.Set("peer_public_key", pubKey)
	q.Set("pre_shared_key", "")
	if len(reserved) > 0 {
		parts := make([]string, len(reserved))
		for i, v := range reserved {
			parts[i] = strconv.Itoa(v)
		}
		q.Set("reserved", strings.Join(parts, "-"))
	}
	q.Set("local_address", strings.Join(addrs, "-"))
	q.Set("persistent_keepalive", "25")
	q.Set("mtu", strconv.Itoa(mtu))
	// NekoBox fork quirk (qr243vbi): From_Link::set_boolean inverts the flag —
	// with the bean default (false) and the param ABSENT, "use system interface"
	// imports as TRUE, which sends AWG down the Wintun path and fails on machines
	// with IPv6 disabled ("set ipv6 options: The parameter is incorrect").
	// In that parser, an explicit "true" is what yields the desired false.
	// After import, the "Use System Interface" checkbox must be OFF in both profiles.
	q.Set("use_system_interface", "true")
	for k, v := range extra {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	// Go's form encoding writes spaces as "+", but NekoBox parses links with
	// Qt QUrlQuery, which does NOT decode "+" as a space — the I1 markup then
	// reaches the core as "<r+2><b+0x...>" and amnezia-go rejects it
	// ("IPC error -22 ... unknown tag"). Percent-encode spaces instead;
	// literal "+" from base64 keys is already %2B at this point.
	u.RawQuery = strings.ReplaceAll(u.RawQuery, "+", "%20")
	return u.String()
}

// --- writers -----------------------------------------------------------------

func generateAll(o options, st *state, acc account, countries []string, base, exit string) ([]string, error) {
	reservedMain := st.Reserved["main"]
	reservedOuter := st.Reserved["outer"]

	if err := os.MkdirAll(o.outDir, 0755); err != nil {
		return nil, err
	}
	stamp := time.Now()
	var written []string

	cfgJSON, err := marshalNoEscape(buildConfig(o, acc, base, exit, reservedMain))
	if err != nil {
		return nil, err
	}
	jsonPath := filepath.Join(o.outDir, "warp-chain.json")
	if err := os.WriteFile(jsonPath, append(cfgJSON, '\n'), 0644); err != nil {
		return nil, err
	}
	written = append(written, jsonPath)

	baseLink, exitLink := buildLinks(o, acc, base, exit, reservedMain, reservedOuter)
	linksPath := filepath.Join(o.outDir, "warp-chain-links.txt")
	links := fmt.Sprintf("# Импорт в NekoBox: Сервер -> Добавить профиль из буфера обмена.\n# По очереди: сначала строка AWG-BASE, затем WARP-EXIT.\n\n%s\n\n%s\n",
		baseLink, exitLink)
	if err := os.WriteFile(linksPath, []byte(links), 0644); err != nil {
		return nil, err
	}
	written = append(written, linksPath)

	cardPath := filepath.Join(o.outDir, "warp-chain-card.md")
	card := buildCard(stamp, o, acc, countries, base, exit, baseLink, exitLink, reservedMain, reservedOuter)
	if err := os.WriteFile(cardPath, []byte(card), 0644); err != nil {
		return nil, err
	}
	written = append(written, cardPath)

	testJSON, err := marshalNoEscape(buildTestConfig(o, acc, base, exit, reservedMain))
	if err != nil {
		return nil, err
	}
	testPath := filepath.Join(o.outDir, "warp-chain-test.json")
	if err := os.WriteFile(testPath, append(testJSON, '\n'), 0644); err != nil {
		return nil, err
	}
	written = append(written, testPath)

	batPath := filepath.Join(o.outDir, "test-chain.bat")
	if err := os.WriteFile(batPath, []byte(testBat), 0644); err != nil {
		return nil, err
	}
	written = append(written, batPath)

	return written, nil
}

// testBat is ASCII-only on purpose: .bat files are interpreted in the OEM
// codepage, and Cyrillic text would turn to mojibake on the user's machine.
const testBat = `@echo off
setlocal
set "DIR=%~dp0"
set "CORE="
if exist "%DIR%nekobox_core.exe" set "CORE=%DIR%nekobox_core.exe"
if exist "%APPDATA%\NekoBox\nekobox_core.exe" set "CORE=%APPDATA%\NekoBox\nekobox_core.exe"
if exist "%LOCALAPPDATA%\NekoBox\nekobox_core.exe" set "CORE=%LOCALAPPDATA%\NekoBox\nekobox_core.exe"
if "%CORE%"=="" (
  echo nekobox_core.exe not found. Install NekoBox or copy this file next to it.
  pause
  exit /b 1
)
echo Using core: %CORE%
echo.
echo Starting WARP-in-WARP chain. It is ready when you see "Core started" lines.
echo Browser proxy: socks5, address 127.0.0.1, port 17890
echo Then open https://2ip.ru - it should show a Cloudflare location, not RU.
echo Stop: close this window or press Ctrl+C.
echo.
"%CORE%" sing-box run -c "%DIR%warp-chain-test.json"
pause
`

func buildCard(stamp time.Time, o options, acc account, countries []string, base, exit, baseLink, exitLink, reservedMain, reservedOuter string) string {
	baseIP, basePort := splitEndpoint(base, 2408)
	exitIP, exitPort := splitEndpoint(exit, 2408)
	var b strings.Builder

	fmt.Fprintf(&b, `# WARP-in-WARP — конфигурация для NekoBox

Сгенерировано warp-chain %s

- Страны выхода: %s
- Базовый эндпоинт (AWG-BASE): %s
- Exit-эндпоинт (WARP-EXIT): %s
- Аккаунт 1 (AWG-BASE): warpscout "outer" (id %s)
- Аккаунт 2 (WARP-EXIT): warpscout "main" (id %s)

## Вариант A — два профиля + цепочка (как в ручной инструкции)

### Быстрый импорт

Скопируйте по очереди строки ниже и в NekoBox: **Сервер -> Добавить профиль из
буфера обмена** (NekoBox сам распознает тип AmneziaWG/WireGuard).

1. Ссылка AWG-BASE:

`+"```"+`
%s
`+"```"+`

2. Ссылка WARP-EXIT:

`+"```"+`
%s
`+"```"+`

### Цепочка

**Сервер -> Добавить профиль вручную -> Тип: Цепочка прокси**, название
%s, узлы строго по порядку:

1. %s (входящий)
2. %s (исходящий)

Активируйте цепочку (Enter по профилю WARP-in-WARP).

## Вариант B — один полный конфиг

**Сервер -> Добавить профиль вручную -> Тип: Custom Config**, ядро sing-box,
режим «Полный конфиг» (internal-full) — вставьте содержимое warp-chain.json.
TUN и DNS при этом управляются настройками самого NekoBox (см. ниже).

## Значения полей (для проверки/ручного ввода)

### Профиль 1: AWG-BASE (тип AmneziaWG, аккаунт outer)

| Поле | Значение |
| :--- | :--- |
| Название | %s |
| Адрес | %s |
| Порт | %d |
| Приватный ключ | %s |
| Публичный ключ | %s |
| Резервный (Reserved) | %s |
| Локальный адрес | %s |
| MTU | %d |
| Jc | %d |
| Jmin | %d |
| Jmax | %d |
| H1 / H2 / H3 / H4 | 1 / 2 / 3 / 4 |
| S1 / S2 / S3 / S4 | 0 |
| I1 | %s |
| Использовать системный интерфейс | **выключено** (галочка снята) |

> Примечание: ядро NekoBox (форк sing-box) для AmneziaWG **не использует**
> Reserved — поле оставлено для полноты, на работу цепочки оно не влияет.
> Если NekoBox импортировал ссылку, но AWG не поднимается, попробуйте
> пересканировать с другим I1: warp-chain -rescan -i1 none.

### Профиль 2: WARP-EXIT (тип Wireguard, аккаунт main)

| Поле | Значение |
| :--- | :--- |
| Название | %s |
| Адрес | %s |
| Порт | %d |
| Приватный ключ | %s |
| Публичный ключ | %s |
| Резервный (Reserved) | %s |
| Локальный адрес | %s |
| MTU | %d |
| Использовать системный интерфейс | **выключено** (галочка снята) |

> **Reserved здесь критически важен** — без него отдача (upload) упадёт до 0.
> Настройки Amnezia для этого профиля включать не нужно.

> **Важно про галочку «Использовать системный интерфейс» (Use System Interface):**
> в текущих сборках NekoBox (форк qr243vbi) есть баг парсера ссылок — при импорте
> эта галочка включается, даже если в ссылке не сказано иное. С включённой галочкой
> AmneziaWG создаёт реальный Wintun-адаптер и на машинах с отключённым IPv6 падает
> с ошибкой «set ipv6 options: The parameter is incorrect». Параметр
> use_system_interface в ссылках выше подобран так, чтобы галочка после импорта
> была снята — **проверьте это в обоих профилях** и снимите вручную, если она стоит.

## Настройки NekoBox (КРИТИЧНО)

1. **TUN MTU = %d**: Настройки -> Настройки режима TUN -> MTU
   (двойная инкапсуляция съедает место; иначе PR_END_OF_FILE_ERROR на GitHub/Roblox).
2. **DNS**: Настройки -> Маршруты -> вкладка DNS:
   - Удалённый DNS: https://1.1.1.1/dns-query (или 8.8.8.8)
   - Стратегия запросов: PreferIPv4
   - DNS для прямых запросов: localhost (или 77.88.8.8)
   - «Подделка IP» (FakeIP): **выключено**
   - DNS-сервер по умолчанию: remote
3. В обоих профилях (AWG-BASE и WARP-EXIT) галочка **«Использовать системный
   интерфейс» должна быть снята** (см. примечание ниже).
4. Включите галочку **Режим TUN** и активируйте профиль WARP-in-WARP.

## Проверка

1. [2ip.ru](https://2ip.ru) или [browserleaks.com/ip](https://browserleaks.com/ip):
   страна — Финляндия/Швеция/Германия, провайдер Cloudflare, Inc.
2. Speedtest: симметричные 80-90 Мбит/с.
3. Если сайты видят RU — пересканируйте: warp-chain -rescan -node HEL
   (или -exclude-node DME, если фильтр нод не задан).

## Если цепочка активна, но сайты не грузятся (Discord при этом живой)

Так бывает, когда сами туннели поднялись, а DNS или TUN-режим настроены
неверно. Проверяйте по шагам:

1. **Настройки DNS** (Настройки -> Маршруты -> вкладка DNS): FakeIP выключен,
   DNS-сервер по умолчанию = remote, стратегия PreferIPv4. Переподключите цепочку.
2. **Порядок узлов цепочки**: первый (входящий) — AWG-BASE, второй — WARP-EXIT.
3. **Тест без TUN**: выключите Режим TUN, включите Системный прокси, активируйте
   цепочку и откройте 2ip.ru. Если грузится и показывает Cloudflare/Финляндию —
   цепочка работает, проблема в режиме TUN: попробуйте стек **gvisor**,
   выключите strict route или снизьте TUN MTU до 1100.
4. **Автономный тест цепочки** (мимо NekoBox): запустите test-chain.bat из этой
   папки, пропишите в браузере прокси socks5 127.0.0.1:17890 и откройте 2ip.ru.
   Работает — туннели в порядке, ищите проблему в настройках NekoBox.
   Не работает — пересканируйте: warp-chain -rescan.
5. **Журнал**: в NekoBox откройте лог (уровень debug) и посмотрите, что идёт
   при попытке открыть сайт: ошибки DNS — пункт 1, таймауты connect — пункты 2-4.

## Troubleshooting

| Симптом | Причина | Решение |
| :--- | :--- | :--- |
| Upload = 0 | неверный Reserved у WARP-EXIT | проверьте Reserved (аккаунт main) |
| create tunnel: set ipv6 options: The parameter is incorrect | в профиле включён «Использовать системный интерфейс», а IPv6 в Windows отключён | снимите галочку в обоих профилях и перезапустите цепочку; либо перегенерируйте: warp-chain -no-ipv6 (переимпорт ссылок); либо включите IPv6 в Windows |
| PR_END_OF_FILE_ERROR | слишком большой MTU | TUN MTU = %d |
| SSL_ERROR_RX_RECORD_TOO_LONG | утечка DNS к провайдеру | DNS по умолчанию = remote; ipconfig /flushdns |
| SEEN AS: RU | внешний туннель попал на ноду DME | warp-chain -rescan (проверьте -exclude-node) |
`,
		stamp.Format("2006-01-02 15:04"),
		strings.Join(countries, ", "), base, exit,
		acc.Outer.ID, acc.ID,
		baseLink, exitLink,
		"`WARP-in-WARP`", "`AWG-BASE`", "`WARP-EXIT`",
		"`AWG-BASE`", "`"+baseIP+"`", basePort,
		"`"+acc.Outer.PrivateKey+"`", "`"+cloudflarePeerKey+"`",
		"`"+reservedOuter+"`", "`"+strings.Join(localAddrs(o, acc.Outer), ", ")+"`", o.mtuBase,
		o.jc, o.jmin, o.jmax,
		"`"+i1ForCard(o.i1)+"`",
		"`WARP-EXIT`", "`"+exitIP+"`", exitPort,
		"`"+acc.PrivateKey+"`", "`"+cloudflarePeerKey+"`",
		"`"+reservedMain+"`", "`"+strings.Join(localAddrs(o, &acc), ", ")+"`", o.mtuExit,
		o.mtuTun,
		o.mtuTun,
	)
	return b.String()
}

func i1ForCard(i1 string) string {
	if i1 == "" || strings.EqualFold(i1, "none") {
		return "(пусто)"
	}
	return i1
}

// marshalNoEscape is plain MarshalIndent without HTML escaping, so the I1
// probe string stays readable instead of \u003c...
func marshalNoEscape(v any) ([]byte, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}
