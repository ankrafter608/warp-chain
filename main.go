package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const cloudflarePeerKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

// overridden by build scripts via -ldflags "-X main.version=..."
var version = "dev"

// appDirs resolves the layout next to the executable:
//
//	<exe>/          the program itself
//	<exe>/data/     warpscout, account, state cache
//	<exe>/out/      generated configs
//
// `go run` puts the binary in a temp dir — fall back to the working directory
// there so dev runs don't litter %TEMP%.
func appDirs() (base, data, out string) {
	base = "."
	if exe, err := os.Executable(); err == nil {
		if d := filepath.Dir(exe); !strings.HasPrefix(strings.ToLower(d), strings.ToLower(os.TempDir())) {
			base = d
		}
	}
	return base, filepath.Join(base, "data"), filepath.Join(base, "out")
}

// warpscout's built-in I1 probe (iCloud DNS query) — the init-packet mimicry
// the scans themselves were verified with. Override with -i1, disable with "-i1 none".
const defaultI1 = "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"

type options struct {
	warpscoutPath string
	accountPath   string
	dataDir       string
	outDir        string
	statePath     string

	countries   string
	excludeNode string
	node        string
	port        int

	baseEndpoint string
	exitEndpoint string

	interactive bool // stdin is a terminal and -plain not given

	mtuTun  int
	mtuBase int
	mtuExit int

	jc, jmin, jmax int
	i1             string

	noIPv6 bool

	rescan bool
	plain  bool
	relay  string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nwarp-chain: %v\n", err)
		waitForEnter("Нажмите Enter, чтобы закрыть окно...")
		os.Exit(1)
	}
}

// waitForEnter keeps the console window open when launched by double-click.
// Skipped when stdin is not a terminal (piped/automated runs must not block).
func waitForEnter(msg string) {
	if !stdinIsTerminal() {
		return
	}
	fmt.Printf("\n%s", msg)
	_, _ = stdinReader.ReadString('\n')
}

func run() error {
	var o options
	var scanTimeout int
	var showVersion bool

	_, dataDir, outDir := appDirs()
	o.dataDir = dataDir
	o.outDir = outDir

	flag.StringVar(&o.warpscoutPath, "warpscout", "", "path to warpscout.exe (default: auto-download into data/)")
	flag.StringVar(&o.accountPath, "account", "", "path to warpscout-account.json (default: data/warpscout-account.json)")
	flag.StringVar(&o.outDir, "out", o.outDir, "output directory for generated configs")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.StringVar(&o.countries, "country", "FI,SE,DE", "exit countries (comma-separated ISO codes, empty = any)")
	flag.StringVar(&o.excludeNode, "exclude-node", "DME,LED", "edge nodes to exclude in phase 1 (empty = keep all)")
	flag.StringVar(&o.node, "node", "", "restrict phase 1 to these edge nodes, e.g. HEL,ARN")
	flag.IntVar(&o.port, "port", 0, "restrict scanned WARP port (0 = all ports)")
	flag.StringVar(&o.baseEndpoint, "base-endpoint", "", "reuse this phase-1 endpoint (ip:port), skip scan 1")
	flag.StringVar(&o.exitEndpoint, "exit-endpoint", "", "reuse this phase-2 endpoint (ip:port), skip scan 2")
	flag.IntVar(&o.mtuTun, "mtu-tun", 1200, "TUN inbound MTU")
	flag.IntVar(&o.mtuBase, "mtu-base", 1280, "AWG-BASE tunnel MTU")
	flag.IntVar(&o.mtuExit, "mtu-exit", 1200, "WARP-EXIT tunnel MTU")
	flag.IntVar(&o.jc, "jc", 6, "AmneziaWG junk packet count")
	flag.IntVar(&o.jmin, "jmin", 21, "AmneziaWG junk packet min size")
	flag.IntVar(&o.jmax, "jmax", 56, "AmneziaWG junk packet max size")
	flag.StringVar(&o.i1, "i1", defaultI1, `AmneziaWG I1 signature packet ("none" to disable)`)
	flag.BoolVar(&o.noIPv6, "no-ipv6", false, "generate IPv4-only profiles (for machines with IPv6 disabled in Windows)")
	flag.BoolVar(&o.rescan, "rescan", false, "ignore cached endpoints and rescan")
	flag.BoolVar(&o.plain, "plain", false, "non-interactive: never prompt, use defaults/flags")
	flag.StringVar(&o.relay, "relay", "https://edge-client-api.vercel.app", "relay for Cloudflare API requests (\"direct\" to skip the relay, \"none\" = direct only)")
	flag.IntVar(&scanTimeout, "scan-timeout", 5, "per-request timeout passed to warpscout (-t)")

	flag.Parse()

	if showVersion {
		fmt.Println("warp-chain", version)
		return nil
	}

	o.statePath = filepath.Join(o.dataDir, "state.json")

	fmt.Println(banner())
	fmt.Printf("версия:    %s\n", version)

	// --- warpscout ---
	var err error
	o.warpscoutPath, err = resolveWarpscout(o.warpscoutPath, o.dataDir)
	if err != nil {
		return err
	}
	if o.accountPath == "" {
		o.accountPath = filepath.Join(o.dataDir, "warpscout-account.json")
	}
	fmt.Printf("warpscout: %s\n", o.warpscoutPath)
	fmt.Printf("аккаунт:   %s\n", o.accountPath)
	fmt.Printf("конфиги:   %s\n", o.outDir)

	// --- wizard (only where flags didn't decide) ---
	o.interactive = !o.plain && stdinIsTerminal()
	if o.interactive {
		o.countries = prompt("Страны выхода (ISO, через запятую)", o.countries)
		o.node = prompt("Ноды фазы 1 (HEL,ARN,FRA; пусто = все кроме exclude-node)", o.node)
		o.excludeNode = prompt("Исключаемые ноды фазы 1", o.excludeNode)
		fmt.Println()
	}

	countries := splitCSV(o.countries)

	// --- state ---
	st, err := loadState(o.statePath)
	if err != nil {
		return err
	}

	// --- accounts ---
	accounts, fresh, err := ensureAccounts(o)
	if err != nil {
		return err
	}
	if fresh {
		// account keys rotated/changed — cached reserved bytes are no longer valid
		st.Reserved = map[string]string{}
	}
	if err := ensureReserved(o, st, accounts); err != nil {
		return fmt.Errorf("reserved: %w", err)
	}

	// --- endpoints ---
	base, exit, err := ensureEndpoints(o, st, countries, scanTimeout)
	if err != nil {
		return err
	}
	st.BaseEndpoint = base
	st.ExitEndpoint = exit

	// --- generate ---
	files, err := generateAll(o, st, accounts, countries, base, exit)
	if err != nil {
		return err
	}
	if err := saveState(o.statePath, st); err != nil {
		return err
	}

	fmt.Println("\nГотово. Созданные файлы:")
	for _, f := range files {
		fmt.Printf("  %s\n", f)
	}
	if o.interactive {
		for _, f := range files {
			if filepath.Base(f) == "warp-chain-profiles.json" {
				if copyToClipboard(f) {
					fmt.Println("\nСодержимое warp-chain-profiles.json скопировано в буфер обмена: " +
						"NekoBox -> Сервер -> Добавить профиль из буфера обмена.")
				}
				break
			}
		}
	}
	fmt.Println("\nПапка результатов:", filepath.Dir(files[0]))
	fmt.Println(nextSteps(files))
	waitForEnter("Нажмите Enter, чтобы закрыть окно...")
	return nil
}

func ensureAccounts(o options) (account, bool, error) {
	acc, err := loadAccount(o.accountPath)
	switch {
	case err == nil:
		if acc.Outer == nil {
			return acc, false, errors.New(
				"в аккаунте нет устройства outer — перерегистрируйте: warpscout register -a \"" + o.accountPath + "\"")
		}
		return acc, false, nil
	case errors.Is(err, os.ErrNotExist):
		fmt.Println("Аккаунт не найден — запускаю warpscout register (может занять до минуты)...")
		if err := warpscoutRegister(o); err != nil {
			return acc, false, err
		}
		acc, err = loadAccount(o.accountPath)
		if err != nil {
			return acc, false, err
		}
		if acc.Outer == nil {
			return acc, true, errors.New("регистрация не создала устройство outer (WARP-in-WARP невозможен)")
		}
		return acc, true, nil
	default:
		return acc, false, err
	}
}

func ensureReserved(o options, st *state, acc account) error {
	if st.Reserved == nil {
		st.Reserved = map[string]string{}
	}
	type dev struct {
		name string
		id   string
	}
	for _, d := range []dev{{"main", acc.ID}, {"outer", acc.Outer.ID}} {
		if _, ok := st.Reserved[d.name]; ok && st.Reserved[d.name] != "" {
			continue
		}
		fmt.Printf("Получаю Reserved (client_id) для %s через Cloudflare API...\n", d.name)
		res, via, err := fetchReserved(o.relay, d.id, tokenFor(acc, d.name))
		if err != nil {
			return fmt.Errorf("не удалось получить client_id для %s (id=%s): %v", d.name, d.id, err)
		}
		st.Reserved[d.name] = res
		fmt.Printf("  %s Reserved = %s (via %s)\n", d.name, res, via)
	}
	return nil
}

func tokenFor(acc account, name string) string {
	if name == "outer" {
		return acc.Outer.Token
	}
	return acc.Token
}

func ensureEndpoints(o options, st *state, countries []string, scanTimeout int) (string, string, error) {
	base, exit := o.baseEndpoint, o.exitEndpoint
	if base == "" && !o.rescan && st.BaseEndpoint != "" {
		base = st.BaseEndpoint
		fmt.Printf("Фаза 1: использую кэшированный эндпоинт %s (-rescan для пересканирования)\n", base)
	}
	if exit == "" && !o.rescan && st.ExitEndpoint != "" {
		exit = st.ExitEndpoint
		fmt.Printf("Фаза 2: использую кэшированный эндпоинт %s (-rescan для пересканирования)\n", exit)
	}

	var err error
	if base == "" {
		fmt.Println("Фаза 1/2: сканирую базовый эндпоинт (AmneziaWG, это может занять несколько минут)...")
		if o.interactive {
			base, err = scanAndPick(o, scanArgs{
				countries: countries, excludeNode: o.excludeNode, node: o.node,
				port: o.port, timeout: scanTimeout, phase: 1,
			})
		} else {
			base, err = scanBest(o, scanArgs{
				countries: countries, excludeNode: o.excludeNode, node: o.node,
				port: o.port, timeout: scanTimeout, phase: 1,
			})
		}
		if err != nil {
			return "", "", fmt.Errorf("фаза 1: %w", err)
		}
		fmt.Printf("Фаза 1: базовый эндпоинт = %s\n", base)
	}
	if exit == "" {
		fmt.Println("Фаза 2/2: сканирую exit-эндпоинт через базовый (ещё несколько минут)...")
		if o.interactive {
			exit, err = scanAndPick(o, scanArgs{
				countries: countries, through: base,
				port: o.port, timeout: scanTimeout, phase: 2,
			})
		} else {
			exit, err = scanBest(o, scanArgs{
				countries: countries, through: base,
				port: o.port, timeout: scanTimeout, phase: 2,
			})
		}
		if err != nil {
			return "", "", fmt.Errorf("фаза 2: %w", err)
		}
		fmt.Printf("Фаза 2: exit-эндпоинт = %s\n", exit)
	}
	return base, exit, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(strings.ToUpper(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

var stdinReader = bufio.NewReader(os.Stdin)

func prompt(label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, _ := stdinReader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func banner() string {
	return fmt.Sprintf(`
warp-chain %s — генератор WARP-in-WARP (AmneziaWG -> WireGuard) для NekoBox
---------------------------------------------------------------------------`, version)
}

func nextSteps(files []string) string {
	var card, js, links, profiles string
	for _, f := range files {
		switch {
		case strings.HasSuffix(f, ".md"):
			card = f
		case filepath.Base(f) == "warp-chain.json": // not warp-chain-test.json
			js = f
		case strings.HasSuffix(f, "-links.txt"):
			links = f
		case filepath.Base(f) == "warp-chain-profiles.json":
			profiles = f
		}
	}
	return fmt.Sprintf(`
Дальше — два варианта.

Вариант А (профили + цепочка):
  1. NekoBox: Сервер -> Добавить профиль из буфера обмена, вставив весь текст
     %s — появятся оба профиля (AWG-BASE и WARP-EXIT). Их же можно добавить
     по ссылкам из %s (по очереди).
  2. Сервер -> Добавить профиль вручную -> Тип: Цепочка прокси:
     AWG-BASE, затем WARP-EXIT. Нажмите Enter на цепочке.
  3. Включите Режим TUN; MTU TUN = 1200 (Настройки -> Настройки режима TUN);
     DNS — как в карточке.

Вариант B (Custom Config, одним файлом) в текущих сборках NekoBox НЕ работает:
приложение при запуске дописывает в эндпоинты "server": null, и его ядро
отклоняет конфиг ("unknown field server") — это баг NekoBox, не конфига.
Файл %s остаётся для прямого запуска ядром (sing-box run -c).

Все значения полей и чек-лист проверки: %s`, profiles, links, js, card)
}
