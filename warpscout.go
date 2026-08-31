package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func warpscoutName() string {
	if runtime.GOOS == "windows" {
		return "warpscout.exe"
	}
	return "warpscout"
}

// resolveWarpscout finds a usable warpscout binary. Explicit -warpscout wins;
// then existing candidates (data dir, cwd, ./warpscout/, PATH); if there is
// none, it is provisioned into dataDir automatically.
func resolveWarpscout(explicit, dataDir string) (string, error) {
	if explicit != "" {
		if st, err := os.Stat(explicit); err == nil && !st.IsDir() {
			return filepath.Abs(explicit)
		}
		return "", fmt.Errorf("warpscout не найден по пути %q (-warpscout)", explicit)
	}
	candidates := []string{
		filepath.Join(dataDir, warpscoutName()),
		warpscoutName(),
		filepath.Join(".", "warpscout", warpscoutName()),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return filepath.Abs(c)
		}
	}
	if p, err := exec.LookPath(warpscoutName()); err == nil {
		return p, nil
	}
	return ensureWarpscout(dataDir)
}

// ensureWarpscout provisions warpscout into dataDir: downloads the latest
// GitHub release, or, if that fails, builds from source with the local Go
// toolchain.
func ensureWarpscout(dataDir string) (string, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return "", err
	}
	dest := filepath.Join(dataDir, warpscoutName())

	fmt.Println("warpscout не найден — скачиваю последний релиз с GitHub...")
	if err := downloadWarpscoutRelease(dest); err != nil {
		fmt.Printf("  скачивание не удалось: %v\n", err)
		fmt.Println("  пробую собрать из исходников (нужен установленный Go)...")
		if err2 := buildWarpscout(dataDir); err2 != nil {
			fmt.Printf("  сборка не удалась: %v\n", err2)
			return "", errors.New("не удалось ни скачать, ни собрать warpscout — положите бинарник в " +
				dataDir + " или укажите путь через -warpscout")
		}
	}
	if _, err := os.Stat(dest); err != nil {
		return "", fmt.Errorf("после установки warpscout не найден: %w", err)
	}
	return dest, nil
}

// --- GitHub releases ---------------------------------------------------------

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

func releaseAssetTag() string {
	return "_" + runtime.GOOS + "_" + runtime.GOARCH + "."
}

func downloadWarpscoutRelease(dest string) error {
	rel, err := latestWarpscoutRelease()
	if err != nil {
		return err
	}
	tag := releaseAssetTag()
	var asset *ghAsset
	for i := range rel.Assets {
		if strings.Contains(rel.Assets[i].Name, tag) {
			asset = &rel.Assets[i]
			break
		}
	}
	if asset == nil {
		return fmt.Errorf("в релизе %s нет архива для %s/%s", rel.TagName, runtime.GOOS, runtime.GOARCH)
	}
	fmt.Printf("  релиз %s: %s\n", rel.TagName, asset.Name)

	tmp, err := os.CreateTemp("", "warpscout-dl-*"+archiveExt(asset.Name))
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	// no client.Timeout: the archive can be slow on a bad connection; the
	// transport below still bounds dial/TLS/handshake phases
	client := &http.Client{Transport: apiTransport}
	resp, err := client.Get(asset.BrowserDownloadURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	n, err := io.Copy(tmp, resp.Body)
	if err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	fmt.Printf("  скачано %.1f МБ, распаковываю...\n", float64(n)/(1<<20))
	return extractWarpscout(tmp.Name(), dest)
}

func archiveExt(name string) string {
	if strings.HasSuffix(name, ".zip") {
		return ".zip"
	}
	return ".tar.gz"
}

// extractWarpscout pulls the warpscout binary out of a release archive into
// dest. Archives contain a single binary (optionally inside a directory).
func extractWarpscout(archivePath, dest string) error {
	if strings.HasSuffix(archivePath, ".zip") {
		return extractFromZip(archivePath, dest)
	}
	return extractFromTarGz(archivePath, dest)
}

func copyEntry(r io.Reader, dest string) error {
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, r)
	return err
}

func extractFromZip(path, dest string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if filepath.Base(f.Name) != warpscoutName() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		return copyEntry(rc, dest)
	}
	return fmt.Errorf("в архиве нет %s", warpscoutName())
}

func extractFromTarGz(path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) != warpscoutName() {
			continue
		}
		return copyEntry(tr, dest)
	}
	return fmt.Errorf("в архиве нет %s", warpscoutName())
}

func latestWarpscoutRelease() (*ghRelease, error) {
	req, err := http.NewRequest(http.MethodGet,
		"https://api.github.com/repos/vernette/warpscout/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "warp-chain")
	client := &http.Client{Timeout: 30 * time.Second, Transport: apiTransport}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" || len(rel.Assets) == 0 {
		return nil, errors.New("пустой ответ GitHub API")
	}
	return &rel, nil
}

// buildWarpscout compiles the latest warpscout into dataDir with the local Go
// toolchain. `go install pkg@latest` is module-free, so it works both inside
// and outside a module directory.
func buildWarpscout(dataDir string) error {
	goTool, err := exec.LookPath("go")
	if err != nil {
		return errors.New("Go не найден в PATH — установите Go 1.25+ или скачайте релиз вручную")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return err
	}
	fmt.Println("  go install github.com/vernette/warpscout@latest (может занять пару минут)...")
	cmd := exec.Command(goTool, "install", "github.com/vernette/warpscout@latest")
	cmd.Env = append(os.Environ(), "GOBIN="+abs)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

type scanArgs struct {
	countries   []string
	excludeNode string
	node        string
	port        int
	timeout     int
	through     string
	phase       int
}

// scanBest runs `warpscout scan ... -best` and returns the ip:port line.
// If -best fails (e.g. every candidate died mid-scan or filters rejected all),
// it re-runs with a report file and parses the table instead.
func scanBest(o options, a scanArgs) (string, error) {
	args := []string{"scan", "-p", "awg", "-plain", "-a", o.accountPath, "-t", strconv.Itoa(a.timeout)}
	if a.node != "" {
		args = append(args, "-node", a.node)
	}
	if a.excludeNode != "" {
		args = append(args, "-exclude-node", a.excludeNode)
	}
	if len(a.countries) > 0 {
		args = append(args, "-country", strings.Join(a.countries, ","))
	}
	if a.port > 0 {
		args = append(args, "-port", strconv.Itoa(a.port))
	}
	if a.through != "" {
		args = append(args, "-through", a.through)
	}

	best := append(append([]string{}, args...), "-best")
	if ep, err := runWarpscout(o.warpscoutPath, best); err == nil && isEndpoint(ep) {
		return ep, nil
	} else if err != nil {
		fmt.Printf("  scan -best не удался (%v) — пробую полный скан с отчётом...\n", err)
	}

	report := filepath.Join(o.outDir, fmt.Sprintf("warpscout-report-phase%d.txt", a.phase))
	full := append(append([]string{}, args...), "-o", report)
	if _, err := runWarpscout(o.warpscoutPath, full); err != nil {
		return "", err
	}
	return pickFromReport(report, a.countries)
}

func runWarpscout(path string, args []string) (string, error) {
	cmd := exec.Command(path, args...)
	cmd.Stderr = os.Stderr // progress/TUI output goes to stderr, stdout stays clean
	out, err := cmd.Output()
	line := strings.TrimSpace(string(out))
	if err != nil {
		return line, err
	}
	// -best prints exactly one ip:port line; be tolerant of trailing noise
	for _, l := range strings.Split(line, "\n") {
		l = strings.TrimSpace(l)
		if isEndpoint(l) {
			return l, nil
		}
	}
	return line, fmt.Errorf("stdout не содержит ip:port (%q)", line)
}

var endpointRe = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$`)

func isEndpoint(s string) bool { return endpointRe.MatchString(s) }

// pickFromReport reads a warpscout text report and returns the best endpoint
// whose SEEN AS column matches the country filter (or the first row at all).
func pickFromReport(path string, countries []string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	want := map[string]bool{}
	for _, c := range countries {
		want[c] = true
	}
	var first, matched string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, ":") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || !isEndpoint(fields[0]) {
			continue
		}
		// row: ENDPOINT PING [TUNPING [LOSS [SPEED]]] SEEN_AS NODE ...
		country := ""
		for _, f := range fields[1:] {
			if looksLikeCountry(f) {
				country = strings.ToUpper(f)
				break
			}
		}
		if first == "" {
			first = fields[0]
		}
		if country != "" && (len(want) == 0 || want[country]) {
			matched = fields[0]
			break
		}
	}
	switch {
	case matched != "":
		return matched, nil
	case first != "":
		return first, nil
	default:
		return "", fmt.Errorf("в отчёте %s нет ни одного рабочего эндпоинта", path)
	}
}

func looksLikeCountry(f string) bool {
	if len(f) != 2 {
		return false
	}
	for _, r := range f {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}
