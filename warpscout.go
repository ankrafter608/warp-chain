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

// pickEndpoint shows the working candidates and returns the user's choice.
// Empty answer keeps the scan's own best (first row, warpscout sorts by ping).
func pickEndpoint(cands []epCandidate, phase int, best string) (string, error) {
	const maxShow = 15
	show := cands
	if len(show) > maxShow {
		show = show[:maxShow]
	}
	fmt.Printf("\nРабочих эндпоинтов: %d. Лучшие %d:\n", len(cands), len(show))
	fmt.Printf("  %-3s %-23s %-8s %-8s %-6s %s\n", "#", "ЭНДПОИНТ", "PING", "ВИДЕН", "НОДА", "ЛОКАЦИЯ")
	for i, c := range show {
		fmt.Printf("  %-3d %-23s %-8s %-8s %-6s %s\n", i+1, c.endpoint, c.ping, c.country, c.node, c.location)
	}
	choice := prompt(fmt.Sprintf("Эндпоинт фазы %d (номер, Enter = лучший)", phase), "")
	if choice == "" {
		return best, nil
	}
	n, err := strconv.Atoi(choice)
	if err != nil || n < 1 || n > len(show) {
		fmt.Printf("  не понял %q — беру лучший (%s)\n", choice, best)
		return best, nil
	}
	return show[n-1].endpoint, nil
}

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

	report := o.reportPath(a.phase)
	full := append(append([]string{}, args...), "-o", report)
	if err := runWarpscoutFull(o.warpscoutPath, full); err != nil {
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

// runWarpscoutFull runs a full scan that writes its -o report. Unlike
// runWarpscout (which expects an ip:port line from -best), a full scan prints
// summary tables to stdout, so only the exit code matters here.
func runWarpscoutFull(path string, args []string) error {
	cmd := exec.Command(path, args...)
	cmd.Stdout = os.Stdout // summary tables double as progress feedback
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// --- scan + interactive pick -------------------------------------------------

// epCandidate is one working endpoint from a warpscout report.
type epCandidate struct {
	endpoint string // ip:port
	ping     string // raw ping column (e.g. "12ms"), may be "?"
	country  string // SEEN AS ISO code (FI, DE, ...)
	node     string // IATA colo code (HEL, ARN, ...)
	location string // human-readable node location
}

// reportRowRe parses one data row of a warpscout report (see reportRowFmt
// in warpscout's report.go):
//
//	ENDPOINT PING [TUNPING LOSS [SPEED]] SEEN_AS NODE LOCATION...
var reportRowRe = regexp.MustCompile(
	`^(\d{1,3}(?:\.\d{1,3}){3}:\d{1,5})\s+(\S+)` + // endpoint, ping
		`(?:\s+(\S+)\s+(\S+))?` + // optional tun ping, loss
		`(?:\s+(\S+))?` + // optional speed
		`\s+(\S+)\s+([A-Z]{3})\s+(.+)$`) // seen-as region, NODE, location

// parseReport reads a warpscout text report and returns all working endpoints
// in scan order (warpscout already sorts them best-first).
func parseReport(path string) ([]epCandidate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []epCandidate
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			// everything after the torn-down header is dead weight: handshake
			// ok, then cut mid-stream — never offer those as candidates
			if strings.Contains(line, "torn down") {
				break
			}
			continue
		}
		m := reportRowRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, epCandidate{
			endpoint: m[1],
			ping:     m[2],
			country:  strings.ToUpper(strings.TrimPrefix(m[6], "?")),
			node:     m[7],
			location: strings.TrimSpace(m[8]),
		})
	}
	return out, nil
}

// reportPath is where scanAndPick stores the phase's full report.
func (o options) reportPath(phase int) string {
	return filepath.Join(o.dataDir, fmt.Sprintf("warpscout-report-phase%d.txt", phase))
}

// scanAndPick runs a full scan into a report file, then — in the interactive
// wizard — lets the user choose the endpoint from the working candidates.
func scanAndPick(o options, a scanArgs) (string, error) {
	cands, best, err := scanCandidates(o, a)
	if err != nil {
		return "", err
	}
	// -plain or piped stdin: no questions, take the best
	if !o.interactive {
		return best, nil
	}
	return pickEndpoint(cands, a.phase, best)
}

// scanCandidates always runs the full report scan (never -best) so the wizard
// has the whole candidate list; returns candidates and the report's best row.
func scanCandidates(o options, a scanArgs) ([]epCandidate, string, error) {
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

	report := o.reportPath(a.phase)
	full := append(append([]string{}, args...), "-o", report)
	if err := runWarpscoutFull(o.warpscoutPath, full); err != nil {
		return nil, "", err
	}
	cands, err := parseReport(report)
	if err != nil {
		return nil, "", err
	}
	if len(cands) == 0 {
		return nil, "", fmt.Errorf("в отчёте %s нет ни одного рабочего эндпоинта", report)
	}
	return cands, cands[0].endpoint, nil
}

var endpointRe = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$`)

func isEndpoint(s string) bool { return endpointRe.MatchString(s) }

// pickFromReport returns the best endpoint from a report, preferring one whose
// SEEN AS country matches the filter. Non-interactive fallback of scanBest.
func pickFromReport(path string, countries []string) (string, error) {
	cands, err := parseReport(path)
	if err != nil {
		return "", err
	}
	want := map[string]bool{}
	for _, c := range countries {
		want[c] = true
	}
	for _, c := range cands {
		if len(want) == 0 || want[c.country] {
			return c.endpoint, nil
		}
	}
	if len(cands) > 0 {
		return cands[0].endpoint, nil
	}
	return "", fmt.Errorf("в отчёте %s нет ни одного рабочего эндпоинта", path)
}
