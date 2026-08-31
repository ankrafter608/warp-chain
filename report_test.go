package main

import (
	"os"
	"path/filepath"
	"testing"
)

// mirrors warpscout's reportRowFmt output, including sections that must NOT
// become candidates (headers, torn-down rows, node picks)
const testReport = `# WARP endpoints: 3 working / 40 probed
# sorted by ping to the endpoint
# ENDPOINT PING = ICMP ping to the endpoint address from this host, no tunnel involved
# SEEN AS = region external services see through the tunnel
# NODE / NODE LOCATION = Cloudflare WARP edge node the tunnel landed on, and where it sits

162.159.192.61:2408     12ms         FI         HEL    Helsinki, Finland
162.159.192.54:2408     15ms         SE         ARN    Stockholm, Sweden
162.159.193.10:2408     21ms         DE         FRA    Frankfurt, Germany

# 1 torn down (handshake ok, data flowed, then cut and never recovered)
162.159.192.99:2408     9ms          FI         HEL    Helsinki, Finland

# Node picks
HEL     162.159.192.61:2408    12ms         FI         Helsinki, Finland
`

func TestParseReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.txt")
	if err := os.WriteFile(path, []byte(testReport), 0644); err != nil {
		t.Fatal(err)
	}
	cands, err := parseReport(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 3 {
		t.Fatalf("want 3 candidates, got %d: %+v", len(cands), cands)
	}
	want := []epCandidate{
		{"162.159.192.61:2408", "12ms", "FI", "HEL", "Helsinki, Finland"},
		{"162.159.192.54:2408", "15ms", "SE", "ARN", "Stockholm, Sweden"},
		{"162.159.193.10:2408", "21ms", "DE", "FRA", "Frankfurt, Germany"},
	}
	for i, w := range want {
		if cands[i] != w {
			t.Errorf("row %d: want %+v, got %+v", i, w, cands[i])
		}
	}
	if ep, _ := pickFromReport(path, nil); ep != want[0].endpoint {
		t.Errorf("pickFromReport: want %s, got %s", want[0].endpoint, ep)
	}
	if ep, _ := pickFromReport(path, []string{"SE"}); ep != want[1].endpoint {
		t.Errorf("pickFromReport(SE): want %s, got %s", want[1].endpoint, ep)
	}
}

// TestParseRealReport parses a real warpscout report when one is provided:
//
//	WARPCHAIN_TEST_REPORT=/tmp/warpchain-real-report.txt go test -run Real -v
func TestParseRealReport(t *testing.T) {
	p := os.Getenv("WARPCHAIN_TEST_REPORT")
	if p == "" {
		t.Skip("WARPCHAIN_TEST_REPORT not set")
	}
	cands, err := parseReport(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) == 0 {
		t.Fatal("no candidates parsed from real report")
	}
	first := cands[0]
	if !isEndpoint(first.endpoint) {
		t.Errorf("first candidate endpoint malformed: %q", first.endpoint)
	}
	if first.country == "" || first.node == "" {
		t.Errorf("first candidate missing country/node: %+v", first)
	}
	t.Logf("parsed %d candidates; best: %s ping=%s country=%s node=%s location=%q",
		len(cands), first.endpoint, first.ping, first.country, first.node, first.location)
}

// TestScanCandidatesReal runs a real phase-1 scan through scanCandidates,
// the path the interactive wizard uses. Regression for the bug where a
// successful full scan was rejected because its stdout holds summary tables
// instead of an ip:port line.
//
//	WARPCHAIN_TEST_SCAN=1 go test -run ScanCandidatesReal -v
func TestScanCandidatesReal(t *testing.T) {
	if os.Getenv("WARPCHAIN_TEST_SCAN") == "" {
		t.Skip("WARPCHAIN_TEST_SCAN not set")
	}
	if _, err := os.Stat(filepath.Join("data", "warpscout.exe")); err != nil {
		t.Skip("no local warpscout in data/")
	}
	o := options{
		warpscoutPath: filepath.Join("data", "warpscout.exe"),
		accountPath:   filepath.Join("data", "warpscout-account.json"),
		dataDir:       "data",
	}
	cands, best, err := scanCandidates(o, scanArgs{
		countries: []string{"FI", "SE", "DE"}, excludeNode: "DME,LED",
		timeout: 5, phase: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !isEndpoint(best) {
		t.Fatalf("best endpoint malformed: %q", best)
	}
	if len(cands) == 0 {
		t.Fatal("no candidates")
	}
	t.Logf("scan ok: %d candidates, best %s", len(cands), best)
}
