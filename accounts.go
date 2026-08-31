package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// account mirrors warpscout-account.json (see warpscout register.go).
type account struct {
	ID            string   `json:"id"`
	Token         string   `json:"token"`
	PrivateKey    string   `json:"private_key"`
	PeerPublicKey string   `json:"peer_public_key"`
	IPv4          string   `json:"ipv4,omitempty"`
	IPv6          string   `json:"ipv6,omitempty"`
	Outer         *account `json:"outer,omitempty"`
}

func loadAccount(path string) (account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return account{}, err
	}
	var a account
	if err := json.Unmarshal(data, &a); err != nil {
		return account{}, fmt.Errorf("%s: %v", path, err)
	}
	if a.PrivateKey == "" || a.PeerPublicKey == "" {
		return account{}, fmt.Errorf("%s: неполный аккаунт", path)
	}
	return a, nil
}

// warpscoutRegister delegates account creation to warpscout itself: it knows the
// registration fallbacks (relay / proxy / through a tunnel) that work from RU.
func warpscoutRegister(o options) error {
	cmd := exec.Command(o.warpscoutPath, "register", "-a", o.accountPath, "-plain")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("warpscout register: %w", err)
	}
	return nil
}

// --- Reserved (client_id) ---------------------------------------------------
//
// WARP's client_id travels in the WireGuard "reserved" field and is what keeps
// upload alive through the exit tunnel. warpscout doesn't persist it, so we ask
// the account API for config.client_id ourselves. api.cloudflareclient.com is
// often unreachable from RU, so requests go through warpscout's own relay first
// (edge-client-api.vercel.app), then direct.

const (
	relayTimeout    = 45 * time.Second
	directTimeout   = 15 * time.Second
	apiUserAgent    = "okhttp/3.12.1"
	apiClientVer    = "a-6.11-2223"
	relayDefaultURL = "https://edge-client-api.vercel.app"
	apiDirectURL    = "https://api.cloudflareclient.com"
	apiRegPath      = "/v0a4005/reg"
)

type regDetail struct {
	ID     string `json:"id"`
	Config struct {
		ClientID string `json:"client_id"`
	} `json:"config"`
}

func fetchReserved(relay, id, token string) (string, string, error) {
	relay = strings.TrimSpace(strings.ToLower(relay))
	var attempts []struct {
		label string
		base  string
	}
	if relay != "" && relay != "direct" && relay != "none" {
		attempts = append(attempts, struct{ label, base string }{"relay", strings.TrimSuffix(relay, "/")})
	}
	attempts = append(attempts, struct{ label, base string }{"direct", apiDirectURL})

	var lastErr error
	for _, a := range attempts {
		res, err := fetchReservedFrom(a.base, id, token)
		if err == nil {
			return res, a.label, nil
		}
		fmt.Printf("  %s: %v\n", a.label, err)
		lastErr = err
	}
	return "", "", lastErr
}

// dnsDialContext dials like the default transport, but if the system resolver
// fails it re-resolves through public DNS servers. Needed on Android: with
// CGO disabled Go's pure resolver looks for /etc/resolv.conf, which Android
// doesn't have, and falls back to [::1]:53 ("connection refused").
func dnsDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, network, addr)
	if err == nil {
		return conn, nil
	}
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil || net.ParseIP(host) != nil {
		return nil, err // not a DNS name — retrying won't help
	}
	public := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var lastErr error
			for _, ns := range []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"} {
				c, e := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, ns)
				if e == nil {
					return c, nil
				}
				lastErr = e
			}
			return nil, lastErr
		},
	}
	retry := net.Dialer{Timeout: 15 * time.Second, Resolver: public}
	return retry.DialContext(ctx, network, addr)
}

var apiTransport = &http.Transport{
	DialContext:         dnsDialContext,
	TLSHandshakeTimeout: 10 * time.Second,
	ForceAttemptHTTP2:   true,
}

func fetchReservedFrom(base, id, token string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, base+apiRegPath+"/"+id, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", apiUserAgent)
	req.Header.Set("CF-Client-Version", apiClientVer)
	// the relay runs on fetch(), which gunzips but forwards Content-Encoding
	req.Header.Set("Accept-Encoding", "identity")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	timeout := relayTimeout
	if base == apiDirectURL {
		timeout = directTimeout
	}
	ctx, cancel := context.WithTimeout(req.Context(), timeout)
	defer cancel()
	req = req.WithContext(ctx)

	client := &http.Client{
		Timeout:   relayTimeout,
		Transport: apiTransport,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var d regDetail
	if err := json.Unmarshal(body, &d); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if d.Config.ClientID == "" {
		return "", errors.New("в ответе нет config.client_id")
	}
	raw, err := base64.StdEncoding.DecodeString(d.Config.ClientID)
	if err != nil {
		return "", fmt.Errorf("decode client_id: %w", err)
	}
	if len(raw) == 0 || len(raw) > 4 {
		return "", fmt.Errorf("client_id неожиданной длины: %d", len(raw))
	}
	return formatReserved(raw), nil
}

func formatReserved(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, ", ")
}

func reservedList(s string) []int {
	var out []int
	for _, p := range strings.Split(strings.ReplaceAll(s, " ", ""), ",") {
		if p == "" {
			continue
		}
		var v int
		fmt.Sscanf(p, "%d", &v)
		out = append(out, v)
	}
	return out
}
