package main

import (
	"encoding/json"
	"testing"
)

// TestProfilesConfigShape guards the "add both profiles in one paste" import:
// the file must contain ONLY the endpoints key — any dns/route/inbounds key
// would make NekoBox's importer treat it as a full config (and hit its
// server:null bug) instead of creating two profiles.
func TestProfilesConfigShape(t *testing.T) {
	o := options{jc: 6, jmin: 21, jmax: 56, mtuBase: 1280, mtuExit: 1200, i1: "x"}
	acc := account{ID: "m", PrivateKey: "priv==", PeerPublicKey: "pub==",
		Outer: &account{ID: "o", PrivateKey: "opriv==", PeerPublicKey: "opub=="}}
	cfg := buildProfilesConfig(o, acc, "1.2.3.4:2408", "5.6.7.8:2408", "1, 2, 3")

	if len(cfg) != 1 {
		t.Fatalf("хотим ровно один ключ endpoints, есть %d: %v", len(cfg), keys(cfg))
	}
	if _, ok := cfg["endpoints"]; !ok {
		t.Fatal("нет ключа endpoints")
	}
	eps, err := json.Marshal(cfg["endpoints"])
	if err != nil {
		t.Fatal(err)
	}
	var parsed []map[string]any
	if err := json.Unmarshal(eps, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 2 {
		t.Fatalf("хотим 2 эндпоинта, есть %d", len(parsed))
	}
	if parsed[0]["type"] != "awg" || parsed[1]["type"] != "wireguard" {
		t.Fatalf("порядок типов: %v, %v", parsed[0]["type"], parsed[1]["type"])
	}
	// the core has no "server" field in endpoint options — never emit one
	for i, ep := range parsed {
		if _, ok := ep["server"]; ok {
			t.Errorf("endpoints[%d]: лишнее поле server", i)
		}
	}
	// reserved must survive on the exit hop (critical for upload)
	wg := parsed[1]["peers"].([]any)[0].(map[string]any)
	if _, ok := wg["reserved"]; !ok {
		t.Error("у WARP-EXIT нет reserved")
	}
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
