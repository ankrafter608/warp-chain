package main

import (
	"encoding/json"
	"os"
	"time"
)

// state caches everything expensive or network-bound so subsequent runs skip
// straight to config generation.
type state struct {
	Version      int               `json:"version"`
	GeneratedAt  string            `json:"generated_at,omitempty"`
	AccountIDs   map[string]string `json:"account_ids,omitempty"`
	Reserved     map[string]string `json:"reserved"` // device -> "n1, n2, n3"
	BaseEndpoint string            `json:"base_endpoint,omitempty"`
	ExitEndpoint string            `json:"exit_endpoint,omitempty"`
	BaseNode     string            `json:"base_node,omitempty"`
	ExitCountry  string            `json:"exit_country,omitempty"`
}

func loadState(path string) (*state, error) {
	st := &state{Version: 1}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, st); err != nil {
		// corrupt cache is not fatal — regenerate it
		return &state{Version: 1}, nil
	}
	if st.Reserved == nil {
		st.Reserved = map[string]string{}
	}
	return st, nil
}

func saveState(path string, st *state) error {
	st.GeneratedAt = time.Now().Format(time.RFC3339)
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
