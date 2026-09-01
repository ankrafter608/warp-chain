package main

import (
	"os"
	"os/exec"
	"runtime"
)

// copyToClipboard best-effort copies a text file's contents so the NekoBox
// "Add profile from clipboard" step needs no editor: clip.exe on Windows,
// termux-clipboard-set (Termux:API) on Android/Linux. Returns false when no
// helper is available or the copy failed — the caller just stays silent.
func copyToClipboard(path string) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		exe, err := exec.LookPath("clip")
		if err != nil {
			return false
		}
		cmd = exec.Command(exe)
	} else {
		exe, err := exec.LookPath("termux-clipboard-set")
		if err != nil {
			return false
		}
		cmd = exec.Command(exe)
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	cmd.Stdin = f
	return cmd.Run() == nil
}
