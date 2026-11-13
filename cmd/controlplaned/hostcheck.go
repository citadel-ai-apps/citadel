package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
)

// daemonJSON is where dockerd reads its configuration.
const daemonJSON = "/etc/docker/daemon.json"

// dockerdForwardNoDrop reports whether dockerd is configured with
// --ip-forward-no-drop, in daemon.json or on the running daemon's command
// line, and where it was found. Docker's info endpoint does not expose it.
func dockerdForwardNoDrop() (bool, string) {

	if b, err := os.ReadFile(daemonJSON); err == nil {

		var cfg map[string]any
		if json.Unmarshal(b, &cfg) == nil {

			if v, ok := cfg["ip-forward-no-drop"].(bool); ok && v {

				return true, daemonJSON
			}
		}
	}
	procs, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, comm := range procs {

		name, err := os.ReadFile(comm)
		if err != nil || string(bytes.TrimSpace(name)) != "dockerd" {

			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(filepath.Dir(comm), "cmdline"))
		if err != nil {

			continue
		}
		for _, arg := range bytes.Split(cmdline, []byte{0}) {

			if string(arg) == "--ip-forward-no-drop" || string(arg) == "--ip-forward-no-drop=true" {

				return true, "dockerd command line"
			}
		}
	}
	return false, ""
}
