//go:build !linux

package hostfs

import "path/filepath"

// fsKind is a no-op off Linux: the control plane only runs on Linux, and the
// development build on a Mac never holds tenant data.
func fsKind(string) (string, bool, error) { return "", false, nil }

func parentDir(dir string) string { return filepath.Dir(dir) }
