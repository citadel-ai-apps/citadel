// Command pbsnap streams a consistent page image of one pb_data database to
// stdout. It ships inside pb-hardened and is run by the control plane with
// `docker exec`, so it reads from inside the tenant's gVisor sandbox, where its
// SQLite locks are coherent with PocketBase's (design.md INV-20). See
// internal/pbsnap.
//
// Usage: pbsnap <name>.db — a bare file name, resolved under /pb/pb_data.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/citadel-ai-apps/citadel/internal/pbsnap"
)

const dataDir = "/pb/pb_data"

func main() {

	if len(os.Args) != 2 {

		fmt.Fprintln(os.Stderr, "usage: pbsnap <name>.db")
		os.Exit(2)
	}
	name := os.Args[1]
	// A bare name only: the control plane decides which database, and the
	// helper never reads anything outside pb_data.
	if name != filepath.Base(name) || !strings.HasSuffix(name, ".db") || strings.HasPrefix(name, ".") {

		fmt.Fprintf(os.Stderr, "pbsnap: %q is not a database name in %s\n", name, dataDir)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := pbsnap.Write(ctx, filepath.Join(dataDir, name), os.Stdout); err != nil {

		fmt.Fprintln(os.Stderr, "pbsnap:", err)
		os.Exit(1)
	}
}
