// Package logcollect writes tenant container output to the host (design §15).
//
// Logs never leave a container through a tenant-controlled channel. PocketBase
// writes request and error logs into its auxiliary database inside pb_data and
// its diagnostics to stdout/stderr; this package follows the latter through the
// driver and lands it under <pb_root>/logs/<tenant>/, where the portal serves it
// read-only.
//
// Why on disk at all, when Docker already keeps a log: a deploy DESTROYS and
// recreates the container (design.md §8.3), so the output that explains
// why the previous release failed is gone at exactly the moment someone wants to
// read it. A file on the host outlives the container that wrote it, which is the
// whole point.
package logcollect

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/driver"
)

// FileName is the live log within a tenant's log directory.
const FileName = "app.log"

// Driver is the slice of the container driver this package needs.
type Driver interface {
	Logs(ctx context.Context, h driver.Handle, opts driver.LogOpts) (io.ReadCloser, error)
}

// Collector owns one follower goroutine per running tenant.
type Collector struct {
	cfg config.Config
	drv Driver
	log *slog.Logger

	mu        sync.Mutex
	followers map[string]*follower
}

type follower struct {
	cancel context.CancelFunc
	done   chan struct{}
	// container is the name being followed. A recreate keeps the name, so it is
	// the stream that ends rather than the identity that changes — the follower
	// reconnects on its own.
	container string
}

// New returns a Collector.
func New(cfg config.Config, drv Driver, log *slog.Logger) *Collector {

	return &Collector{cfg: cfg, drv: drv, log: log, followers: map[string]*follower{}}
}

// Ensure starts following a tenant's container if it is not already.
//
// Idempotent and cheap, so the reconciler can call it on every tick for every
// running tenant without tracking state of its own.
func (c *Collector) Ensure(ctx context.Context, tenantID, containerName string) error {

	c.mu.Lock()
	defer c.mu.Unlock()

	if f, ok := c.followers[tenantID]; ok && f.container == containerName {

		return nil
	}
	c.stopLocked(tenantID)

	dir := c.cfg.TenantLogDir(tenantID)
	if err := os.MkdirAll(dir, 0o750); err != nil {

		return fmt.Errorf("logcollect: mkdir %s: %w", dir, err)
	}

	fctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	f := &follower{cancel: cancel, done: make(chan struct{}), container: containerName}
	c.followers[tenantID] = f
	go c.follow(fctx, f, tenantID, containerName)
	return nil
}

// Stop ends a tenant's follower, on teardown or when the tenant stops.
func (c *Collector) Stop(tenantID string) {

	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopLocked(tenantID)
}

func (c *Collector) stopLocked(tenantID string) {

	f, ok := c.followers[tenantID]
	if !ok {

		return
	}
	f.cancel()
	delete(c.followers, tenantID)
}

// Close stops every follower.
func (c *Collector) Close() {

	c.mu.Lock()
	defer c.mu.Unlock()
	for id := range c.followers {

		c.stopLocked(id)
	}
}

// follow reconnects until cancelled.
//
// The stream ends every time the container stops, and the reconciler restarts
// containers by design (§8.3), so ending is the normal case and not an error.
// The retry delay exists so a container in a crash loop does not become a
// reconnect loop against the daemon.
func (c *Collector) follow(ctx context.Context, f *follower, tenantID, containerName string) {

	defer close(f.done)

	for ctx.Err() == nil {

		if err := c.stream(ctx, tenantID, containerName); err != nil && ctx.Err() == nil {

			c.log.Debug("tenant log stream ended", "tenant", tenantID, "err", err)
		}
		select {

		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// stream copies one connection's worth of output into the tenant's file.
//
// It starts from `Since: now` rather than from the beginning: the alternative
// re-copies the container's whole history into the file on every reconnect, and
// a container that restarts every few seconds then multiplies its own log.
func (c *Collector) stream(ctx context.Context, tenantID, containerName string) error {

	rc, err := c.drv.Logs(ctx, driver.Handle{TenantID: tenantID, Name: containerName},
		driver.LogOpts{Follow: true, Since: time.Now()})
	if err != nil {

		return err
	}
	defer rc.Close()

	path := filepath.Join(c.cfg.TenantLogDir(tenantID), FileName)
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {

		return fmt.Errorf("logcollect: open %s: %w", path, err)
	}
	defer fh.Close()

	return demux(ctx, rc, fh, func() error {

		// Checked as the file grows rather than on a timer, so the bound holds
		// against a hook that writes faster than any tick.
		rotated, err := Rotate(path, c.cfg.LogMaxBytes, c.cfg.LogKeep)
		if err != nil {

			return err
		}
		if !rotated {

			return nil
		}
		// The handle now points at the rotated inode. Reopen so the writes land
		// in the new file.
		next, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {

			return err
		}
		old := fh
		fh = next
		return old.Close()
	})
}

// demux strips Docker's 8-byte stream framing and writes the payload.
//
// A non-TTY container's log stream interleaves stdout and stderr with a header
// per frame: [stream, 0, 0, 0, len(uint32 BE)]. Writing it raw puts those bytes
// into the file, where they show up as control characters in the middle of a
// stack trace.
func demux(ctx context.Context, src io.Reader, dst io.Writer, afterWrite func() error) error {

	var header [8]byte
	for {

		if ctx.Err() != nil {

			return ctx.Err()
		}
		if _, err := io.ReadFull(src, header[:]); err != nil {

			if err == io.EOF || err == io.ErrUnexpectedEOF {

				return nil
			}
			return err
		}
		n := binary.BigEndian.Uint32(header[4:])
		if n == 0 {

			continue
		}
		if _, err := io.CopyN(dst, src, int64(n)); err != nil {

			return err
		}
		if afterWrite != nil {

			if err := afterWrite(); err != nil {

				return err
			}
		}
	}
}

// Tail returns the last `limit` bytes of a tenant's collected log.
//
// The portal reads this before falling back to the live container stream, so
// the output of a release that failed and was rolled back is still readable
// after the container that produced it is gone.
func (c *Collector) Tail(tenantID string, limit int64) ([]byte, error) {

	path := filepath.Join(c.cfg.TenantLogDir(tenantID), FileName)
	fh, err := os.Open(path)
	if err != nil {

		return nil, err
	}
	defer fh.Close()

	info, err := fh.Stat()
	if err != nil {

		return nil, err
	}
	if info.Size() > limit {

		if _, err := fh.Seek(info.Size()-limit, 0); err != nil {

			return nil, err
		}
	}
	return io.ReadAll(fh)
}
