package egressctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/logcollect"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// accessLog is the file Squid writes and this package reads. Read as a FILE on
// the host, not as a container log stream: the control plane then owns the
// cursor and the rotation, and a proxy restart does not lose the record of what
// it turned away.
const accessLog = "access.log"

// cursorName holds the byte offset already accounted for.
const cursorName = ".v2p-cursor"

// maxScanBytes bounds one tick's read. A hook hammering a denied host produces
// log lines faster than anything else in the system; the cap keeps a reconcile
// tick bounded and the remainder is picked up next tick.
const maxScanBytes = 4 << 20

type cursor struct {
	Offset int64 `json:"offset"`
	Size   int64 `json:"size"`
}

// CollectDenials reads new access-log lines and returns denials aggregated per
// (tenant, host, port).
//
// `byIP` maps an egress address onto a tenant id. An address the control plane
// does not recognise is reported separately rather than dropped: traffic on the
// egress network from something the database does not know about is the same
// class of signal as an unbacked firewall rule, not noise.
func (c *Controller) CollectDenials(byIP map[string]string) (denials []store.Denial, unknown []string, err error) {

	path := filepath.Join(c.cfg.EgressLogDir(), accessLog)
	// Opened beneath the log directory and never through a symlink out of it:
	// the proxy writes this directory, and the host reading a file the proxy
	// chose would be the host reading whatever it pointed at.
	f, _, err := hostfs.OpenRegularUnder(c.cfg.EgressLogDir(), accessLog)
	if err != nil {

		if errors.Is(err, fs.ErrNotExist) {

			return nil, nil, nil // the proxy has not written anything yet
		}
		return nil, nil, fmt.Errorf("egressctl: open %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {

		return nil, nil, err
	}
	cur := c.readCursor()
	if info.Size() < cur.Offset {

		// Rotated or truncated under us. Start again rather than seeking past
		// the end and reading nothing forever.
		cur = cursor{}
	}
	if _, err := f.Seek(cur.Offset, 0); err != nil {

		return nil, nil, err
	}

	buf := make([]byte, maxScanBytes)
	n, err := f.Read(buf)
	if err != nil && n == 0 {

		return nil, nil, nil
	}
	chunk := buf[:n]
	// Only whole lines: a partial trailing line is left for the next tick,
	// which is why the cursor advances by the consumed prefix and not by n.
	lastNL := strings.LastIndexByte(string(chunk), '\n')
	if lastNL < 0 {

		return nil, nil, nil
	}
	consumed := int64(lastNL + 1)

	agg := map[store.Denial]*store.Denial{}
	seenUnknown := map[string]bool{}
	for _, line := range strings.Split(string(chunk[:lastNL]), "\n") {

		d, srcIP, ok := parseDenial(line)
		if !ok {

			continue
		}
		tenantID, known := byIP[srcIP]
		if !known {

			if !seenUnknown[srcIP] {

				seenUnknown[srcIP] = true
				unknown = append(unknown, srcIP)
			}
			continue
		}
		d.TenantID = tenantID
		key := store.Denial{TenantID: d.TenantID, Host: d.Host, Port: d.Port}
		if existing, ok := agg[key]; ok {

			existing.Hits++
			if d.LastSeenAt.After(existing.LastSeenAt) {

				existing.LastSeenAt = d.LastSeenAt
			}
			continue
		}
		copied := d
		agg[key] = &copied
	}

	for _, d := range agg {

		denials = append(denials, *d)
	}
	c.writeCursor(cursor{Offset: cur.Offset + consumed, Size: info.Size()})
	return denials, unknown, nil
}

// parseDenial pulls one refusal out of a Squid access-log line in the default
// `squid` format:
//
//	<epoch.ms> <elapsed> <client> <result>/<status> <bytes> <method> <url> ...
//
// Three shapes count as a refusal, and they are not the same event:
//
//   - TCP_DENIED — the allowlist said no to the CONNECT target or the URL;
//   - NONE/TAG_NONE with a 403 — the same, before a peer was chosen;
//   - NONE_NONE — an ssl_bump terminate, i.e. the CONNECT target was allowed
//     and the ClientHello named something else. That one is the interesting
//     line in an incident, and it only exists because the SNI filter does.
func parseDenial(line string) (store.Denial, string, bool) {

	f := strings.Fields(line)
	if len(f) < 7 {

		return store.Denial{}, "", false
	}
	result, status, _ := strings.Cut(f[3], "/")
	denied := strings.HasPrefix(result, "TCP_DENIED") ||
		result == "NONE_NONE" ||
		((result == "NONE" || result == "TAG_NONE") && (status == "403" || status == "0" || status == "000"))
	if !denied {

		return store.Denial{}, "", false
	}

	host, port := splitTarget(f[6])
	if host == "" {

		return store.Denial{}, "", false
	}
	return store.Denial{
		Host:        host,
		Port:        port,
		Hits:        1,
		FirstSeenAt: parseEpoch(f[0]),
		LastSeenAt:  parseEpoch(f[0]),
	}, f[2], true
}

// splitTarget turns either `api.stripe.com:443` (CONNECT) or
// `http://api.stripe.com/x` (plain) into a host and a port.
func splitTarget(target string) (string, int) {

	port := 80
	if i := strings.Index(target, "://"); i >= 0 {

		if target[:i] == "https" {

			port = 443
		}
		target = target[i+3:]
	}
	if i := strings.IndexByte(target, '/'); i >= 0 {

		target = target[:i]
	}
	if h, p, ok := strings.Cut(target, ":"); ok {

		if n, err := strconv.Atoi(p); err == nil {

			return h, n
		}
		return h, port
	}
	return target, port
}

func parseEpoch(s string) time.Time {

	secs, frac, _ := strings.Cut(s, ".")
	n, err := strconv.ParseInt(secs, 10, 64)
	if err != nil {

		return time.Now().UTC()
	}
	ms, _ := strconv.ParseInt(frac, 10, 64)
	return time.Unix(n, ms*int64(time.Millisecond)).UTC()
}

func (c *Controller) cursorPath() string {

	return filepath.Join(c.cfg.EgressLogDir(), cursorName)
}

func (c *Controller) readCursor() cursor {

	f, _, err := hostfs.OpenRegularUnder(c.cfg.EgressLogDir(), cursorName)
	if err != nil {

		return cursor{}
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {

		return cursor{}
	}
	var cur cursor
	if err := json.Unmarshal(b, &cur); err != nil {

		return cursor{}
	}
	return cur
}

// writeCursor persists the offset. A failure here costs a re-count of one
// tick's denials after a restart, which inflates a hit counter and breaks
// nothing — so it is logged, not returned.
func (c *Controller) writeCursor(cur cursor) {

	b, err := json.Marshal(cur)
	if err != nil {

		return
	}
	if err := writeNoFollow(c.cursorPath(), b); err != nil {

		c.log.Warn("could not persist the egress log cursor; denials may be counted twice after a restart",
			"path", c.cursorPath(), "err", err)
	}
}

// RotateLogs keeps the proxy's own access log bounded.
func (c *Controller) RotateLogs(maxBytes int64, keep int) error {

	dir := c.cfg.EgressLogDir()
	for _, name := range []string{accessLog, "cache.log"} {

		rotated, err := logcollect.Rotate(filepath.Join(dir, name), maxBytes, keep)
		if err != nil {

			return err
		}
		if rotated && name == accessLog {

			// The cursor counts bytes in the live file, which just became a
			// different file.
			c.writeCursor(cursor{})
		}
	}
	return nil
}

// writeNoFollow replaces path with b without ever writing through a symlink.
//
// The cursor lives in a directory the proxy can write. os.WriteFile on a name
// the proxy had replaced with a symlink would have root overwrite the link's
// target; a fresh temporary file renamed over the name replaces the link
// itself.
func writeNoFollow(path string, b []byte) error {

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {

		return err
	}
	if _, err := tmp.Write(b); err != nil {

		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {

		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {

		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}
