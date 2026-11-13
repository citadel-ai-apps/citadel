package proxyctl

import (
	"strconv"
	"strings"
)

// DefaultBodyCap is the fallback when a tenant's cap cannot be parsed.
const DefaultBodyCap int64 = 32 << 20

// parseSize converts a human size like "32MB" into bytes for Caddy's
// request_body max_size.
//
// Caddy accepts the string form too, but converting here means an unparseable
// value fails closed at the default rather than being handed to the proxy,
// where a rejected config would take the whole edge's reload with it.
func parseSize(s string) int64 {

	t := strings.TrimSpace(strings.ToUpper(s))
	mult := int64(1)
	switch {

	case strings.HasSuffix(t, "GB"), strings.HasSuffix(t, "GIB"):
		mult, t = 1<<30, strings.TrimSuffix(strings.TrimSuffix(t, "GIB"), "GB")
	case strings.HasSuffix(t, "MB"), strings.HasSuffix(t, "MIB"):
		mult, t = 1<<20, strings.TrimSuffix(strings.TrimSuffix(t, "MIB"), "MB")
	case strings.HasSuffix(t, "KB"), strings.HasSuffix(t, "KIB"):
		mult, t = 1<<10, strings.TrimSuffix(strings.TrimSuffix(t, "KIB"), "KB")
	case strings.HasSuffix(t, "B"):
		t = strings.TrimSuffix(t, "B")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
	if err != nil || n <= 0 {

		return DefaultBodyCap
	}
	return n * mult
}
