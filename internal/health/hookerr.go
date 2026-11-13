package health

import (
	"strings"
)

// hookErrorMarkers are the substrings that mean a tenant's JSVM hooks did not
// load on this binary.
//
// A marker list rather than a parser, because PocketBase's hook-registration
// errors are goja runtime errors printed to stdout in whatever shape the
// throwing code produced. The list is tuned to the failure §12 exists to catch:
// hooks written against an older JSVM API booting on a newer binary, where the
// old namespaces (`daos`, `models`, `$app.dao`) and the old hook names are
// simply gone, so the file throws at registration time.
//
// Deliberately NOT matched: the bare words "error" and "warn", and the string
// "pb_hooks". A PocketBase instance logs plenty of the first two in normal
// operation, and the third appears in ordinary start-up lines. This list decides
// whether an upgrade is rolled back, so a marker that fires on a healthy boot
// would turn every upgrade into a rollback.
var hookErrorMarkers = []string{
	"failed to register",
	"failed to execute",
	"ReferenceError",
	"TypeError",
	"SyntaxError",
	"is not defined",
	"is not a function",
	"daos is not",
	"$app.dao",
}

// maxHookErrors caps what is carried into a report. A hook file throwing in a
// loop can produce thousands of identical lines, and a tenant needs the first
// few, not the transcript.
const maxHookErrors = 20

// HookErrors picks the hook-registration failures out of an instance's log.
//
// These do not appear in the probe's report: the probe sees HTTP responses, and
// a PocketBase that failed to register a hook still serves. The evidence is on
// the instance's own stdout, which is why a rehearsal pairs the probe report
// with the rehearsal container's log — and why this exists rather than the
// rehearsal simply reporting "smoke request 3 returned 404".
func HookErrors(logs string) []string {

	var out []string
	seen := map[string]bool{}
	for line := range strings.SplitSeq(logs, "\n") {

		line = strings.TrimSpace(line)
		if line == "" {

			continue
		}
		if !hasMarker(line) {

			continue
		}
		if seen[line] {

			continue
		}
		seen[line] = true
		out = append(out, line)
		if len(out) == maxHookErrors {

			break
		}
	}
	return out
}

func hasMarker(line string) bool {

	for _, m := range hookErrorMarkers {

		if strings.Contains(line, m) {

			return true
		}
	}
	return false
}
