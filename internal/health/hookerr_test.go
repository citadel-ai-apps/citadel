package health

import (
	"strings"
	"testing"
)

// A real 0.22-era hook file booting on a current binary: onAfterBootstrap is
// gone, so the call throws at registration time and the rest of the file never
// runs. This is the failure §12's rehearsal exists to catch, and the probe
// cannot see it — PocketBase keeps serving HTTP with no hooks registered.
const legacyOnCurrent = `
2026-09-22 10:14:02.101 INFO  Server started at http://0.0.0.0:8090
2026-09-22 10:14:02.104 ERROR failed to execute pb_hooks/main.pb.js: ReferenceError: onAfterBootstrap is not defined
	at main.pb.js:17:1
2026-09-22 10:14:02.110 INFO  GET /api/health 200 0.4ms
`

func TestHookErrorsFindsARegistrationFailure(t *testing.T) {

	got := HookErrors(legacyOnCurrent)
	if len(got) == 0 {

		t.Fatal("a ReferenceError from a hook file was not reported")
	}
	if !strings.Contains(got[0], "onAfterBootstrap is not defined") {

		t.Fatalf("first line is %q, want the error itself", got[0])
	}
}

// A healthy instance logs plenty of ordinary traffic. A report that cries wolf
// on every boot teaches the tenant to ignore it, which costs more than it saves.
func TestHookErrorsIgnoresOrdinaryLogs(t *testing.T) {

	const clean = `
2026-09-22 10:14:02.101 INFO  Server started at http://0.0.0.0:8090
2026-09-22 10:14:02.110 INFO  GET /api/health 200 0.4ms
2026-09-22 10:14:03.000 INFO  POST /api/collections/notes/records 400 1.2ms
2026-09-22 10:14:04.000 WARN  slow query took 512ms
`
	if got := HookErrors(clean); len(got) != 0 {

		t.Fatalf("a clean log produced %v", got)
	}
}

func TestHookErrorsDeduplicatesAndCaps(t *testing.T) {

	line := "ERROR failed to register hook: TypeError: $app.dao is not a function"
	var b strings.Builder
	for range 500 {

		b.WriteString(line + "\n")
	}
	got := HookErrors(b.String())
	if len(got) != 1 {

		t.Fatalf("a repeated line produced %d entries, want 1", len(got))
	}

	b.Reset()
	for i := range maxHookErrors + 10 {

		b.WriteString("ERROR ReferenceError: symbol" + string(rune('a'+i%26)) + string(rune('0'+i/26)) + " is not defined\n")
	}
	if got := HookErrors(b.String()); len(got) > maxHookErrors {

		t.Fatalf("report carries %d lines, past the cap of %d", len(got), maxHookErrors)
	}
}
