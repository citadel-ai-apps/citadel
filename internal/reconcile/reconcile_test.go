package reconcile

import (
	"strings"
	"testing"
	"time"
)

// TestBackoffLadderClimbsThenGivesUp is the §8.3 ladder: 1s, 5s, 30s, 2m, then
// mark failed. A hook with an infinite loop must not become a restart storm.
func TestBackoffLadderClimbsThenGivesUp(t *testing.T) {

	now := time.Now()

	if ready, _ := backoffReady(0, nil, now); !ready {

		t.Fatal("the first attempt was delayed")
	}

	for attempt, wait := range backoffLadder {

		last := now.Add(-wait).Add(-time.Millisecond)
		if ready, _ := backoffReady(attempt+1, &last, now); !ready {

			t.Errorf("attempt %d was not ready after waiting %s", attempt+1, wait)
		}
		tooSoon := now.Add(-wait / 2)
		ready, remaining := backoffReady(attempt+1, &tooSoon, now)
		if ready {

			t.Errorf("attempt %d fired after only half its %s backoff", attempt+1, wait)
		}
		if remaining <= 0 {

			t.Errorf("attempt %d reported no remaining wait", attempt+1)
		}
	}

	// Past the last rung: never ready and no remaining wait, which is how the
	// caller distinguishes "wait longer" from "give up and mark failed".
	last := now.Add(-time.Hour)
	ready, remaining := backoffReady(MaxRestarts, &last, now)
	if ready {

		t.Error("the ladder handed out an attempt past its last rung")
	}
	if remaining != 0 {

		t.Errorf("exhausted ladder reported a remaining wait of %s, want 0", remaining)
	}
}

func TestBackoffSurvivesAMissingTimestamp(t *testing.T) {

	// A restart count with no timestamp can only come from a partially written
	// row; retrying immediately is safer than never retrying.
	if ready, _ := backoffReady(2, nil, time.Now()); !ready {

		t.Fatal("a count with no timestamp blocked forever")
	}
}

func TestValidateSlug(t *testing.T) {

	valid := []string{"demo", "up-demo", "a", "a1", "0123456789"}
	for _, s := range valid {

		if err := ValidateSlug(s); err != nil {

			t.Errorf("ValidateSlug(%q): %v", s, err)
		}
	}

	invalid := map[string]string{
		// 11 characters: br-t-<slug> would be 16, over IFNAMSIZ. The bridge
		// would fail to create — and a truncated one would stop matching the
		// br-t-+ INPUT wildcard, silently dropping the tenant's host protection.
		"elevenchars": "IFNAMSIZ",
		"Demo":        "lowercase",
		"de_mo":       "lowercase",
		"-demo":       "lowercase",
		"demo-":       "lowercase",
		"":            "lowercase",
		"de mo":       "lowercase",
		// The shape of an upgrade rehearsal's network slug; a rehearsal
		// teardown removes that network by name.
		"rh0a1b2c3d": "reserved",
		"rh":         "reserved",
	}
	for s, want := range invalid {

		err := ValidateSlug(s)
		if err == nil {

			t.Errorf("ValidateSlug(%q) succeeded", s)
			continue
		}
		if !strings.Contains(err.Error(), want) {

			t.Errorf("ValidateSlug(%q) = %v, want a message mentioning %q", s, err, want)
		}
	}
}

func TestDriftBoardKeepsTheFirstDetectionTime(t *testing.T) {

	b := newDriftBoard()
	first := time.Now().Add(-time.Hour).UTC()
	b.Record(Drift{Kind: DriftDigest, TenantID: "demo", Detail: "x", DetectedAt: first})
	b.Record(Drift{Kind: DriftDigest, TenantID: "demo", Detail: "x"})

	got := b.List()
	if len(got) != 1 {

		t.Fatalf("board holds %d entries, want 1", len(got))
	}
	// "This has been wrong since 03:14" is the useful fact during an incident,
	// not "it was still wrong five seconds ago".
	if !got[0].DetectedAt.Equal(first) {

		t.Fatalf("detection time moved to %s, want %s", got[0].DetectedAt, first)
	}
}

func TestDriftBoardSortsSecurityItemsFirst(t *testing.T) {

	b := newDriftBoard()
	b.Record(Drift{Kind: DriftMissingRoute, TenantID: "a", Detail: "route", DetectedAt: time.Now()})
	b.Record(Drift{Kind: DriftUnbackedRule, TenantID: "b", Detail: "rule",
		Security: true, DetectedAt: time.Now().Add(time.Minute)})

	got := b.List()
	if len(got) != 2 {

		t.Fatalf("board holds %d entries, want 2", len(got))
	}
	// enforcement_without_grant pages and is never auto-remediated (§15), so it
	// must not be buried under operational noise.
	if !got[0].Security {

		t.Fatalf("security drift is not first: %+v", got)
	}
}

func TestDriftBoardClearScopesByKindAndTenant(t *testing.T) {

	b := newDriftBoard()
	b.Record(Drift{Kind: DriftDigest, TenantID: "a", Detail: "x"})
	b.Record(Drift{Kind: DriftDigest, TenantID: "b", Detail: "x"})
	b.Record(Drift{Kind: DriftMissingRoute, TenantID: "a", Detail: "y"})

	b.Clear(DriftDigest, "a")
	got := b.List()
	if len(got) != 2 {

		t.Fatalf("after Clear the board holds %d entries, want 2: %+v", len(got), got)
	}
	for _, d := range got {

		if d.Kind == DriftDigest && d.TenantID == "a" {

			t.Fatal("Clear did not remove the targeted entry")
		}
	}

	b.ClearTenant("a")
	for _, d := range b.List() {

		if d.TenantID == "a" {

			t.Fatalf("ClearTenant left %+v", d)
		}
	}
}
