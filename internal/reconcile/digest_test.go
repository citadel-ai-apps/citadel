package reconcile

import (
	"testing"

	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// TestDigestGuardCoversEveryContainerState is INV-11 beyond the running case:
// a stopped container, or none at all, must not be (re)created on a digest
// other than the one pb_data was last served by.
func TestDigestGuardCoversEveryContainerState(t *testing.T) {

	const old, desired = "reg/pb@sha256:old", "reg/pb@sha256:new"

	cases := []struct {
		name  string
		st    driver.Status
		in    store.Instance
		drift bool
	}{
		{"running on the desired digest", driver.Status{Exists: true, Running: true, ImageDigest: desired}, store.Instance{RunningDigest: desired}, false},
		{"running on another digest", driver.Status{Exists: true, Running: true, ImageDigest: old}, store.Instance{RunningDigest: old}, true},
		{"stopped on another digest", driver.Status{Exists: true, ImageDigest: old}, store.Instance{RunningDigest: old}, true},
		{"stopped on the desired digest", driver.Status{Exists: true, ImageDigest: desired}, store.Instance{RunningDigest: old}, false},
		{"no container, last ran another digest", driver.Status{}, store.Instance{RunningDigest: old}, true},
		{"no container, last ran the desired digest", driver.Status{}, store.Instance{RunningDigest: desired}, false},
		{"fresh provision: nothing known", driver.Status{}, store.Instance{}, false},
	}
	for _, c := range cases {

		if _, got := digestDrifted(c.st, c.in, desired); got != c.drift {

			t.Errorf("%s: drift=%v, want %v", c.name, got, c.drift)
		}
	}
}
