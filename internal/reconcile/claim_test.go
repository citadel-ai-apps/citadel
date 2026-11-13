package reconcile

import (
	"errors"
	"sync"
	"testing"

	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

func claimer(t *testing.T, maxUpgrades int) *Reconciler {

	t.Helper()
	cfg := config.Default()
	cfg.MaxConcurrentUpgrades = maxUpgrades
	return &Reconciler{cfg: cfg, claims: map[string]string{}}
}

// INV-6, in the window the other two layers cannot cover: the deploy gate reads
// the job table several steps before the instance lock is taken, so without a
// claim two requests can both pass it.
func TestClaimRefusesTheOtherAxis(t *testing.T) {

	r := claimer(t, 4)

	release, err := r.claim("demo", claimUpgrade)
	if err != nil {

		t.Fatal(err)
	}
	if _, err := r.claim("demo", claimDeploy); !errors.Is(err, ErrUpgradeActive) {

		t.Fatalf("a deploy during an upgrade returned %v, want ErrUpgradeActive", err)
	}
	if _, err := r.claim("demo", claimUpgrade); !errors.Is(err, ErrUpgradeActive) {

		t.Fatalf("a second upgrade returned %v, want ErrUpgradeActive", err)
	}
	// Another tenant is unaffected: the interlock is per tenant, not global.
	other, err := r.claim("second", claimDeploy)
	if err != nil {

		t.Fatalf("a second tenant was blocked by the first: %v", err)
	}
	other()

	release()
	release2, err := r.claim("demo", claimDeploy)
	if err != nil {

		t.Fatalf("the claim was not released: %v", err)
	}
	if _, err := r.claim("demo", claimUpgrade); !errors.Is(err, ErrDeployActive) {

		t.Fatalf("an upgrade during a deploy returned %v, want ErrDeployActive", err)
	}
	release2()
}

// Each upgrade is an mkfs, a multi-gigabyte copy and two container boots. An
// EOL sweep that started twenty at once would take the host down in the name of
// keeping it current.
func TestClaimCapsConcurrentUpgrades(t *testing.T) {

	r := claimer(t, 2)

	a, err := r.claim("one", claimUpgrade)
	if err != nil {

		t.Fatal(err)
	}
	b, err := r.claim("two", claimUpgrade)
	if err != nil {

		t.Fatal(err)
	}
	if _, err := r.claim("three", claimUpgrade); !errors.Is(err, ErrTooManyUpgrades) {

		t.Fatalf("a third upgrade returned %v, want ErrTooManyUpgrades", err)
	}
	// A DEPLOY is not capped: the limit is about the cost of an upgrade, not a
	// general throttle, and blocking deploys would make an EOL sweep look like
	// an outage.
	d, err := r.claim("three", claimDeploy)
	if err != nil {

		t.Fatalf("a deploy hit the upgrade cap: %v", err)
	}
	d()

	a()
	c, err := r.claim("three", claimUpgrade)
	if err != nil {

		t.Fatalf("releasing one upgrade did not free a slot: %v", err)
	}
	c()
	b()
}

func TestClaimIsSafeUnderConcurrency(t *testing.T) {

	r := claimer(t, 100)
	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := 0

	for range 50 {

		wg.Add(1)
		go func() {

			defer wg.Done()
			release, err := r.claim("demo", claimUpgrade)
			if err != nil {

				return
			}
			mu.Lock()
			granted++
			mu.Unlock()
			release()
		}()
	}
	wg.Wait()
	if granted == 0 {

		t.Fatal("no goroutine ever got the claim")
	}
	if len(r.claims) != 0 {

		t.Fatalf("%d claims leaked", len(r.claims))
	}
	if r.upgrades != 0 {

		t.Fatalf("the upgrade counter is %d after every release", r.upgrades)
	}
}

// §12 keeps three or four minor lines, and hooks written for one are likelier
// to survive the next than the last. A tenant the PLATFORM is moving gets the
// smallest step that exists.
func TestNextTargetPicksTheSmallestStepUp(t *testing.T) {

	versions := versionSet(map[string]string{
		"0.22.55": "eol",
		"0.38.2":  "supported",
		"0.40.4":  "current",
		"0.41.0":  "deprecated",
	})
	if got := nextTarget("0.22.55", versions); got != "0.38.2" {

		t.Fatalf("next target from 0.22.55 is %q, want 0.38.2", got)
	}
	// A deprecated line is never a target: nobody is moved onto a version the
	// platform is already retiring.
	if got := nextTarget("0.40.4", versions); got != "" {

		t.Fatalf("next target from 0.40.4 is %q, want none", got)
	}
}

func versionSet(states map[string]string) []store.RuntimeVersion {

	out := make([]store.RuntimeVersion, 0, len(states))
	for v, s := range states {

		out = append(out, store.RuntimeVersion{Version: v, State: s})
	}
	return out
}
