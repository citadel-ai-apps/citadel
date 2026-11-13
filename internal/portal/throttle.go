package portal

import (
	"context"
	"sync"
	"time"
)

// loginThrottle bounds password guessing at the portal's one unauthenticated
// form.
//
// Failures are counted per claimed principal and per source address over a
// sliding window, and a key over its budget is refused before any password is
// hashed. Both keys matter: per principal stops a slow guess against one
// account — `platform`, whose session is owner on every tenant, is the obvious
// target — and per address stops one client spraying every name. A refused
// attempt is neither hashed nor audited, so the throttle also bounds how fast
// failed logins can grow the append-only audit chain.
//
// In memory, deliberately: a restart forgets the counts, which costs an
// attacker one window and costs the platform no table that grows with every
// failed login.
type loginThrottle struct {
	mu       sync.Mutex
	now      func() time.Time
	window   time.Duration
	limits   map[string]int // key prefix -> failures allowed per window
	failures map[string][]time.Time
}

const (
	throttleWindow       = 15 * time.Minute
	failuresPerPrincipal = 10
	failuresPerAddress   = 50
	throttleMaxKeys      = 10000
)

func newLoginThrottle() *loginThrottle {

	return &loginThrottle{
		now:    time.Now,
		window: throttleWindow,
		limits: map[string]int{
			"principal": failuresPerPrincipal,
			"address":   failuresPerAddress,
		},
		failures: map[string][]time.Time{},
	}
}

type throttleKey struct{ kind, value string }

func (k throttleKey) String() string { return k.kind + ":" + k.value }

// allowed reports whether every key is still within its budget.
func (t *loginThrottle) allowed(keys ...throttleKey) bool {

	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range keys {

		if len(t.recent(k.String())) >= t.limits[k.kind] {

			return false
		}
	}
	return true
}

// fail records a failed attempt against every key.
func (t *loginThrottle) fail(keys ...throttleKey) {

	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.failures) >= throttleMaxKeys {

		t.sweep()
	}
	now := t.now()
	for _, k := range keys {

		t.failures[k.String()] = append(t.recent(k.String()), now)
	}
}

// succeed clears a key, so an owner who mistyped twice is not carrying those
// failures into the next window.
func (t *loginThrottle) succeed(k throttleKey) {

	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, k.String())
}

// recent returns the key's failures inside the window. Caller holds mu.
func (t *loginThrottle) recent(key string) []time.Time {

	cutoff := t.now().Add(-t.window)
	all := t.failures[key]
	i := 0
	for i < len(all) && !all[i].After(cutoff) {

		i++
	}
	if i == len(all) {

		delete(t.failures, key)
		return nil
	}
	return all[i:]
}

// sweep drops every key with no failure inside the window. Caller holds mu.
func (t *loginThrottle) sweep() {

	for k := range t.failures {

		t.recent(k)
	}
}

// hashSlots caps concurrent password hashing. Each argon2id verification
// allocates 64 MiB, and /login is unauthenticated: without a cap, a burst of
// parallel requests is a memory exhaustion of the control plane itself.
type hashSlots chan struct{}

const concurrentHashes = 4

func (h hashSlots) do(ctx context.Context, fn func()) error {

	select {

	case h <- struct{}{}:
		defer func() { <-h }()
		fn()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
