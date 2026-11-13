package hostfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// ErrLocked means another operation currently holds the tenant's lock.
var ErrLocked = errors.New("hostfs: another operation holds this tenant's instance.lock")

// Lock is a held instance.lock.
type Lock struct {
	f    *os.File
	once sync.Once
}

// Release drops the lock. Safe to call more than once.
func (l *Lock) Release() {

	l.once.Do(func() { _ = l.f.Close() })
}

// Lock takes the tenant's singleton guard: one process per pb_data, ever.
//
// The lock is advisory and held by an open descriptor, so it evaporates when
// the process dies: killing the control plane mid-operation never leaves a
// tenant permanently locked, which is what makes crash recovery a normal
// reconcile rather than a repair mode.
//
// Held across every mutating sequence including destroy: a teardown that took
// no lock could race a deploy.
func (f *FS) Lock(tenantID string) (*Lock, error) {

	if err := os.MkdirAll(f.cfg.TenantDir(tenantID), 0o700); err != nil {

		return nil, err
	}
	path := f.LockPath(tenantID)
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {

		return nil, fmt.Errorf("hostfs: open %s: %w", path, err)
	}
	if err := unix.Flock(int(fh.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {

		_ = fh.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {

			return nil, fmt.Errorf("%w: %s", ErrLocked, tenantID)
		}
		return nil, fmt.Errorf("hostfs: flock %s: %w", path, err)
	}
	return &Lock{f: fh}, nil
}

// LockWait is Lock, retrying until the budget runs out.
//
// The non-blocking Lock is right for the reconcile tick: a tenant someone else
// is working on is skipped, and the next tick picks it up. It is wrong for
// anything a human or an API call is waiting on. The tick holds the lock for a
// fraction of a second every five seconds, so a deploy, a restore or an upgrade
// that refuses outright has a real chance of failing for a reason that has
// nothing to do with what was asked — and the caller's only recourse is to try
// again, which is what this does for them.
//
// It still gives up. Waiting forever would turn one stuck operation into every
// operation on that tenant hanging, and a caller told "busy, try again" can
// make a decision; a caller that never returns cannot.
func (f *FS) LockWait(ctx context.Context, tenantID string, budget time.Duration) (*Lock, error) {

	deadline := time.Now().Add(budget)
	for {

		lock, err := f.Lock(tenantID)
		if err == nil || !errors.Is(err, ErrLocked) {

			return lock, err
		}
		if time.Now().After(deadline) {

			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
}
