package reconcile

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/health"
	"github.com/citadel-ai-apps/citadel/internal/pbauth"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// healthToken signs a fresh token for the data-plane check, from the tenant's
// live pb_data, for whichever superuser exists.
//
// Not the owner seat: the owner is a full superuser of their instance and can
// rename, re-password or delete the seat, and none of that may make a healthy
// instance look broken.
func (r *Reconciler) healthToken(t store.Tenant) health.TokenSource {

	return func(ctx context.Context) (string, error) {

		return r.mintFrom(ctx, t, r.fs.DataDir(t.ID), t.RuntimeVersion, pbauth.AnySuperuser(), 0)
	}
}

// mintFrom signs a superuser token from a pb_data directory: the tenant's own,
// or a rehearsal copy of it.
func (r *Reconciler) mintFrom(ctx context.Context, t store.Tenant, dataDir, pbVersion string, sel pbauth.Selector, ttl time.Duration) (string, error) {

	key, err := r.fs.EncryptionKey(t.ID)
	if err != nil {

		return "", err
	}
	tok, err := pbauth.Mint(ctx, pbauth.Source{DataDir: dataDir, PBVersion: pbVersion, EncryptionKey: key}, sel, ttl)
	if err != nil {

		return "", err
	}
	return tok.Token, nil
}

// waitReady is health.WaitReady with a token signed per attempt.
func (r *Reconciler) waitReady(ctx context.Context, t store.Tenant) error {

	return r.hc.WaitReady(ctx, t.Hostname, t.RuntimeVersion, r.healthToken(t), r.cfg.HealthTimeout.D())
}

// ensureSeat creates the owner seat with a password nobody will ever see.
//
// The password is required by the CLI and useless afterwards: the owner reaches
// /_/ through the portal's signed-token handoff, so it is generated, passed to
// the one-shot and dropped. Only ever called with no PocketBase process on the
// tenant's pb_data (design.md INV-3).
func (r *Reconciler) ensureSeat(ctx context.Context, t store.Tenant, pbVersion string, spec driver.InstanceSpec) error {

	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {

		return err
	}
	return r.drv.EnsureSuperuser(ctx, spec, pbVersion, pbauth.SeatEmail(t.ID), hex.EncodeToString(b))
}

// restoreSeat re-creates the owner seat if the owner deleted it from inside the
// instance, so the portal handoff works again after the next deploy. An
// existing seat is left alone: an upsert would overwrite a password the owner
// may have set on it.
//
// 0.23+ only. Pre-0.23 has no upsert, and `admin create` cannot be told apart
// from success by its exit code (design.md §5). A failure here is logged, never
// fatal: a missing seat costs the owner the handoff, not the deploy.
func (r *Reconciler) restoreSeat(ctx context.Context, t store.Tenant, spec driver.InstanceSpec) {

	if pbauth.IsLegacy(t.RuntimeVersion) {

		return
	}
	key, err := r.fs.EncryptionKey(t.ID)
	if err != nil {

		r.log.Warn("cannot check the owner seat", "tenant", t.ID, "err", err)
		return
	}
	src := pbauth.Source{DataDir: r.fs.DataDir(t.ID), PBVersion: t.RuntimeVersion, EncryptionKey: key}
	ok, err := pbauth.Exists(ctx, src, pbauth.BySeatEmail(pbauth.SeatEmail(t.ID)))
	if err != nil || ok {

		if err != nil {

			r.log.Warn("cannot check the owner seat", "tenant", t.ID, "err", err)
		}
		return
	}
	if err := r.ensureSeat(ctx, t, t.RuntimeVersion, spec); err != nil {

		r.log.Warn("cannot re-create the owner seat", "tenant", t.ID, "err", err)
		return
	}
	r.log.Info("owner seat re-created", "tenant", t.ID)
}
