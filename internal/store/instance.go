package store

import (
	"context"
	"time"

	"github.com/uptrace/bun"
)

// GetInstance returns the observed state of a tenant's container.
func GetInstance(ctx context.Context, db bun.IDB, tenantID string) (Instance, error) {

	var in Instance
	err := db.NewSelect().Model(&in).Where("tenant_id = ?", tenantID).Scan(ctx)
	if err != nil {

		return Instance{}, err
	}
	return in, nil
}

// InstanceUpdate is a partial write of observed state. Nil fields are left
// alone, so the reconciler can record what it learned without clobbering what
// it did not look at.
type InstanceUpdate struct {
	ContainerID   *string
	ObservedState *string
	RunningDigest *string
	RestartCount  *int
	LastRestartAt *time.Time
	LastHealthAt  *time.Time
	LastError     *string
}

// UpdateInstance applies an InstanceUpdate.
func UpdateInstance(ctx context.Context, tx bun.Tx, tenantID string, u InstanceUpdate) error {

	q := tx.NewUpdate().Model((*Instance)(nil)).
		Set("updated_at = ?", time.Now().UTC()).
		Where("tenant_id = ?", tenantID)
	if u.ContainerID != nil {

		q = q.Set("container_id = ?", nullStr(*u.ContainerID))
	}
	if u.ObservedState != nil {

		q = q.Set("observed_state = ?", *u.ObservedState)
	}
	if u.RunningDigest != nil {

		q = q.Set("running_digest = ?", nullStr(*u.RunningDigest))
	}
	if u.RestartCount != nil {

		q = q.Set("restart_count = ?", *u.RestartCount)
	}
	if u.LastRestartAt != nil {

		q = q.Set("last_restart_at = ?", u.LastRestartAt.UTC())
	}
	if u.LastHealthAt != nil {

		q = q.Set("last_health_at = ?", u.LastHealthAt.UTC())
	}
	if u.LastError != nil {

		q = q.Set("last_error = ?", nullStr(*u.LastError))
	}
	_, err := q.Exec(ctx)
	return err
}
