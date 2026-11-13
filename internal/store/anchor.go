package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// ErrNoAnchor is returned when the chain has never been anchored.
var ErrNoAnchor = errors.New("store: no audit anchor")

// Anchor is a signed copy of the audit chain head, written somewhere the
// control plane cannot later retract (§14.4).
//
// Hashing alone stops in-place edits; it does not stop someone with database
// access rewriting the table and recomputing every hash. An anchor already
// replicated elsewhere is the thing that rewrite cannot reach, which is what
// bounds the tampering: history older than the last replicated anchor is fixed.
//
// Note there is no primary key. Anchors are append-only like the chain itself,
// and two anchors at the same seq (a re-run, a replica) are a fact worth
// keeping rather than a conflict to resolve.
type Anchor struct {
	bun.BaseModel `bun:"table:audit_anchor,alias:audit_anchor" json:"-"`

	Seq        int64     `bun:"seq" json:"seq"`
	HeadHash   string    `bun:"head_hash" json:"head_hash"`
	Signature  string    `bun:"signature" json:"signature"`
	AnchoredAt time.Time `bun:"anchored_at" json:"anchored_at"`
	Location   string    `bun:"location" json:"location"`
}

// InsertAnchor records an anchor inside tx.
func InsertAnchor(ctx context.Context, tx bun.Tx, a Anchor) error {

	if a.AnchoredAt.IsZero() {

		a.AnchoredAt = time.Now().UTC()
	}
	if _, err := tx.NewInsert().Model(&a).Exec(ctx); err != nil {

		return fmt.Errorf("store: insert anchor at seq %d: %w", a.Seq, err)
	}
	return nil
}

// LatestAnchor returns the most recently written anchor.
func LatestAnchor(ctx context.Context, db bun.IDB) (Anchor, error) {

	var a Anchor
	err := db.NewSelect().Model(&a).Order("anchored_at DESC", "seq DESC").Limit(1).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return Anchor{}, ErrNoAnchor
	}
	return a, err
}

// ListAnchors returns every anchor, oldest first.
//
// Verification walks them in chain order, so the ordering is by seq rather than
// by write time: an anchor written late for an earlier seq still constrains
// that point in the chain.
func ListAnchors(ctx context.Context, db bun.IDB) ([]Anchor, error) {

	var out []Anchor
	err := db.NewSelect().Model(&out).Order("seq", "anchored_at").Scan(ctx)
	return out, err
}
