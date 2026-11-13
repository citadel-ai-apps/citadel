package auditlog_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// appendFor writes an event attributed to a tenant, the kind §14.6's access
// log filters on.
func appendFor(t *testing.T, db *store.DB, tenant, onBehalfOf string) auditlog.Record {

	t.Helper()
	ctx := context.Background()
	var rec auditlog.Record
	err := db.Tx(ctx, func(tx bun.Tx) error {

		var err error
		rec, err = auditlog.New().Append(ctx, tx, auditlog.Event{
			ActorID: auditlog.PlatformPrincipal, ActorKind: auditlog.ActorPlatform,
			OnBehalfOf: onBehalfOf, TenantID: tenant,
			Action: auditlog.ActionDataRead, SubjectRef: "tenant/" + tenant,
		})
		return err
	})
	if err != nil {

		t.Fatal(err)
	}
	return rec
}

func tamper(t *testing.T, db *store.DB, sql string) {

	t.Helper()
	ctx := context.Background()
	if _, err := db.Reader().ExecContext(ctx, `DROP TRIGGER IF EXISTS audit_event_no_update`); err != nil {

		t.Fatal(err)
	}
	if _, err := db.Reader().ExecContext(ctx, sql); err != nil {

		t.Fatal(err)
	}
}

// Moving a platform read out of a tenant's access log, or erasing the
// impersonation behind it, must break the row's hash.
func TestV2CoversTenantAndImpersonation(t *testing.T) {

	for name, edit := range map[string]string{
		"tenant_id":    `UPDATE audit_event SET tenant_id = NULL WHERE seq = 2`,
		"on_behalf_of": `UPDATE audit_event SET on_behalf_of = NULL WHERE seq = 2`,
		"source_ip":    `UPDATE audit_event SET source_ip = '192.0.2.1' WHERE seq = 2`,
		"actor_kind":   `UPDATE audit_event SET actor_kind = 'person' WHERE seq = 2`,
	} {

		t.Run(name, func(t *testing.T) {

			db := openDB(t)
			appendFor(t, db, "demo", "")
			rec := appendFor(t, db, "demo", auditlog.PlatformPrincipal)
			if rec.HashVersion != auditlog.HashV2 {

				t.Fatalf("new row written under hash version %d", rec.HashVersion)
			}
			appendFor(t, db, "demo", "")
			tamper(t, db, edit)

			res, err := auditlog.Verify(context.Background(), db.Reader())
			if err != nil {

				t.Fatal(err)
			}
			if res.OK || res.FailedSeq != 2 {

				t.Fatalf("editing %s verified: %+v", name, res)
			}
		})
	}
}

// Rows from before migration 006 keep verifying under v1, so existing chains
// and their anchors stay valid; but once the chain has moved to v2, a row may
// not claim v1 again.
func TestMixedChainVerifiesAndRefusesADowngrade(t *testing.T) {

	ctx := context.Background()
	db := openDB(t)
	l := auditlog.New()
	append1(t, db, l, "tenant.provisioned")
	append1(t, db, l, "tenant.started")
	// Rewrite rows 1–2 as a pre-006 control plane would have written them.
	tamper(t, db, `UPDATE audit_event SET hash_version = 1`)
	recomputeV1(t, db)
	append1(t, db, l, "tenant.stopped")

	res, err := auditlog.Verify(ctx, db.Reader())
	if err != nil {

		t.Fatal(err)
	}
	if !res.OK || res.RowsV1 != 2 || res.Rows != 3 {

		t.Fatalf("mixed chain: %+v", res)
	}

	tamper(t, db, `INSERT INTO audit_event (seq, id, occurred_at, actor_id, actor_kind, action, prev_hash, hash, hash_version)
		SELECT 4, 'ae-x', occurred_at, actor_id, actor_kind, action, hash, '', 1 FROM audit_event WHERE seq = 3`)
	recomputeV1(t, db)
	res, err = auditlog.Verify(ctx, db.Reader())
	if err != nil {

		t.Fatal(err)
	}
	if res.OK || res.FailedSeq != 4 || !strings.Contains(res.Reason, "downgraded") {

		t.Fatalf("a v1 row after v2 rows verified: %+v", res)
	}
}

// recomputeV1 rewrites every v1 row's hash, standing in for rows a pre-006
// control plane wrote.
func recomputeV1(t *testing.T, db *store.DB) {

	t.Helper()
	ctx := context.Background()
	rows, err := auditlog.Segment(ctx, db.Reader(), 1, 1<<62)
	if err != nil {

		t.Fatal(err)
	}
	prev := auditlog.GenesisHash
	for _, r := range rows {

		if r.HashVersion != auditlog.HashV1 {

			prev = r.Hash
			continue
		}
		h := auditlog.ChainHashV1ForTest(r, prev)
		if _, err := db.Reader().ExecContext(ctx,
			`UPDATE audit_event SET prev_hash = ?, hash = ? WHERE seq = ?`, prev, h, r.Seq); err != nil {

			t.Fatal(err)
		}
		prev = h
	}
}

// The database's copy of an anchor is the one a rewrite deletes first. The
// file copy must still contradict it.
func TestDeletedAnchorRowIsCaughtByItsFile(t *testing.T) {

	ctx := context.Background()
	db := openDB(t)
	l := auditlog.New()
	append1(t, db, l, "tenant.provisioned")
	sg := signer()
	dir := filepath.Join(t.TempDir(), "anchors")
	if _, err := auditlog.Anchor(ctx, db, sg, dir); err != nil {

		t.Fatal(err)
	}

	if _, err := db.Reader().ExecContext(ctx, `DELETE FROM audit_anchor`); err == nil {

		t.Fatal("audit_anchor accepted a DELETE")
	}
	// Somebody who drops it first gets past the database, not past the file.
	if _, err := db.Reader().ExecContext(ctx, `DROP TRIGGER audit_anchor_no_delete`); err != nil {

		t.Fatal(err)
	}
	if _, err := db.Reader().ExecContext(ctx, `DELETE FROM audit_anchor`); err != nil {

		t.Fatal(err)
	}
	rows, err := store.ListAnchors(ctx, db.Reader())
	if err != nil {

		t.Fatal(err)
	}
	files, err := auditlog.LoadAnchorFiles(dir)
	if err != nil || len(files) != 1 {

		t.Fatalf("anchor files: %v, %v", files, err)
	}
	res, err := auditlog.VerifyAll(ctx, db.Reader(), rows, files, sg.PublicKey())
	if err != nil {

		t.Fatal(err)
	}
	if res.OK || !strings.Contains(res.AnchorReason, "missing") {

		t.Fatalf("a deleted anchor row verified: %+v", res)
	}

	// With both copies present, the same check passes.
	db2 := openDB(t)
	append1(t, db2, l, "tenant.provisioned")
	dir2 := filepath.Join(t.TempDir(), "anchors")
	if _, err := auditlog.Anchor(ctx, db2, sg, dir2); err != nil {

		t.Fatal(err)
	}
	rows2, _ := store.ListAnchors(ctx, db2.Reader())
	files2, _ := auditlog.LoadAnchorFiles(dir2)
	res2, err := auditlog.VerifyAll(ctx, db2.Reader(), rows2, files2, sg.PublicKey())
	if err != nil || !res2.OK {

		t.Fatalf("intact anchors failed: %+v, %v", res2, err)
	}
}

// An anchor whose signature nobody checked is the database vouching for itself.
func TestAnchorsWithoutAKeyDoNotVerify(t *testing.T) {

	ctx := context.Background()
	db := openDB(t)
	append1(t, db, auditlog.New(), "tenant.provisioned")
	a, err := auditlog.Anchor(ctx, db, signer(), filepath.Join(t.TempDir(), "anchors"))
	if err != nil {

		t.Fatal(err)
	}
	res, err := auditlog.VerifyWithAnchors(ctx, db.Reader(), []store.Anchor{a}, "")
	if err != nil {

		t.Fatal(err)
	}
	if res.OK {

		t.Fatal("an anchor verified with no public key")
	}
}
