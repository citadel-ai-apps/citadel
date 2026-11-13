package auditlog_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

func openDB(t *testing.T) *store.DB {

	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {

		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func append1(t *testing.T, db *store.DB, l *auditlog.Logger, action string) auditlog.Record {

	t.Helper()
	ctx := context.Background()
	var rec auditlog.Record
	err := db.Tx(ctx, func(tx bun.Tx) error {

		var err error
		rec, err = l.Append(ctx, tx, auditlog.Event{
			ActorID:    auditlog.PlatformPrincipal,
			ActorKind:  auditlog.ActorPlatform,
			Action:     action,
			SubjectRef: "tenant/demo",
		})
		return err
	})
	if err != nil {

		t.Fatalf("append %s: %v", action, err)
	}
	return rec
}

func TestChainLinksEachRowToItsPredecessor(t *testing.T) {

	db := openDB(t)
	l := auditlog.New()

	first := append1(t, db, l, "tenant.provisioned")
	if first.Seq != 1 {

		t.Fatalf("first seq = %d, want 1", first.Seq)
	}
	if first.PrevHash != auditlog.GenesisHash {

		t.Fatalf("first prev_hash = %s, want genesis", first.PrevHash)
	}

	prev := first
	for range 20 {

		rec := append1(t, db, l, "tenant.started")
		if rec.Seq != prev.Seq+1 {

			t.Fatalf("seq %d follows %d", rec.Seq, prev.Seq)
		}
		if rec.PrevHash != prev.Hash {

			t.Fatalf("seq %d prev_hash = %s, want %s", rec.Seq, rec.PrevHash, prev.Hash)
		}
		prev = rec
	}

	res, err := auditlog.Verify(context.Background(), db.Reader())
	if err != nil {

		t.Fatalf("verify: %v", err)
	}
	if !res.OK {

		t.Fatalf("verify reported failure at seq %d: %s", res.FailedSeq, res.Reason)
	}
	if res.Rows != 21 || res.HeadSeq != 21 {

		t.Fatalf("verify saw %d rows head %d, want 21/21", res.Rows, res.HeadSeq)
	}
}

// TestUpdateAndDeleteAreRefusedByTheDatabase is the §16 done-when clause: an
// attempt to UPDATE or DELETE an audit row is refused by the database, not
// merely avoided by convention.
func TestUpdateAndDeleteAreRefusedByTheDatabase(t *testing.T) {

	db := openDB(t)
	l := auditlog.New()
	append1(t, db, l, "tenant.provisioned")
	ctx := context.Background()

	for _, tc := range []struct{ name, stmt string }{
		{"update", `UPDATE audit_event SET action = 'forged' WHERE seq = 1`},
		{"delete", `DELETE FROM audit_event WHERE seq = 1`},
	} {

		t.Run(tc.name, func(t *testing.T) {

			err := db.Tx(ctx, func(tx bun.Tx) error {

				_, err := tx.ExecContext(ctx, tc.stmt)
				return err
			})
			if err == nil {

				t.Fatalf("%s succeeded; audit_event must be append-only", tc.name)
			}
			if !strings.Contains(err.Error(), "append-only") {

				t.Fatalf("%s failed with %v, want the trigger's append-only message", tc.name, err)
			}
		})
	}
}

// TestVerifyNamesTheEditedRow exercises the detection path. The edit has to go
// around the triggers, which is exactly the threat model: someone with database
// access, not someone using the API.
func TestVerifyNamesTheEditedRow(t *testing.T) {

	db := openDB(t)
	l := auditlog.New()
	for range 5 {

		append1(t, db, l, "tenant.started")
	}
	ctx := context.Background()

	// Drop the triggers to simulate an operator with a sqlite3 shell, then edit
	// row 3's action without touching its hash.
	err := db.Tx(ctx, func(tx bun.Tx) error {

		if _, err := tx.ExecContext(ctx, `DROP TRIGGER audit_event_no_update`); err != nil {

			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE audit_event SET action = 'forged' WHERE seq = 3`)
		return err
	})
	if err != nil {

		t.Fatalf("simulated tamper: %v", err)
	}

	res, err := auditlog.Verify(ctx, db.Reader())
	if err != nil {

		t.Fatalf("verify: %v", err)
	}
	if res.OK {

		t.Fatal("verify passed on a tampered chain")
	}
	if res.FailedSeq != 3 {

		t.Fatalf("verify blamed seq %d, want 3", res.FailedSeq)
	}
	if !strings.Contains(res.Reason, "hash") {

		t.Fatalf("reason %q does not explain the hash mismatch", res.Reason)
	}
}

func TestVerifyDetectsARemovedRow(t *testing.T) {

	db := openDB(t)
	l := auditlog.New()
	for range 5 {

		append1(t, db, l, "tenant.started")
	}
	ctx := context.Background()

	err := db.Tx(ctx, func(tx bun.Tx) error {

		if _, err := tx.ExecContext(ctx, `DROP TRIGGER audit_event_no_delete`); err != nil {

			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM audit_event WHERE seq = 3`)
		return err
	})
	if err != nil {

		t.Fatalf("simulated tamper: %v", err)
	}

	res, err := auditlog.Verify(ctx, db.Reader())
	if err != nil {

		t.Fatalf("verify: %v", err)
	}
	if res.OK {

		t.Fatal("verify passed with a row removed from the middle of the chain")
	}
	// Row 4 is the first row whose prev_hash no longer matches the chain.
	if res.FailedSeq != 4 {

		t.Fatalf("verify blamed seq %d, want 4", res.FailedSeq)
	}
}

func TestAppendRequiresATransaction(t *testing.T) {

	l := auditlog.New()
	// bun.Tx is a value type, so the "no transaction" case is its zero value.
	_, err := l.Append(context.Background(), bun.Tx{}, auditlog.Event{
		ActorID: "platform", ActorKind: "platform", Action: "x",
	})
	if err == nil {

		t.Fatal("Append with a zero transaction succeeded; the event must commit with its state change")
	}
}

func TestAppendRequiresAnActor(t *testing.T) {

	db := openDB(t)
	l := auditlog.New()
	ctx := context.Background()
	err := db.Tx(ctx, func(tx bun.Tx) error {

		_, err := l.Append(ctx, tx, auditlog.Event{Action: "tenant.provisioned"})
		return err
	})
	if err == nil {

		t.Fatal("Append with no actor succeeded; every event needs a real actor")
	}
}

// TestDetailRejectsSecretsAndPayloads covers the §14.4 rule that audit rows hold
// subject refs, never payloads: they outlive tenant data, so a payload in
// detail_json contradicts the deletion promise in D10.
func TestDetailRejectsSecretsAndPayloads(t *testing.T) {

	db := openDB(t)
	l := auditlog.New()
	ctx := context.Background()

	cases := map[string]map[string]any{
		"encryption key":  {"enc_key": "deadbeef"},
		"bearer token":    {"api_token": "t-123"},
		"password":        {"password": "hunter2"},
		"authorization":   {"authorization": "Bearer x"},
		"oversized value": {"body": strings.Repeat("x", 600)},
	}
	for name, detail := range cases {

		t.Run(name, func(t *testing.T) {

			err := db.Tx(ctx, func(tx bun.Tx) error {

				_, err := l.Append(ctx, tx, auditlog.Event{
					ActorID: auditlog.PlatformPrincipal, ActorKind: auditlog.ActorPlatform,
					Action: "tenant.provisioned", Detail: detail,
				})
				return err
			})
			if err == nil {

				t.Fatalf("detail %v was accepted", detail)
			}
			if !errors.Is(err, auditlog.ErrDetailRejected) {

				t.Fatalf("got %v, want ErrDetailRejected", err)
			}
		})
	}
}

func TestDetailIsEncodedDeterministically(t *testing.T) {

	db := openDB(t)
	l := auditlog.New()
	ctx := context.Background()

	// Map iteration order is randomised, so an encoder that did not sort would
	// produce a different hash for the same event on different runs — and the
	// chain would not verify after a restart.
	var hashes []string
	for range 8 {

		fresh, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
		if err != nil {

			t.Fatal(err)
		}
		var rec auditlog.Record
		err = fresh.Tx(ctx, func(tx bun.Tx) error {

			var err error
			rec, err = l.Append(ctx, tx, auditlog.Event{
				ActorID: auditlog.PlatformPrincipal, ActorKind: auditlog.ActorPlatform,
				Action: "tenant.provisioned", SubjectRef: "tenant/demo",
				OccurredAt: fixedTime(),
				Detail: map[string]any{
					"slug": "demo", "pb_version": "0.40.4", "subnet": "10.213.1.0/29",
					"disk_mib": 2048, "runtime": "runsc",
				},
			})
			return err
		})
		if err != nil {

			t.Fatal(err)
		}
		// The v2 hash also commits to the row's random id, so the comparison is
		// of the encoded detail the hash takes as input.
		var detail string
		if err := fresh.Reader().QueryRowContext(ctx,
			`SELECT detail_json FROM audit_event WHERE seq = ?`, rec.Seq).Scan(&detail); err != nil {

			t.Fatal(err)
		}
		_ = fresh.Close()
		hashes = append(hashes, detail)
	}
	for _, h := range hashes[1:] {

		if h != hashes[0] {

			t.Fatalf("identical details encoded differently: %s vs %s", h, hashes[0])
		}
	}
	_ = db
}

func TestSelectFiltersByTenantAndActionFamily(t *testing.T) {

	db := openDB(t)
	l := auditlog.New()
	ctx := context.Background()

	err := db.Tx(ctx, func(tx bun.Tx) error {

		for _, ev := range []auditlog.Event{
			{ActorID: "platform", ActorKind: "platform", TenantID: "a", Action: "tenant.provisioned"},
			{ActorID: "platform", ActorKind: "platform", TenantID: "a", Action: "netpolicy.rule.repaired"},
			{ActorID: "platform", ActorKind: "platform", TenantID: "b", Action: "tenant.provisioned"},
		} {

			if _, err := l.Append(ctx, tx, ev); err != nil {

				return err
			}
		}
		return nil
	})
	if err != nil {

		t.Fatal(err)
	}

	got, err := auditlog.Select(ctx, db.Reader(), auditlog.Query{TenantID: "a"})
	if err != nil {

		t.Fatal(err)
	}
	if len(got) != 2 {

		t.Fatalf("tenant a has %d events, want 2", len(got))
	}

	got, err = auditlog.Select(ctx, db.Reader(), auditlog.Query{Action: "netpolicy."})
	if err != nil {

		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Action != "netpolicy.rule.repaired" {

		t.Fatalf("family filter returned %v", got)
	}
}

// fixedTime removes wall-clock variation so two encodings of the same event are
// comparable.
func fixedTime() time.Time {

	return time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
}

// TestReplaceCannotRewriteAnAuditRow: INSERT OR REPLACE deletes the
// conflicting row, and without recursive triggers SQLite skips its DELETE
// triggers while doing so (INV-18).
func TestReplaceCannotRewriteAnAuditRow(t *testing.T) {

	db := openDB(t)
	l := auditlog.New()
	rec := append1(t, db, l, "tenant.provisioned")
	ctx := context.Background()
	err := db.Tx(ctx, func(tx bun.Tx) error {

		_, err := tx.NewRaw(`INSERT OR REPLACE INTO audit_event
			SELECT * FROM audit_event WHERE seq = ?`, rec.Seq).Exec(ctx)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "append-only") {

		t.Fatalf("INSERT OR REPLACE over an audit row returned %v, want the append-only refusal", err)
	}
}
