package auditlog_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

func signer() *hostfs.Signer { return hostfs.NewSignerFromSeed([]byte("anchor-test-seed")) }

func TestAnchorWritesARowAndAFile(t *testing.T) {

	db := openDB(t)
	l := auditlog.New()
	append1(t, db, l, "tenant.provisioned")
	append1(t, db, l, "tenant.started")

	dir := filepath.Join(t.TempDir(), "anchors")
	a, err := auditlog.Anchor(context.Background(), db, signer(), dir)
	if err != nil {

		t.Fatalf("anchor: %v", err)
	}
	if a.Seq != 2 {

		t.Fatalf("anchored seq = %d, want 2", a.Seq)
	}

	// The file is the copy meant to leave the host. A row claiming an anchor
	// with no file on disk would be a lie about evidence.
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {

		t.Fatalf("anchors dir holds %v (err %v), want exactly one file", entries, err)
	}
	body, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {

		t.Fatal(err)
	}
	var onDisk struct {
		Seq       int64  `json:"seq"`
		HeadHash  string `json:"head_hash"`
		Signature string `json:"signature"`
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(body, &onDisk); err != nil {

		t.Fatalf("anchor file is not JSON: %v", err)
	}
	if onDisk.Seq != a.Seq || onDisk.HeadHash != a.HeadHash {

		t.Fatalf("anchor file %+v does not match the row %+v", onDisk, a)
	}
	// Verifiable by somebody who does not hold the key: that is the whole
	// reason the anchor is signed rather than hashed.
	if !hostfs.Verify(onDisk.PublicKey, onDisk.Signature,
		auditlog.AnchorPayload(a.Seq, a.HeadHash, a.AnchoredAt)) {

		t.Fatal("the anchor signature does not verify against its published public key")
	}
}

// A wholesale rewrite is the failure a local recompute cannot see: every hash
// is recalculated, so the chain agrees with itself. Only an anchor written
// before the rewrite contradicts it.
func TestAnchorCatchesAWholesaleRewriteThatRecomputesClean(t *testing.T) {

	ctx := context.Background()
	db := openDB(t)
	l := auditlog.New()
	append1(t, db, l, "tenant.provisioned")
	append1(t, db, l, "grant.approved")

	sg := signer()
	anchor, err := auditlog.Anchor(ctx, db, sg, filepath.Join(t.TempDir(), "anchors"))
	if err != nil {

		t.Fatalf("anchor: %v", err)
	}

	// Rewrite the chain from scratch, the way somebody with database access
	// would: drop the append-only triggers first, then delete and re-append
	// different events. The new table is internally consistent.
	dropAuditGuards(t, db)
	if _, err := db.Reader().ExecContext(ctx, `DELETE FROM audit_event`); err != nil {

		t.Fatalf("rewrite: %v", err)
	}
	append1(t, db, l, "tenant.provisioned")
	append1(t, db, l, "grant.denied")

	plain, err := auditlog.Verify(ctx, db.Reader())
	if err != nil {

		t.Fatal(err)
	}
	if !plain.OK {

		t.Fatalf("a rewritten chain should recompute cleanly; got %q at seq %d",
			plain.Reason, plain.FailedSeq)
	}

	withAnchors, err := auditlog.VerifyWithAnchors(ctx, db.Reader(),
		[]store.Anchor{anchor}, sg.PublicKey())
	if err != nil {

		t.Fatal(err)
	}
	if withAnchors.OK {

		t.Fatal("the anchor did not contradict the rewrite; this is the one case it exists for")
	}
	if withAnchors.ContradictedSeq != anchor.Seq {

		t.Fatalf("contradicted seq = %d, want %d", withAnchors.ContradictedSeq, anchor.Seq)
	}
}

func TestAnchorDetectsATruncatedChain(t *testing.T) {

	ctx := context.Background()
	db := openDB(t)
	l := auditlog.New()
	append1(t, db, l, "tenant.provisioned")
	append1(t, db, l, "tenant.started")

	sg := signer()
	anchor, err := auditlog.Anchor(ctx, db, sg, filepath.Join(t.TempDir(), "anchors"))
	if err != nil {

		t.Fatal(err)
	}
	dropAuditGuards(t, db)
	if _, err := db.Reader().ExecContext(ctx, `DELETE FROM audit_event WHERE seq = 2`); err != nil {

		t.Fatal(err)
	}
	res, err := auditlog.VerifyWithAnchors(ctx, db.Reader(), []store.Anchor{anchor}, sg.PublicKey())
	if err != nil {

		t.Fatal(err)
	}
	if res.OK {

		t.Fatal("deleting the anchored head verified clean")
	}
}

func TestAnchorRejectsAForgedSignature(t *testing.T) {

	ctx := context.Background()
	db := openDB(t)
	append1(t, db, auditlog.New(), "tenant.provisioned")

	sg := signer()
	a, err := auditlog.Anchor(ctx, db, sg, filepath.Join(t.TempDir(), "anchors"))
	if err != nil {

		t.Fatal(err)
	}
	// An operator who rewrites the table and re-signs the anchor under a key
	// the published one does not match gains nothing.
	forged := a
	forged.Signature = hostfs.NewSignerFromSeed([]byte("other")).Sign(
		auditlog.AnchorPayload(a.Seq, a.HeadHash, a.AnchoredAt))

	res, err := auditlog.VerifyWithAnchors(ctx, db.Reader(), []store.Anchor{forged}, sg.PublicKey())
	if err != nil {

		t.Fatal(err)
	}
	if res.OK {

		t.Fatal("a signature from the wrong key verified")
	}
}

// dropAuditGuards removes the append-only triggers, standing in for an operator
// with database access. The triggers are a guard against accident and a second
// writer, never against somebody who can run arbitrary SQL — which is exactly
// why the anchors exist.
func dropAuditGuards(t *testing.T, db *store.DB) {

	t.Helper()
	for _, name := range []string{"audit_event_no_update", "audit_event_no_delete"} {

		if _, err := db.Reader().ExecContext(context.Background(), "DROP TRIGGER "+name); err != nil {

			t.Fatalf("drop %s: %v", name, err)
		}
	}
}

func TestSegmentSpansOtherTenantsRows(t *testing.T) {

	ctx := context.Background()
	db := openDB(t)
	l := auditlog.New()
	append1(t, db, l, "tenant.provisioned")
	append1(t, db, l, "tenant.started")
	append1(t, db, l, "grant.approved")

	seg, err := auditlog.Segment(ctx, db.Reader(), 1, 3)
	if err != nil {

		t.Fatal(err)
	}
	// Without the intervening rows a recipient cannot recompute the chain:
	// a prev_hash would point at a row they do not have.
	if len(seg) != 3 {

		t.Fatalf("segment holds %d rows, want 3", len(seg))
	}
	if seg[0].PrevHash != auditlog.GenesisHash {

		t.Fatalf("segment does not start at genesis: %s", seg[0].PrevHash)
	}
}

// Anchoring can fire before the platform has done anything: the reconciler runs
// it on its own schedule, not on the first event. An anchor at genesis is a
// real statement, and verification must not read a freshly installed control
// plane as a tampered one.
func TestAnchoringAnEmptyChainVerifies(t *testing.T) {

	ctx := context.Background()
	db := openDB(t)
	sg := signer()

	a, err := auditlog.Anchor(ctx, db, sg, filepath.Join(t.TempDir(), "anchors"))
	if err != nil {

		t.Fatal(err)
	}
	if a.Seq != 0 || a.HeadHash != auditlog.GenesisHash {

		t.Fatalf("empty-chain anchor = seq %d hash %s, want 0/genesis", a.Seq, a.HeadHash)
	}
	res, err := auditlog.VerifyWithAnchors(ctx, db.Reader(), []store.Anchor{a}, sg.PublicKey())
	if err != nil {

		t.Fatal(err)
	}
	if !res.OK {

		t.Fatalf("a genesis anchor fails verification: %s / %s", res.Reason, res.AnchorReason)
	}

	// And it keeps verifying once events arrive on top of it.
	append1(t, db, auditlog.New(), "tenant.provisioned")
	res, err = auditlog.VerifyWithAnchors(ctx, db.Reader(), []store.Anchor{a}, sg.PublicKey())
	if err != nil {

		t.Fatal(err)
	}
	if !res.OK {

		t.Fatalf("a genesis anchor fails once the chain grows: %s", res.AnchorReason)
	}
}
