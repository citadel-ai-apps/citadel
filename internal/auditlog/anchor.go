package auditlog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/store"
	"github.com/uptrace/bun"
)

// Signer is what auditlog needs from a signing key. hostfs.Signer satisfies it.
//
// An interface rather than the concrete type so that the anchor path can be
// tested without a key on disk, and so nothing here can reach the key material
// itself.
type Signer interface {
	Sign(payload []byte) string
	PublicKey() string
}

// AnchorPayload is what a signature commits to.
//
// The timestamp is inside the signed bytes deliberately. Without it, an anchor
// is a statement about a point in the chain that could be re-presented at any
// later date; with it, replaying an old anchor says when it was made and is
// therefore checkable against the interval it was supposed to be written on.
func AnchorPayload(seq int64, headHash string, at time.Time) []byte {

	return fmt.Appendf(nil, "v2p-anchor\x00%d\x00%s\x00%s", seq, headHash, at.UTC().Format(tsLayout))
}

// anchorFile is the on-disk form, written to a directory meant to be
// replicated somewhere the control plane cannot reach back into.
type anchorFile struct {
	Seq        int64     `json:"seq"`
	HeadHash   string    `json:"head_hash"`
	Signature  string    `json:"signature"`
	PublicKey  string    `json:"public_key"`
	AnchoredAt time.Time `json:"anchored_at"`
}

// Head returns the chain's current tip without recomputing it.
func Head(ctx context.Context, db bun.IDB) (seq int64, hash string, err error) {

	row := db.QueryRowContext(ctx, `SELECT seq, hash FROM audit_event ORDER BY seq DESC LIMIT 1`)
	switch err := row.Scan(&seq, &hash); {

	case err == nil:
		return seq, hash, nil

	case errors.Is(err, sql.ErrNoRows):
		// An empty chain is not an error: the platform has simply not acted
		// yet, and anchoring genesis is a meaningful thing to have recorded.
		return 0, GenesisHash, nil

	default:
		// Anything else is a database that could not be read, and signing
		// "the chain is empty" over it would be a false statement.
		return 0, "", fmt.Errorf("auditlog: read chain head: %w", err)
	}
}

// Anchor signs the current chain head and records it both in the database and
// as a file under dir.
//
// Two copies because they fail differently. The row makes the anchor queryable
// next to the chain it constrains; the file is what gets replicated off this
// host, and an operator who rewrites the table cannot reach a copy that has
// already left. Until that replication exists, the file is only as trustworthy
// as the host — say so rather than implying otherwise.
func Anchor(ctx context.Context, db *store.DB, signer Signer, dir string) (store.Anchor, error) {

	seq, hash, err := Head(ctx, db.Reader())
	if err != nil {

		return store.Anchor{}, err
	}
	at := time.Now().UTC().Truncate(time.Second)
	a := store.Anchor{
		Seq:        seq,
		HeadHash:   hash,
		Signature:  signer.Sign(AnchorPayload(seq, hash, at)),
		AnchoredAt: at,
		Location:   dir,
	}
	if err := writeAnchorFile(dir, signer.PublicKey(), a); err != nil {

		return store.Anchor{}, err
	}
	// The file first, then the row: a file with no row is a harmless duplicate
	// on the next tick, while a row with no file claims an offsite copy that
	// does not exist.
	err = db.Tx(ctx, func(tx bun.Tx) error {

		return store.InsertAnchor(ctx, tx, a)
	})
	if err != nil {

		return store.Anchor{}, err
	}
	return a, nil
}

func writeAnchorFile(dir, pub string, a store.Anchor) error {

	if err := os.MkdirAll(dir, 0o700); err != nil {

		return err
	}
	body, err := json.MarshalIndent(anchorFile{
		Seq: a.Seq, HeadHash: a.HeadHash, Signature: a.Signature,
		PublicKey: pub, AnchoredAt: a.AnchoredAt,
	}, "", "  ")
	if err != nil {

		return err
	}
	// The sequence is part of the name: two anchors in one second must not
	// overwrite each other's evidence.
	name := filepath.Join(dir, fmt.Sprintf("%s-%d.json", a.AnchoredAt.Format("20060102T150405Z"), a.Seq))
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {

		return err
	}
	if err := os.Rename(tmp, name); err != nil {

		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// AnchorCheck is one anchor's verdict after the chain was recomputed.
type AnchorCheck struct {
	Seq        int64     `json:"seq"`
	AnchoredAt time.Time `json:"anchored_at"`
	OK         bool      `json:"ok"`
	Reason     string    `json:"reason,omitempty"`
}

// checkAnchors compares recomputed hashes against what was anchored.
//
// This is the check a local recompute cannot make. Recomputing catches a row
// edited in place, because the row no longer agrees with its own hash. It does
// NOT catch a table rewritten wholesale with every hash recomputed — that chain
// is internally consistent and verifies clean. What it cannot do is reach a
// signed head that already left the host, so a rewrite shows up here as an
// anchor whose head hash no longer appears at its own seq.
func checkAnchors(anchors []store.Anchor, pub string, hashes map[int64]string, headSeq int64) []AnchorCheck {

	out := make([]AnchorCheck, 0, len(anchors))
	for _, a := range anchors {

		c := AnchorCheck{Seq: a.Seq, AnchoredAt: a.AnchoredAt, OK: true}
		switch {

		case pub == "":
			// Unsigned is unverified. An anchor whose signature nobody checked
			// is a claim the database makes about itself.
			c.OK, c.Reason = false, "no public key to verify the anchor signature against"

		case !hostfs.Verify(pub, a.Signature, AnchorPayload(a.Seq, a.HeadHash, a.AnchoredAt)):
			c.OK, c.Reason = false, "anchor signature does not verify"

		case a.Seq > headSeq:
			c.OK, c.Reason = false, fmt.Sprintf(
				"chain is truncated: anchored at seq %d, head is now seq %d", a.Seq, headSeq)

		case hashes[a.Seq] != a.HeadHash:
			c.OK, c.Reason = false, fmt.Sprintf(
				"seq %d now hashes to %s, anchor says %s",
				a.Seq, short(hashes[a.Seq]), short(a.HeadHash))
		}
		out = append(out, c)
	}
	return out
}

// LoadAnchorFiles reads the anchor files written under dir.
//
// These are the copies an operator who rewrites the database cannot reach once
// they have left the host, and, until they have, the copies a rewrite of the
// database alone does not touch. A missing directory is no anchors, not an
// error: a control plane that has never anchored has nothing to load.
func LoadAnchorFiles(dir string) ([]store.Anchor, error) {

	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {

		return nil, nil
	}
	if err != nil {

		return nil, fmt.Errorf("auditlog: read anchors: %w", err)
	}
	var out []store.Anchor
	for _, e := range entries {

		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".json") {

			continue
		}
		path := filepath.Join(dir, e.Name())
		body, err := os.ReadFile(path)
		if err != nil {

			return nil, fmt.Errorf("auditlog: read anchor %s: %w", path, err)
		}
		var f anchorFile
		if err := json.Unmarshal(body, &f); err != nil {

			return nil, fmt.Errorf("auditlog: anchor %s is not an anchor: %w", path, err)
		}
		out = append(out, store.Anchor{
			Seq: f.Seq, HeadHash: f.HeadHash, Signature: f.Signature,
			AnchoredAt: f.AnchoredAt.UTC(), Location: path,
		})
	}
	return out, nil
}

// VerifyAll is VerifyWithAnchors over both copies of the anchors: the rows in
// the database and the files on disk.
//
// Every distinct anchor is checked against the chain. On top of that, an
// anchor that exists as a file but has no row is reported: rows are written
// after their file and are append-only, so a file with no row is a row that
// was removed — the first thing to go in a rewrite that wants its anchors to
// stop contradicting it.
func VerifyAll(ctx context.Context, db bun.IDB, rows, files []store.Anchor, pub string) (VerifyResult, error) {

	key := func(a store.Anchor) string {

		return fmt.Sprintf("%d\x00%s\x00%s", a.Seq, a.HeadHash, a.Signature)
	}
	inDB := make(map[string]bool, len(rows))
	merged := append([]store.Anchor{}, rows...)
	for _, a := range rows {

		inDB[key(a)] = true
	}
	var missing []store.Anchor
	for _, a := range files {

		if !inDB[key(a)] {

			missing = append(missing, a)
			merged = append(merged, a)
			inDB[key(a)] = true // a duplicate file is one anchor, not two
		}
	}
	res, err := VerifyWithAnchors(ctx, db, merged, pub)
	if err != nil {

		return res, err
	}
	for _, a := range missing {

		res.Anchors = append(res.Anchors, AnchorCheck{
			Seq: a.Seq, AnchoredAt: a.AnchoredAt,
			Reason: "anchor file " + filepath.Base(a.Location) + " has no row in the database",
		})
		if res.AnchorReason == "" {

			res.OK = false
			res.ContradictedSeq = a.Seq
			res.AnchorReason = "anchor row missing: " + filepath.Base(a.Location) + " is on disk but not in the database"
		}
	}
	res.AnchorsChecked = len(res.Anchors)
	return res, nil
}
