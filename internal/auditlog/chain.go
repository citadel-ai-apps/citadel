package auditlog

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/store"
	"github.com/uptrace/bun"
)

// VerifyResult reports the outcome of recomputing the chain and comparing it
// against the anchors.
//
// Two independent failures, and they catch different attacks. A recompute
// catches a row edited in place; only an anchor catches a table rewritten
// wholesale with every hash recomputed, because that chain is internally
// consistent and verifies clean against itself.
type VerifyResult struct {
	Rows int64 `json:"rows"`
	// RowsV1 counts rows verified under the v1 commitment, which does not
	// cover tenant_id or on_behalf_of: those fields are only as trustworthy as
	// the database for these rows.
	RowsV1    int64  `json:"rows_v1,omitempty"`
	HeadSeq   int64  `json:"head_seq"`
	HeadHash  string `json:"head_hash"`
	OK        bool   `json:"ok"`
	FailedSeq int64  `json:"failed_seq,omitempty"`
	Reason    string `json:"reason,omitempty"`

	Anchors          []AnchorCheck `json:"anchors,omitempty"`
	AnchorsChecked   int           `json:"anchors_checked"`
	ContradictedSeq  int64         `json:"contradicted_seq,omitempty"`
	AnchorReason     string        `json:"anchor_reason,omitempty"`
	LastAnchoredAt   time.Time     `json:"last_anchored_at,omitzero"`
	SigningPublicKey string        `json:"signing_public_key,omitempty"`
}

// Verify recomputes the whole chain and reports the first row that does not
// agree with its own contents or with its predecessor.
//
// This alone cannot detect a wholesale rewrite. Use VerifyWithAnchors wherever
// the anchors are reachable.
func Verify(ctx context.Context, db bun.IDB) (VerifyResult, error) {

	return VerifyWithAnchors(ctx, db, nil, "")
}

// VerifyWithAnchors recomputes the chain and checks the recomputed hashes
// against every signed head that was written at a point in it.
func VerifyWithAnchors(ctx context.Context, db bun.IDB, anchors []store.Anchor, pub string) (VerifyResult, error) {

	anchored := make(map[int64]bool, len(anchors))
	for _, a := range anchors {

		anchored[a.Seq] = true
	}
	// Seeded with genesis. Anchoring runs on the reconciler's own schedule and
	// can fire before the platform has done anything, which records seq 0 and
	// the genesis hash — a real, meaningful anchor ("the chain was empty at this
	// time"). Without this seed the walk finds no row at seq 0, reads the
	// missing entry as a mismatch, and reports a freshly installed control plane
	// as a tampered one.
	hashes := map[int64]string{0: GenesisHash}

	rows, err := db.QueryContext(ctx, `
		SELECT seq, id, occurred_at, actor_id, actor_kind, COALESCE(on_behalf_of,''),
		       COALESCE(tenant_id,''), action, COALESCE(subject_ref,''), COALESCE(detail_json,''),
		       COALESCE(request_id,''), COALESCE(source_ip,''), prev_hash, hash, hash_version
		FROM audit_event ORDER BY seq ASC`)
	if err != nil {

		return VerifyResult{}, err
	}
	defer rows.Close()

	res := VerifyResult{OK: true}
	prevHash := GenesisHash
	var prevSeq int64
	sawV2 := false
	for rows.Next() {

		var (
			f          fields
			storedHash string
			version    int
		)
		if err := rows.Scan(&f.seq, &f.id, &f.occurredAt, &f.actorID, &f.actorKind, &f.onBehalfOf,
			&f.tenantID, &f.action, &f.subjectRef, &f.detailJSON, &f.requestID, &f.sourceIP,
			&f.prevHash, &storedHash, &version); err != nil {

			return VerifyResult{}, err
		}
		seq, storedPrev := f.seq, f.prevHash
		res.Rows++

		if storedPrev != prevHash {

			return failed(res, seq, fmt.Sprintf(
				"prev_hash does not chain onto seq %d (row says %s, chain says %s)",
				prevSeq, short(storedPrev), short(prevHash))), nil
		}
		ts, err := time.Parse(tsLayout, f.occurredAt)
		if err != nil {

			return failed(res, seq, "occurred_at is not a chain timestamp: "+f.occurredAt), nil
		}
		// The cutover to v2 happens once. A v1 row after it is a row that
		// claims the weaker commitment so that the columns only v2 covers can
		// be edited.
		switch {

		case version == HashV2:
			sawV2 = true
		case version == HashV1 && sawV2:
			return failed(res, seq, "a v1 row follows v2 rows; the hash version was downgraded"), nil
		case version == HashV1:
			res.RowsV1++
		}
		want, err := hashFor(version, f, ts)
		if err != nil {

			return failed(res, seq, err.Error()), nil
		}
		if want != storedHash {

			return failed(res, seq, fmt.Sprintf(
				"row contents do not match its hash (stored %s, recomputed %s)",
				short(storedHash), short(want))), nil
		}
		if anchored[seq] {

			hashes[seq] = storedHash
		}
		prevHash, prevSeq = storedHash, seq
	}
	if err := rows.Err(); err != nil {

		return VerifyResult{}, err
	}
	res.HeadSeq, res.HeadHash = prevSeq, prevHash

	res.Anchors = checkAnchors(anchors, pub, hashes, prevSeq)
	res.AnchorsChecked = len(res.Anchors)
	res.SigningPublicKey = pub
	for _, c := range res.Anchors {

		if c.AnchoredAt.After(res.LastAnchoredAt) {

			res.LastAnchoredAt = c.AnchoredAt
		}
		if !c.OK && res.AnchorReason == "" {

			// A contradicted anchor fails the whole verification even when the
			// recompute was clean — that combination IS the wholesale-rewrite
			// signature, and reporting it as a pass would be the one answer
			// this command must never give.
			res.OK = false
			res.ContradictedSeq, res.AnchorReason = c.Seq, c.Reason
		}
	}
	return res, nil
}

func failed(res VerifyResult, seq int64, reason string) VerifyResult {

	res.OK = false
	res.FailedSeq = seq
	res.Reason = reason
	return res
}

func short(h string) string {

	if len(h) > 12 {

		return h[:12]
	}
	return h
}

// Segment returns every row between two seqs inclusive, whatever tenant it
// belongs to.
//
// This is what makes a tenant-scoped export checkable. With one global chain, a
// tenant's own rows commit to rows belonging to other tenants, so handing over
// only the matching rows hands over something that cannot be verified — the
// recipient would find a prev_hash pointing at a row they do not have. The
// segment closes that, and the cost is real and worth stating: subject_ref and
// detail_json are hash INPUTS, so another tenant's rows cannot be redacted
// without making the segment unverifiable. That is why §14.4's "subject refs,
// never payloads" rule is load-bearing rather than tidy — an export is the
// moment a payload in detail_json would leak to a third party. Treat an export
// as operator-only until D14a settles on per-tenant chains or inclusion proofs.
func Segment(ctx context.Context, db bun.IDB, from, to int64) ([]Record, error) {

	return selectRecords(ctx, db, " WHERE seq BETWEEN ? AND ? ORDER BY seq ASC", from, to)
}

// recordColumns is every column a Record carries, in scanRecord's order.
const recordColumns = `SELECT seq, id, occurred_at, actor_id, actor_kind,
                   COALESCE(on_behalf_of,''), COALESCE(tenant_id,''), action,
                   COALESCE(subject_ref,''), COALESCE(detail_json,''),
                   COALESCE(request_id,''), COALESCE(source_ip,''), prev_hash, hash, hash_version
            FROM audit_event`

// selectRecords runs recordColumns with a tail of WHERE/ORDER/LIMIT clauses.
//
// Every column is returned, not only the ones a caller displays: under v2 the
// hash commits to all of them, and a segment handed to a third party must be
// recomputable from what it contains.
func selectRecords(ctx context.Context, db bun.IDB, tail string, args ...any) ([]Record, error) {

	rows, err := db.QueryContext(ctx, recordColumns+tail, args...)
	if err != nil {

		return nil, err
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {

		var r Record
		var occurredAt, detail string
		if err := rows.Scan(&r.Seq, &r.ID, &occurredAt, &r.ActorID, &r.ActorKind,
			&r.OnBehalfOf, &r.TenantID, &r.Action, &r.SubjectRef, &detail,
			&r.RequestID, &r.SourceIP, &r.PrevHash, &r.Hash, &r.HashVersion); err != nil {

			return nil, err
		}
		r.OccurredAt, _ = time.Parse(tsLayout, occurredAt)
		if detail != "" {

			_ = json.Unmarshal([]byte(detail), &r.Detail)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Query is a filter over the audit log.
type Query struct {
	TenantID string
	ActorID  string
	Action   string // exact, or a "family." prefix
	Since    time.Time
	Until    time.Time
	Limit    int
}

// Select returns matching audit records, oldest first.
func Select(ctx context.Context, db bun.IDB, q Query) ([]Record, error) {

	var where []string
	var args []any
	if q.TenantID != "" {

		where = append(where, "tenant_id = ?")
		args = append(args, q.TenantID)
	}
	if q.ActorID != "" {

		where = append(where, "actor_id = ?")
		args = append(args, q.ActorID)
	}
	if q.Action != "" {

		if strings.HasSuffix(q.Action, ".") {

			where = append(where, "action LIKE ?")
			args = append(args, q.Action+"%")

		} else {

			where = append(where, "action = ?")
			args = append(args, q.Action)
		}
	}
	if !q.Since.IsZero() {

		where = append(where, "occurred_at >= ?")
		args = append(args, q.Since.UTC().Format(tsLayout))
	}
	if !q.Until.IsZero() {

		where = append(where, "occurred_at <= ?")
		args = append(args, q.Until.UTC().Format(tsLayout))
	}
	limit := q.Limit
	if limit <= 0 || limit > 1000 {

		limit = 200
	}

	tail := ""
	if len(where) > 0 {

		tail = " WHERE " + strings.Join(where, " AND ")
	}
	tail += " ORDER BY seq ASC LIMIT ?"
	args = append(args, limit)
	return selectRecords(ctx, db, tail, args...)
}
