// Package auditlog is the ONLY writer of the audit_event table (design §14.4).
// A second writer means a second hash chain and a broken one.
//
// The public API deliberately offers no way to append outside a caller-supplied
// transaction: the event and the state change it records must commit together
// or not at all (design §14.4).
package auditlog

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bun"
)

// GenesisHash is the prev_hash of the first row in the chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Actor kinds, mirroring principal.kind.
const (
	ActorPerson         = "person"
	ActorServiceAccount = "service_account"
	ActorPlatform       = "platform"
)

// PlatformPrincipal is the id of the principal that owns automated actions.
// Seeded by migration 001 so an automated action never has a NULL actor (§14.1).
const PlatformPrincipal = "platform"

// Action names emitted by the control plane. Namespaced per §14.4 so an audit
// query can select a whole family.
const (
	ActionPrincipalCreated    = "principal.created"
	ActionPrincipalSuspended  = "principal.suspended"
	ActionOwnerGranted        = "tenant.owner.granted"
	ActionOwnerRevoked        = "tenant.owner.revoked"
	ActionOwnerTransferred    = "tenant.owner.transferred"
	ActionOwnerOrphaned       = "tenant.owner.orphaned"
	ActionTenantProvisioned   = "tenant.provisioned"
	ActionTenantStarted       = "tenant.started"
	ActionTenantStopped       = "tenant.stopped"
	ActionTenantRestarted     = "tenant.restarted"
	ActionTenantDestroyed     = "tenant.destroyed"
	ActionTenantDesiredState  = "tenant.desired_state.changed"
	ActionTenantResized       = "tenant.resized"
	ActionRuleWritten         = "netpolicy.rule.written"
	ActionRuleRepaired        = "netpolicy.rule.repaired"
	ActionRuleRemoved         = "netpolicy.rule.removed"
	ActionNetpolicyDrift      = "netpolicy.drift.detected"
	ActionUnbackedRule        = "netpolicy.rule.unbacked"
	ActionDigestDrift         = "instance.digest_drift.detected"
	ActionPostureDrift        = "instance.posture_drift.detected"
	ActionRestartAttempted    = "instance.restart.attempted"
	ActionMarkedFailed        = "instance.marked_failed"
	ActionRoutePublished      = "proxy.route.published"
	ActionRouteRemoved        = "proxy.route.removed"
	ActionRuntimeVersionAdded = "runtime_version.registered"
	ActionRuntimePinned       = "instance.runtime.pinned"
	ActionRecovered           = "controlplane.recovered"
)

// Pipeline actions: packages, grants, backups, ownership transfer
// and control-plane authentication (§14.4's "what is audited" list).
const (
	ActionReleaseUploaded     = "release.uploaded"
	ActionReleaseDeployed     = "release.deployed"
	ActionReleaseDeployFailed = "release.deploy.failed"
	ActionReleaseRolledBack   = "release.rolled_back"
	ActionReleaseDownloaded   = "release.downloaded"
	ActionBackupCreated       = "backup.created"
	ActionBackupRestored      = "backup.restored"
	ActionBackupDeleted       = "backup.deleted"
	ActionBackupSwept         = "backup.retention.swept"
	ActionBackupStoppedCopy   = "backup.live_copy.stopped_instance"
	ActionGrantRequested      = "grant.requested"
	ActionGrantAutoApproved   = "grant.auto_approved"
	ActionGrantApproved       = "grant.approved"
	ActionGrantDenied         = "grant.denied"
	ActionGrantRevoked        = "grant.revoked"
	ActionTransferOffered     = "tenant.owner.transfer_offered"
	ActionTransferDeclined    = "tenant.owner.transfer_declined"
	ActionTransferCancelled   = "tenant.owner.transfer_cancelled"
	ActionTokenCreated        = "auth.token.created"
	ActionTokenRevoked        = "auth.token.revoked"
	ActionCredentialSet       = "auth.credential.set"
	ActionLoginSucceeded      = "auth.login.succeeded"
	ActionLoginFailed         = "auth.login.failed"
	ActionLogout              = "auth.logout"
)

// Egress actions: enforcement and quarantine.
//
// ActionEgressDenied is written at most once per tenant per reconcile tick,
// carrying a count. One event per refusal would let a hook in a retry loop
// write the audit chain as fast as it can open sockets, which is a
// denial-of-service against the one table that must never be truncated
// .
const (
	ActionEgressACLReloaded     = "egress.acl.reloaded"
	ActionEgressACLTampered     = "egress.acl.tampered"
	ActionEgressACLUnbacked     = "egress.acl.unbacked"
	ActionEgressDenied          = "egress.denied"
	ActionEgressEnforced        = "egress.enforced"
	ActionEgressWithdrawn       = "egress.withdrawn"
	ActionEgressAddressAssigned = "egress.address.assigned"
	ActionTenantQuarantined     = "tenant.quarantined"
	ActionTenantFrozen          = "tenant.frozen"
	ActionTenantUnfrozen        = "tenant.unfrozen"
	ActionTenantUnquarantined   = "tenant.unquarantined"
)

// Runtime upgrade actions (§12).
//
// The ladder is audited at every transition rather than only at its ends,
// because a job that stops moving is exactly the case a human has to reconstruct
// afterwards: an `upgrade.applied` with no `upgrade.succeeded` and no
// `upgrade.rolled_back` says a one-way migration ran and nothing confirmed it.
//
// ActionUpgradeRehearsalResidue is separate from a failed rehearsal on purpose.
// A rehearsal that fails is a normal, useful outcome; a rehearsal that fails to
// clean itself up has left a container, a network or a mount behind, and that
// is an operator's problem rather than the tenant's.
const (
	ActionUpgradeRequested        = "upgrade.requested"
	ActionUpgradeBlocked          = "upgrade.blocked"
	ActionUpgradeRehearsalStarted = "upgrade.rehearsal.started"
	ActionUpgradeRehearsalPassed  = "upgrade.rehearsal.passed"
	ActionUpgradeRehearsalFailed  = "upgrade.rehearsal.failed"
	ActionUpgradeRehearsalResidue = "upgrade.rehearsal.residue"
	ActionUpgradeApplied          = "upgrade.applied"
	ActionUpgradeSucceeded        = "upgrade.succeeded"
	ActionUpgradeRolledBack       = "upgrade.rolled_back"
	ActionUpgradeFailed           = "upgrade.failed"
	ActionUpgradeAbandoned        = "upgrade.abandoned"
	ActionVersionStateChanged     = "runtime_version.state_changed"
	ActionEOLNagged               = "runtime_version.eol.nagged"
	ActionEOLForceScheduled       = "runtime_version.eol.force_upgrade_scheduled"
	ActionEOLQuarantined          = "runtime_version.eol.quarantined"
)

// Accountability actions (§14.3–§14.6).
//
// ActionEnforcementWithoutGrant is deliberately its own action rather than an
// attestation with a field set. It is the one outcome that pages someone, and
// an alert rule that has to parse a detail field to find out whether it fired is
// an alert rule that will one day not fire.
//
// The data-access actions are what make the platform's own reads visible to the
// tenant they concern. A platform that reads a customer's database and records
// only that it "generated a report" has an audit log that is technically
// complete and practically useless.
const (
	ActionAttestationGenerated    = "attestation.generated"
	ActionEnforcementWithoutGrant = "attestation.enforcement_without_grant"
	ActionBreakglassOpened        = "grant.breakglass.opened"
	ActionBreakglassReviewed      = "grant.breakglass.reviewed"
	ActionGrantsInherited         = "tenant.owner.grants_inherited"
	ActionGrantReaffirmed         = "grant.reaffirmed"
	ActionGrantReaffirmLapsed     = "grant.reaffirm.lapsed"
	ActionGrantExpired            = "grant.expired"
	ActionDataRead                = "data.pb_data.read"
	ActionBackupDownloaded        = "data.backup.downloaded"
	ActionLogRead                 = "data.log.read"
	ActionImpersonationStarted    = "data.impersonation.started"
	ActionInstanceAdminOpened     = "tenant.instance_admin.opened"
	ActionAuditExported           = "audit.exported"
	ActionAuditAnchored           = "audit.anchored"
	ActionOwnerForceTransferred   = "tenant.owner.force_transferred"
	ActionNotificationSent        = "notification.sent"
)

// DataAccessActions are the actions that constitute a platform read of a
// tenant's data, which is what GET /tenants/:id/access-log serves (§14.6).
//
// A named set rather than a prefix match: the tenant's own view of "who looked
// at my data" must not silently change shape because somebody added an action
// under the same namespace.
var DataAccessActions = []string{
	ActionDataRead,
	ActionBackupDownloaded,
	ActionLogRead,
	ActionImpersonationStarted,
	ActionBreakglassOpened,
	ActionBackupRestored,
}

// Event is one thing that happened, as the caller describes it. seq, hashes and
// the id are assigned by Append.
type Event struct {
	OccurredAt time.Time
	ActorID    string
	ActorKind  string
	OnBehalfOf string // set during impersonation; empty otherwise
	TenantID   string // empty for platform-wide events
	Action     string
	SubjectRef string // a reference, NEVER a payload
	Detail     map[string]any
	RequestID  string
	SourceIP   string
}

// Record is a persisted audit row.
type Record struct {
	Seq        int64          `json:"seq"`
	ID         string         `json:"id"`
	OccurredAt time.Time      `json:"occurred_at"`
	ActorID    string         `json:"actor_id"`
	ActorKind  string         `json:"actor_kind"`
	OnBehalfOf string         `json:"on_behalf_of,omitempty"`
	TenantID   string         `json:"tenant_id,omitempty"`
	Action     string         `json:"action"`
	SubjectRef string         `json:"subject_ref,omitempty"`
	Detail     map[string]any `json:"detail,omitempty"`
	RequestID  string         `json:"request_id,omitempty"`
	SourceIP   string         `json:"source_ip,omitempty"`
	PrevHash   string         `json:"prev_hash"`
	Hash       string         `json:"hash"`
	// HashVersion names the commitment Hash was computed under (see
	// chainHashV2). Exported with the row so a recipient of a segment can
	// recompute it.
	HashVersion int `json:"hash_version"`
}

// Hash versions.
const (
	// HashV1 commits to seq, occurred_at, actor_id, action, subject_ref,
	// detail_json and prev_hash only. Rows written before migration 006.
	HashV1 = 1
	// HashV2 commits to every column of the row. Every row since.
	HashV2 = 2
)

// Logger appends to the chain.
type Logger struct{}

// New returns a Logger. It holds no state: the chain head lives in the table,
// read inside the caller's transaction, so two Loggers cannot disagree.
func New() *Logger { return &Logger{} }

var errNoTx = errors.New("auditlog: Append requires the transaction of the state change it records")

// Append writes ev into tx, chained onto the current head.
//
// tx must be the same transaction as the state change being recorded. Append
// reads the head and inserts inside it, so a crash can never leave a state
// change without its event, or an event without its state change.
func (l *Logger) Append(ctx context.Context, tx bun.Tx, ev Event) (Record, error) {

	// bun.Tx is a value type, so a caller can hand over a zero one. The
	// embedded *sql.Tx is what tells a real transaction from that.
	if tx.Tx == nil {

		return Record{}, errNoTx
	}
	if ev.ActorID == "" || ev.ActorKind == "" {

		return Record{}, fmt.Errorf("auditlog: %s has no actor; automated actions use the platform principal", ev.Action)
	}
	if ev.Action == "" {

		return Record{}, errors.New("auditlog: event has no action")
	}
	if ev.OccurredAt.IsZero() {

		ev.OccurredAt = time.Now().UTC()
	}
	ev.OccurredAt = ev.OccurredAt.UTC().Truncate(time.Microsecond)

	detail, err := encodeDetail(ev.Detail)
	if err != nil {

		return Record{}, err
	}

	prevSeq, prevHash, err := head(ctx, tx)
	if err != nil {

		return Record{}, err
	}

	rec := Record{
		Seq:         prevSeq + 1,
		ID:          newID(),
		OccurredAt:  ev.OccurredAt,
		ActorID:     ev.ActorID,
		ActorKind:   ev.ActorKind,
		OnBehalfOf:  ev.OnBehalfOf,
		TenantID:    ev.TenantID,
		Action:      ev.Action,
		SubjectRef:  ev.SubjectRef,
		Detail:      ev.Detail,
		RequestID:   ev.RequestID,
		SourceIP:    ev.SourceIP,
		PrevHash:    prevHash,
		HashVersion: HashV2,
	}
	rec.Hash = chainHashV2(rowFields(rec, detail))

	_, err = tx.ExecContext(ctx, `
		INSERT INTO audit_event (seq, id, occurred_at, actor_id, actor_kind, on_behalf_of,
		                         tenant_id, action, subject_ref, detail_json, request_id,
		                         source_ip, prev_hash, hash, hash_version)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		rec.Seq, rec.ID, rec.OccurredAt.Format(tsLayout), rec.ActorID, rec.ActorKind,
		nullable(rec.OnBehalfOf), nullable(rec.TenantID), rec.Action, nullable(rec.SubjectRef),
		nullable(detail), nullable(rec.RequestID), nullable(rec.SourceIP), rec.PrevHash, rec.Hash,
		rec.HashVersion)
	if err != nil {

		return Record{}, fmt.Errorf("auditlog: insert %s: %w", rec.Action, err)
	}
	return rec, nil
}

const tsLayout = "2006-01-02T15:04:05.999999Z"

func head(ctx context.Context, tx bun.Tx) (int64, string, error) {

	var seq int64
	var hash string
	err := tx.QueryRowContext(ctx,
		`SELECT seq, hash FROM audit_event ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	switch {

	case errors.Is(err, sql.ErrNoRows):
		return 0, GenesisHash, nil
	case err != nil:
		return 0, "", err
	}
	return seq, hash, nil
}

// chainHash implements the v1 §14.4 commitment, which rows written before
// migration 006 are verified under:
//
//	hash = H(seq ‖ occurred_at ‖ actor_id ‖ action ‖ subject_ref ‖ detail_json ‖ prev_hash)
//
// Fields are length-prefixed rather than concatenated, so no value containing a
// separator can be arranged to produce another row's hash.
func chainHash(seq int64, occurredAt time.Time, actorID, action, subjectRef, detailJSON, prevHash string) string {

	h := sha256.New()
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(seq))
	h.Write(n[:])
	for _, f := range []string{occurredAt.Format(tsLayout), actorID, action, subjectRef, detailJSON, prevHash} {

		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		h.Write(n[:])
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fields is one row as the chain commits to it, with absent values as "".
// The table stores "" as NULL and every reader COALESCEs it back, so the two
// are one value by construction and need no separate encoding.
type fields struct {
	seq                                                 int64
	occurredAt                                          string // tsLayout
	id, actorID, actorKind, onBehalfOf, tenantID        string
	action, subjectRef, detailJSON, requestID, sourceIP string
	prevHash                                            string
}

func rowFields(r Record, detailJSON string) fields {

	return fields{
		seq: r.Seq, occurredAt: r.OccurredAt.Format(tsLayout), id: r.ID,
		actorID: r.ActorID, actorKind: r.ActorKind, onBehalfOf: r.OnBehalfOf, tenantID: r.TenantID,
		action: r.Action, subjectRef: r.SubjectRef, detailJSON: detailJSON,
		requestID: r.RequestID, sourceIP: r.SourceIP, prevHash: r.PrevHash,
	}
}

// v2Domain separates the v2 commitment from v1's. Without it a v1 hash input
// could, in principle, be arranged to collide with a v2 one.
const v2Domain = "citadel-audit-v2\x00"

// chainHashV2 commits to every column of the row, length-prefixed in a fixed
// order:
//
//	hash = H("citadel-audit-v2\0" ‖ seq ‖ occurred_at ‖ id ‖ actor_id ‖ actor_kind ‖
//	         on_behalf_of ‖ tenant_id ‖ action ‖ subject_ref ‖ detail_json ‖
//	         request_id ‖ source_ip ‖ prev_hash)
//
// tenant_id decides which tenant's access log (§14.6) shows a row, and
// on_behalf_of is the only trace of an impersonation; v1 left both editable.
func chainHashV2(f fields) string {

	h := sha256.New()
	h.Write([]byte(v2Domain))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(f.seq))
	h.Write(n[:])
	for _, v := range []string{
		f.occurredAt, f.id, f.actorID, f.actorKind, f.onBehalfOf, f.tenantID,
		f.action, f.subjectRef, f.detailJSON, f.requestID, f.sourceIP, f.prevHash,
	} {

		binary.BigEndian.PutUint64(n[:], uint64(len(v)))
		h.Write(n[:])
		h.Write([]byte(v))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// hashFor recomputes a stored row's hash under the version it claims.
func hashFor(version int, f fields, occurredAt time.Time) (string, error) {

	switch version {

	case HashV1:
		return chainHash(f.seq, occurredAt, f.actorID, f.action, f.subjectRef, f.detailJSON, f.prevHash), nil
	case HashV2:
		return chainHashV2(f), nil
	}
	return "", fmt.Errorf("unknown hash version %d", version)
}

func newID() string {

	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {

		panic("auditlog: crypto/rand failed: " + err.Error())
	}
	return "ae-" + hex.EncodeToString(b[:])
}

func nullable(s string) any {

	if s == "" {

		return nil
	}
	return s
}

// secretish matches detail keys that must never reach an audit row. Audit rows
// outlive tenant data by design, so a secret or a payload in detail_json is a
// direct contradiction of the deletion promise in D10 (§14.4).
var secretish = regexp.MustCompile(`(?i)(key|token|password|passwd|secret|credential|cookie|authorization)`)

// ErrDetailRejected is returned when a caller tries to put something in
// detail_json that must not be recorded.
var ErrDetailRejected = errors.New("auditlog: detail rejected")

const maxDetailValue = 512

func encodeDetail(detail map[string]any) (string, error) {

	if len(detail) == 0 {

		return "", nil
	}
	keys := make([]string, 0, len(detail))
	for k := range detail {

		if secretish.MatchString(k) {

			return "", fmt.Errorf("%w: key %q looks like a secret; record a reference, not the value", ErrDetailRejected, k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Encode deterministically: the hash commits to this string, so map
	// iteration order must not affect it.
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {

		v := detail[k]
		if s, ok := v.(string); ok && len(s) > maxDetailValue {

			return "", fmt.Errorf("%w: value for %q is %d bytes; audit rows hold subject refs, never payloads",
				ErrDetailRejected, k, len(s))
		}
		kj, err := json.Marshal(k)
		if err != nil {

			return "", err
		}
		vj, err := json.Marshal(v)
		if err != nil {

			return "", fmt.Errorf("%w: value for %q is not encodable: %v", ErrDetailRejected, k, err)
		}
		if len(vj) > maxDetailValue {

			return "", fmt.Errorf("%w: value for %q encodes to %d bytes; audit rows hold subject refs, never payloads",
				ErrDetailRejected, k, len(vj))
		}
		if i > 0 {

			b.WriteByte(',')
		}
		b.Write(kj)
		b.WriteByte(':')
		b.Write(vj)
	}
	b.WriteByte('}')
	return b.String(), nil
}
