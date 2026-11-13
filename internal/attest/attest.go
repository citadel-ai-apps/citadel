// Package attest builds a picture of a tenant's effective external access by
// inspecting the HOST, then diffs it against the grants (design §14.5).
//
// The direction matters more than anything else in here. An audit that reads
// the same table that generated the rules proves nothing: it would confirm that
// the control plane agrees with itself. So every observation in this package
// comes from the kernel's ruleset, the running proxies and the Docker daemon,
// and the database appears only on the other side of the comparison.
//
// The asymmetry between the two failure outcomes is the second load-bearing
// idea. A grant that is not in effect is a reliability problem, repaired on the
// next tick. A rule in effect with nothing behind it is either a platform bug
// or someone operating outside the control plane — so it is alerted, frozen and
// never silently repaired, because auto-removing it would destroy the evidence
// and hide a recurring intrusion behind a self-healing loop.
package attest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/docker/docker/client"
	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/config"
	dockerdrv "github.com/citadel-ai-apps/citadel/internal/driver/docker"
	"github.com/citadel-ai-apps/citadel/internal/egressctl"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
	"github.com/citadel-ai-apps/citadel/internal/proxyctl"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// Signer signs a report. hostfs.Signer satisfies it.
type Signer interface {
	Sign(payload []byte) string
	PublicKey() string
}

// Service generates and stores attestations.
type Service struct {
	cfg    config.Config
	db     *store.DB
	net    *netpolicy.Manager
	egress *egressctl.Controller
	proxy  *proxyctl.Controller
	docker client.APIClient
	signer Signer
	audit  *auditlog.Logger
	log    *slog.Logger
}

// Options bundles the Service's collaborators.
type Options struct {
	Config config.Config
	DB     *store.DB
	Net    *netpolicy.Manager
	Egress *egressctl.Controller
	Proxy  *proxyctl.Controller
	Docker client.APIClient
	Signer Signer
	Audit  *auditlog.Logger
	Log    *slog.Logger
}

// New returns a Service.
func New(o Options) *Service {

	return &Service{
		cfg: o.Config, db: o.DB, net: o.Net, egress: o.Egress, proxy: o.Proxy,
		docker: o.Docker, signer: o.Signer, audit: o.Audit, log: o.Log,
	}
}

// Finding is one thing the host and the grants disagree about.
type Finding struct {
	Kind     string `json:"kind"`               // egress_host, firewall_rule, published_port…
	GrantID  string `json:"grant_id,omitempty"` // empty when there is no grant behind it
	Subject  string `json:"subject"`
	Where    string `json:"where"` // proxy ACL, DOCKER-USER, container config
	Detail   string `json:"detail"`
	Security bool   `json:"security"` // true for enforcement_without_grant
}

// Report is the signed artefact. Everything in Observed came from the host.
type Report struct {
	TenantID    string    `json:"tenant_id"`
	Slug        string    `json:"slug"`
	GeneratedAt time.Time `json:"generated_at"`
	Outcome     string    `json:"outcome"`

	Observed  Observed  `json:"observed"`
	Grants    []Granted `json:"grants"`
	Findings  []Finding `json:"findings,omitempty"`
	PublicKey string    `json:"public_key"`
	Signature string    `json:"signature,omitempty"`
}

// Granted is one authorisation, as the database records it, alongside whether
// the host was seen to be enforcing it.
type Granted struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Direction  string     `json:"direction"`
	Subject    string     `json:"subject"`
	Tier       int        `json:"tier"`
	State      string     `json:"state"`
	DecidedBy  string     `json:"decided_by,omitempty"`
	DecidedAt  *time.Time `json:"decided_at,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Enforced   bool       `json:"enforced"`
	Enforcible bool       `json:"enforcible"`
}

// enforcible reports whether this platform has any machinery that could put a
// grant of this kind into effect.
//
// Only egress_host does today. The others are recorded, decided, expiring and
// attributable — but nothing generates a relay ACL or a scoped credential from
// them yet (D5). Saying so in the report is the honest answer: a grant the
// platform cannot enforce must not read as one it forgot to.
func enforcible(kind string) bool { return kind == store.GrantEgressHost }

// Generate builds, signs and stores one tenant's attestation.
func (s *Service) Generate(ctx context.Context, tenantID string) (Report, error) {

	t, err := store.GetTenant(ctx, s.db.Reader(), tenantID)
	if err != nil {

		return Report{}, err
	}
	grants, err := store.ListGrants(ctx, s.db.Reader(), store.GrantFilter{TenantID: tenantID})
	if err != nil {

		return Report{}, err
	}
	lapsed, err := store.LapsedGrantIDs(ctx, s.db.Reader(), time.Now().UTC())
	if err != nil {

		return Report{}, err
	}

	obs := s.observe(ctx, t)
	rep := Report{
		TenantID:    t.ID,
		Slug:        t.Slug,
		GeneratedAt: time.Now().UTC().Truncate(time.Second),
		Observed:    obs,
		PublicKey:   s.signer.PublicKey(),
	}
	rep.Grants, rep.Findings, rep.Outcome = diff(grants, lapsed, obs, expectation{
		TenantID:      t.ID,
		Network:       t.NetworkName,
		EgressNetwork: s.cfg.EgressNetwork,
		Mounts:        map[string]string{dockerdrv.DataMount: "rw", dockerdrv.AppMount: "ro"},
	})

	body, err := json.Marshal(rep)
	if err != nil {

		return Report{}, err
	}
	rep.Signature = s.signer.Sign(body)

	if err := s.persist(ctx, t, rep, body); err != nil {

		return Report{}, err
	}
	return rep, nil
}

// persist writes the row, the signed file and the audit event.
//
// The row and the audit event go in one transaction, per the rule that a state
// change and the record of it are never written separately. The file is written
// first: a file with no row is a duplicate next time, while a row claiming a
// signed report that was never written is a lie about evidence.
func (s *Service) persist(ctx context.Context, t store.Tenant, rep Report, body []byte) error {

	observed, err := json.Marshal(rep.Observed)
	if err != nil {

		return err
	}
	grants, err := json.Marshal(rep.Grants)
	if err != nil {

		return err
	}
	var mismatch []byte
	if len(rep.Findings) > 0 {

		if mismatch, err = json.Marshal(rep.Findings); err != nil {

			return err
		}
	}
	row := store.Attestation{
		ID:           store.NewID("at"),
		TenantID:     t.ID,
		GeneratedAt:  rep.GeneratedAt,
		ObservedJSON: string(observed),
		Outcome:      rep.Outcome,
		MismatchJSON: string(mismatch),
		GrantsJSON:   string(grants),
		Signature:    rep.Signature,
	}
	if err := s.writeFile(t.ID, row.ID, rep, body); err != nil {

		return err
	}
	return s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertAttestation(ctx, tx, row); err != nil {

			return err
		}
		action := auditlog.ActionAttestationGenerated
		if rep.Outcome == store.OutcomeEnforcementWithoutGrant {

			action = auditlog.ActionEnforcementWithoutGrant
		}
		if _, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID:    identity.PlatformPrincipal,
			ActorKind:  identity.KindPlatform,
			TenantID:   t.ID,
			Action:     action,
			SubjectRef: "attestation/" + row.ID,
			Detail:     map[string]any{"outcome": rep.Outcome, "findings": len(rep.Findings)},
		}); err != nil {

			return err
		}
		if rep.Outcome == store.OutcomeEnforcementWithoutGrant {

			// Frozen (§14.5): deploys, upgrades and grant changes are refused
			// until an operator lifts it, so the configuration under
			// investigation does not move. Set once; a later report does not
			// re-stamp the time it was first found.
			if t.FrozenReason == "" {

				if err := store.SetFrozen(ctx, tx, t.ID, "attestation/"+row.ID+": enforcement without grant"); err != nil {

					return err
				}
				if _, err := s.audit.Append(ctx, tx, auditlog.Event{
					ActorID: identity.PlatformPrincipal, ActorKind: identity.KindPlatform, TenantID: t.ID,
					Action: auditlog.ActionTenantFrozen, SubjectRef: "tenant/" + t.ID,
					Detail: map[string]any{"attestation": row.ID, "findings": len(rep.Findings)},
				}); err != nil {

					return err
				}
			}
			// Notified, not merely recorded. A security outcome that only an
			// operator polling the fleet view would ever see is one nobody sees.
			return store.Notify(ctx, tx, store.Notification{
				TenantID: t.ID, Audience: store.AudienceOperator,
				Kind: store.NotifyAttestationMismatch, SubjectRef: "attestation/" + row.ID,
				Body: fmt.Sprintf("%s has %d enforcement path(s) with no grant behind them. "+
					"The rules are deliberately NOT removed, and the tenant is frozen; investigate before touching them.",
					t.Slug, len(rep.Findings)),
			})
		}
		return nil
	})
}

func (s *Service) writeFile(tenantID, id string, rep Report, body []byte) error {

	dir := s.cfg.TenantAttestationDir(tenantID)
	if err := os.MkdirAll(dir, 0o700); err != nil {

		return err
	}
	// The signature covers `body`, so the file stores the signed bytes verbatim
	// alongside it rather than re-marshalling: a re-marshal with different key
	// ordering would produce a file whose signature does not check.
	envelope, err := json.MarshalIndent(struct {
		ID        string          `json:"id"`
		Signature string          `json:"signature"`
		PublicKey string          `json:"public_key"`
		Report    json.RawMessage `json:"report"`
	}{ID: id, Signature: rep.Signature, PublicKey: rep.PublicKey, Report: body}, "", "  ")
	if err != nil {

		return err
	}
	name := filepath.Join(dir, rep.GeneratedAt.Format("20060102T150405Z")+"-"+id+".json")
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, append(envelope, '\n'), 0o600); err != nil {

		return err
	}
	if err := os.Rename(tmp, name); err != nil {

		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Summarise strips the report down to what a tenant may see (D17).
//
// Full reports name bridge interfaces, chain positions, subnets and the proxy's
// address — platform topology handed to a party the model treats as hostile.
// What the tenant is owed is the accountability content: what it can reach, who
// authorised it, when that lapses, and whether the platform is enforcing what it
// said it would.
func Summarise(rep Report) Report {

	out := Report{
		TenantID: rep.TenantID, Slug: rep.Slug, GeneratedAt: rep.GeneratedAt,
		Outcome: rep.Outcome, Grants: rep.Grants,
		Observed: Observed{
			Reachable:     rep.Observed.Reachable,
			ProxyACL:      rep.Observed.ProxyACL,
			ProxyReadable: rep.Observed.ProxyReadable,
			EdgeRouted:    rep.Observed.EdgeRouted,
			Running:       rep.Observed.Running,
			PublishedPort: rep.Observed.PublishedPort,
		},
		PublicKey: rep.PublicKey, Signature: rep.Signature,
	}
	for _, f := range rep.Findings {

		// The finding is kept; only the location is dropped. A tenant should
		// learn that an approved host is not actually in effect without being
		// told which chain the missing rule belongs in.
		out.Findings = append(out.Findings, Finding{
			Kind: f.Kind, GrantID: f.GrantID, Subject: f.Subject,
			Detail: f.Detail, Security: f.Security,
		})
	}
	sort.Slice(out.Grants, func(i, j int) bool { return out.Grants[i].Subject < out.Grants[j].Subject })
	return out
}
