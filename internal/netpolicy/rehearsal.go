package netpolicy

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"

	"github.com/citadel-ai-apps/citadel/internal/config"
)

// LabelRehearsal marks the Docker objects belonging to one rehearsal, so
// recovery can find them without the database.
const LabelRehearsal = "v2p.rehearsal"

// RehearsalSlug is the network slug for one rehearsal job.
//
// "rh" plus the job id's 8 hex characters is exactly config.MaxSlugLen, so the
// bridge is br-t-rh######## — 15 characters, inside IFNAMSIZ, and matching the
// `br-t-+` host-protection wildcard.
//
// Matching that wildcard is deliberate and not a side effect of the naming. A
// rehearsal boots the TENANT'S OWN hooks, which are hostile by assumption
// (INV-1); a bridge outside the wildcard would hand that code the container→host
// path the wildcard exists to close. The cost is that the control plane cannot
// dial a rehearsal either, which is why §12 requires a probe container on the
// rehearsal network rather than a health check from the host.
func RehearsalSlug(jobID string) string {

	id := jobID
	if _, rest, ok := strings.Cut(jobID, "-"); ok {

		id = rest
	}
	if len(id) > config.MaxSlugLen-2 {

		id = id[:config.MaxSlugLen-2]
	}
	return "rh" + id
}

// RehearsalTag is the comment on a rehearsal's firewall rule.
//
// Tagged `rehearsal=<job>` and deliberately NOT `tenant=<id>`. Two things
// depend on that: internal/attest builds a tenant's attestation by filtering
// rules on the tenant field, so a rehearsal cannot manufacture a mismatch
// against the tenant it is rehearsing for; and UnbackedRules classifies this
// rule against the job's liveness instead of the tenant's grant set, which is
// what makes a leaked rehearsal rule visible rather than silently accepted.
func RehearsalTag(jobID string, extra ...string) string {

	return Tag(append([]string{"rehearsal=" + jobID}, extra...)...)
}

// RehearsalRules is the whole rule set of a rehearsal network: one accept,
// from the probe to the rehearsal instance's PocketBase port, and nothing else.
//
// The accept is required rather than optional. Same-bridge traffic still
// traverses FORWARD and therefore DOCKER-USER, where the platform's
// unconditional RFC1918 denies would otherwise kill the probe container's
// connection to the rehearsal instance — both of them being on a private
// subnet. It is one direction and one port, exactly like a tenant's own
// ingress (IntraNetworkRule): the instance runs the tenant's hooks, which are
// hostile (INV-1), and must not be able to open connections to the probe.
// Replies ride the platform's ESTABLISHED accept. No egress accept is written
// for any grant the tenant holds, which is the firewall half of §12's
// "rehearsal runs with no egress at all".
func RehearsalRules(jobID string, in Ingress) []Rule {

	bridge := config.BridgeName(RehearsalSlug(jobID))
	return []Rule{{
		Chain: ChainDockerUser,
		Spec: []string{
			"-i", bridge,
			"-o", bridge,
			"-s", in.EdgeIP.String(),
			"-d", in.TenantIP.String(),
			"-p", "tcp", "--dport", config.PocketBasePort,
			"-m", "conntrack", "--ctstate", "NEW",
			"-j", "ACCEPT",
		},
		Comment: rehearsalComments(jobID)[0],
	}}
}

// rehearsalComments is every comment a rehearsal's rules have carried, so a
// teardown removes them by tag without needing the addresses they were
// written with. "intra-network" is the earlier bidirectional accept.
func rehearsalComments(jobID string) []string {

	return []string{RehearsalTag(jobID, "intra-network=probe"), RehearsalTag(jobID, "intra-network")}
}

// EnsureRehearsalNetwork creates the isolated network one rehearsal runs on.
//
// `internal: true`, like a tenant's own network and for the same reason: no
// outbound path at all, declared rather than filtered. Nothing joins it except
// the rehearsal instance and the probe.
func (m *Manager) EnsureRehearsalNetwork(ctx context.Context, jobID string, alloc Allocation) error {

	slug := RehearsalSlug(jobID)
	name := config.NetworkName(slug)
	if insp, err := m.docker.NetworkInspect(ctx, name, network.InspectOptions{}); err == nil {

		if err := checkNetwork(insp, true, config.BridgeName(slug), alloc.Subnet.String()); err != nil {

			return err
		}
		if insp.Labels[LabelRehearsal] != jobID {

			return fmt.Errorf("%w: %s is not labelled for rehearsal %s", ErrNetworkMismatch, name, jobID)
		}
		return nil

	} else if !client.IsErrNotFound(err) {

		return fmt.Errorf("netpolicy: inspect rehearsal network %s: %w", name, err)
	}
	_, err := m.docker.NetworkCreate(ctx, name, network.CreateOptions{
		Driver: "bridge",
		// Explicitly off: a daemon-wide default-network-opts change would
		// otherwise give this network IPv6 that no v6 rule covers.
		EnableIPv6: ptrBool(false),
		Internal:   true,
		IPAM: &network.IPAM{
			Driver: "default",
			Config: []network.IPAMConfig{{
				Subnet:  alloc.Subnet.String(),
				Gateway: alloc.GatewayIP.String(),
			}},
		},
		Options: map[string]string{
			"com.docker.network.bridge.name": config.BridgeName(slug),
		},
		Labels: map[string]string{
			LabelManaged:   "true",
			LabelRehearsal: jobID,
		},
	})
	if err != nil {

		return fmt.Errorf("netpolicy: create rehearsal network %s: %w", name, err)
	}
	return nil
}

// EnsureRehearsalRules writes the rehearsal's single accept. in names the
// probe (EdgeIP) and the rehearsal instance (TenantIP).
func (m *Manager) EnsureRehearsalRules(jobID string, in Ingress) ([]Change, error) {

	if !in.Valid() {

		return nil, fmt.Errorf("netpolicy: rehearsal %s has no valid probe and instance addresses", jobID)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	pos, err := m.insertPosition()
	if err != nil {

		return nil, err
	}
	var changes []Change
	for _, r := range RehearsalRules(jobID, in) {

		wrote, err := m.ipt.insert(r, pos)
		if err != nil {

			return changes, fmt.Errorf("netpolicy: rehearsal rules for %s: %w", jobID, err)
		}
		if wrote {

			changes = append(changes, Change{Rule: r})
		}
	}
	return changes, nil
}

// TeardownRehearsal removes a rehearsal's rules and its network.
//
// Rules are removed by comment tag, so this can never take out a tenant's rule
// or the shared host-protection rule. Both steps are attempted even when the
// first fails: leaving a network behind because a rule would not delete is how
// a subnet leaks.
func (m *Manager) TeardownRehearsal(ctx context.Context, jobID string) ([]Change, []string, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	var changes []Change
	var residue []string
	for _, comment := range rehearsalComments(jobID) {

		n, err := m.ipt.removeByComment(ChainDockerUser, comment, false)
		if err != nil {

			residue = append(residue, "rule "+comment+": "+err.Error())
			continue
		}
		if n > 0 {

			changes = append(changes, Change{Rule: Rule{Chain: ChainDockerUser, Comment: comment}, Removed: true})
		}
	}
	name := config.NetworkName(RehearsalSlug(jobID))
	if err := m.docker.NetworkRemove(ctx, name); err != nil && !client.IsErrNotFound(err) {

		residue = append(residue, "network "+name+": "+err.Error())
	}
	// Anything still tagged for this job after the removals above was not
	// written by RehearsalRules. Reported, never force-removed — the same rule
	// as every other unaccountable rule (§14.5).
	observed, err := m.Observe()
	if err != nil {

		return changes, residue, err
	}
	for _, o := range observed {

		if o.Fields["rehearsal"] == jobID {

			residue = append(residue, "unexpected rule "+o.Comment)
		}
	}
	return changes, residue, nil
}

// RehearsalNetworks maps job id to network name for every rehearsal network on
// the host, so a crashed job's leftovers can be found without the database.
func (m *Manager) RehearsalNetworks(ctx context.Context) (map[string]string, error) {

	nets, err := m.docker.NetworkList(ctx, network.ListOptions{})
	if err != nil {

		return nil, err
	}
	out := map[string]string{}
	for _, n := range nets {

		if n.Labels[LabelManaged] != "true" {

			continue
		}
		if job := n.Labels[LabelRehearsal]; job != "" {

			out[job] = n.Name
		}
	}
	return out, nil
}

// LiveSubnets reads the subnets Docker currently has allocated.
//
// A rehearsal subnet exists only on the host — there is no row for it — so the
// allocator's "already taken" set cannot come from the database alone. Reading
// the daemon also catches subnets a crashed rehearsal left behind, which are
// exactly the ones a fresh allocation must not collide with.
func (m *Manager) LiveSubnets(ctx context.Context) ([]netip.Prefix, error) {

	nets, err := m.docker.NetworkList(ctx, network.ListOptions{})
	if err != nil {

		return nil, err
	}
	var out []netip.Prefix
	for _, n := range nets {

		for _, c := range n.IPAM.Config {

			if c.Subnet == "" {

				continue
			}
			p, err := netip.ParsePrefix(c.Subnet)
			if err != nil || !p.Addr().Is4() {

				continue
			}
			out = append(out, p)
		}
	}
	return out, nil
}
