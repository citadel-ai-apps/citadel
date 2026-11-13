package attest

import (
	"context"
	"sort"
	"strings"

	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// Observed is what the host showed. Nothing in it is reconstructed from the
// control-plane database.
type Observed struct {
	// Reachable is the set of hostnames the RUNNING egress proxy will let this
	// tenant's address connect to. Empty with ProxyReadable false means the
	// question could not be asked, which is not the same as "nothing".
	Reachable     []string `json:"reachable"`
	ProxyACL      string   `json:"proxy_acl_source"`
	ProxyReadable bool     `json:"proxy_readable"`

	Networks      []string             `json:"networks"`
	Rules         []netpolicy.Observed `json:"rules"`
	RulesReadable bool                 `json:"rules_readable"`
	BindMounts    []string             `json:"bind_mounts"`
	PublishedPort []string             `json:"published_ports"`
	ImageDigest   string               `json:"image_digest"`
	ContainerID   string               `json:"container_id,omitempty"`
	Running       bool                 `json:"running"`
	EdgeRouted    bool                 `json:"edge_routed"`
	ObserveErrors []string             `json:"observe_errors,omitempty"`
}

// observe collects everything the host can say about one tenant.
//
// Every read is best-effort and records its own failure rather than aborting.
// An attestation that refuses to produce a report because one source was
// unreachable is an attestation that stops running exactly when something is
// wrong — and the ProxyReadable / RulesReadable flags exist so a partial
// observation can never be mistaken for an empty one.
func (s *Service) observe(ctx context.Context, t store.Tenant) Observed {

	obs := Observed{ProxyACL: "squid manager (running proxy)"}

	if rules, err := s.net.Observe(); err != nil {

		obs.ObserveErrors = append(obs.ObserveErrors, "firewall: "+err.Error())

	} else {

		obs.RulesReadable = true
		for _, r := range rules {

			if r.Fields["tenant"] == t.ID {

				obs.Rules = append(obs.Rules, r)
			}
		}
	}

	if acls, err := s.egress.LiveACL(ctx); err != nil {

		obs.ObserveErrors = append(obs.ObserveErrors, "egress proxy: "+err.Error())

	} else {

		obs.ProxyReadable = true
		// The proxy names tenants by their ACL-safe id, so match on the same
		// transformation rather than on the raw id.
		key := egressACLName(t.ID)
		obs.Reachable = append(obs.Reachable, acls[key]...)
		sort.Strings(obs.Reachable)
	}

	if routes, err := s.proxy.RouteIDs(ctx); err != nil {

		obs.ObserveErrors = append(obs.ObserveErrors, "edge: "+err.Error())

	} else {

		obs.EdgeRouted = routes[t.Slug]
	}

	s.observeContainer(ctx, t, &obs)
	return obs
}

func (s *Service) observeContainer(ctx context.Context, t store.Tenant, obs *Observed) {

	insp, err := s.docker.ContainerInspect(ctx, config.ContainerName(t.Slug))
	if err != nil {

		obs.ObserveErrors = append(obs.ObserveErrors, "container: "+err.Error())
		return
	}
	obs.ContainerID = insp.ID
	if insp.State != nil {

		obs.Running = insp.State.Running
	}
	if insp.Image != "" {

		obs.ImageDigest = insp.Image
	}
	for _, m := range insp.Mounts {

		mode := "rw"
		if !m.RW {

			mode = "ro"
		}
		obs.BindMounts = append(obs.BindMounts, m.Source+":"+m.Destination+":"+mode)
	}
	sort.Strings(obs.BindMounts)

	if insp.NetworkSettings != nil {

		for name := range insp.NetworkSettings.Networks {

			obs.Networks = append(obs.Networks, name)
		}
		sort.Strings(obs.Networks)
		// Published ports must be empty. A tenant port on the host is a DNAT
		// rule and a path around the host firewall's INPUT chain, so finding one
		// is not drift to reconcile but access nobody granted.
		for port, binds := range insp.NetworkSettings.Ports {

			for _, b := range binds {

				obs.PublishedPort = append(obs.PublishedPort,
					b.HostIP+":"+b.HostPort+"->"+string(port))
			}
		}
		sort.Strings(obs.PublishedPort)
	}
}

// egressACLName mirrors egressctl.TenantACL.ACLName. Duplicated rather than
// exported across the boundary because the attestation must compare against
// what the proxy WROTE, and a shared helper that both sides changed together
// would hide a rename that broke the mapping.
func egressACLName(tenantID string) string {

	var b strings.Builder
	for _, r := range tenantID {

		switch {

		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)

		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
