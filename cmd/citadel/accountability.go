package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// attest is the §14.5 surface: what the HOST says a tenant can reach.
//
// `show` reads the last stored report; `generate` goes back to the host. The
// distinction matters during an incident — a stored report is what was true at
// its timestamp, and the question mid-incident is what is true now.
func (c *client) attest(ctx context.Context, args []string) error {

	if len(args) == 0 {

		return errors.New("attest needs a subcommand: show|generate")
	}
	sub, rest := args[0], args[1:]

	switch sub {

	case "show":
		if len(rest) == 0 {

			return c.printGet(ctx, "/api/v1/admin/attestations", renderMismatches)
		}
		return c.printGet(ctx, "/api/v1/tenants/"+rest[0]+"/attestation", renderAttestation)

	case "generate":
		slug, err := one(rest, "attest generate")
		if err != nil {

			return err
		}
		raw, status, err := c.do(ctx, http.MethodPost, "/api/v1/admin/tenants/"+slug+"/attestation", nil)
		if err != nil {

			return err
		}
		if err := c.emit(raw, renderAttestation); err != nil {

			return err
		}
		if status != http.StatusOK {

			// Non-zero exit so CI and operators can gate on it: enforcement
			// with no grant behind it is a security alert, not a result.
			return errors.New("attestation found enforcement with no grant behind it")
		}
		return nil

	default:
		return fmt.Errorf("unknown attest subcommand %q", sub)
	}
}

// breakglass is Tier-3 access (§14.3).
//
// The CLI states the terms rather than assuming the operator remembers them:
// the box is hard, the reason reaches the tenant verbatim, and the tenant is
// told at grant time rather than at review time.
func (c *client) breakglass(ctx context.Context, args []string) error {

	if len(args) == 0 {

		return errors.New("breakglass needs a subcommand: open|review|list")
	}
	sub, rest := args[0], args[1:]

	switch sub {

	case "list":
		return c.printGet(ctx, "/api/v1/admin/breakglass", renderBreakglass)

	case "open":
		var slug, reason, scope, kind string
		for i := 0; i < len(rest); i++ {

			var err error
			switch rest[i] {

			case "--reason":
				reason, err = next(rest, &i, "--reason")
			case "--scope":
				scope, err = next(rest, &i, "--scope")
			case "--kind":
				kind, err = next(rest, &i, "--kind")
			default:
				if slug != "" {

					err = fmt.Errorf("unexpected argument %q", rest[i])

				} else {

					slug = rest[i]
				}
			}
			if err != nil {

				return err
			}
		}
		if slug == "" {

			return errors.New("breakglass open needs <slug>")
		}
		if reason == "" {

			return errors.New("breakglass open needs --reason: it is shown to the tenant verbatim")
		}
		raw, err := c.call(ctx, http.MethodPost, "/api/v1/admin/tenants/"+slug+"/breakglass",
			map[string]string{"reason": reason, "scope": scope, "kind": kind})
		if err != nil {

			return err
		}
		return c.emit(raw, renderBreakglassOpen)

	case "review":
		var gid, outcome, notes string
		for i := 0; i < len(rest); i++ {

			var err error
			switch rest[i] {

			case "--outcome":
				outcome, err = next(rest, &i, "--outcome")
			case "--notes":
				notes, err = next(rest, &i, "--notes")
			default:
				if gid != "" {

					err = fmt.Errorf("unexpected argument %q", rest[i])

				} else {

					gid = rest[i]
				}
			}
			if err != nil {

				return err
			}
		}
		if gid == "" || outcome == "" || notes == "" {

			return errors.New("breakglass review needs <grant-id> --outcome justified|unjustified --notes <text>")
		}
		raw, err := c.call(ctx, http.MethodPost, "/api/v1/admin/grants/"+gid+"/review",
			map[string]string{"outcome": outcome, "notes": notes})
		if err != nil {

			return err
		}
		return c.emit(raw, func([]byte) error {

			fmt.Printf("reviewed %s: %s\n", gid, outcome)
			fmt.Println("  the operator who opened it can open break-glass again")
			return nil
		})

	default:
		return fmt.Errorf("unknown breakglass subcommand %q", sub)
	}
}
