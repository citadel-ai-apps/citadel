package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/citadel-ai-apps/citadel/internal/api"
)

func (c *client) tenant(ctx context.Context, args []string) error {

	if len(args) == 0 {

		return errors.New("tenant needs a subcommand: create|list|status|start|stop|restart|resize|destroy|logs|owner|upgrade|upgrade-status|pin-runtime")
	}
	sub, args := args[0], args[1:]

	switch sub {

	case "create":
		return c.tenantCreate(ctx, args)
	case "list":
		return c.printGet(ctx, "/api/v1/admin/tenants", renderTenantList)
	case "status":
		slug, err := one(args, "status")
		if err != nil {

			return err
		}
		return c.printGet(ctx, "/api/v1/tenants/"+slug, renderTenantStatus)
	case "start", "stop", "restart":
		slug, err := one(args, sub)
		if err != nil {

			return err
		}
		raw, err := c.call(ctx, http.MethodPost, "/api/v1/tenants/"+slug+"/"+sub, nil)
		if err != nil {

			return err
		}
		return c.emit(raw, func([]byte) error {

			fmt.Printf("%s: %s requested\n", slug, sub)
			return nil
		})
	case "resize":
		return c.tenantResize(ctx, args)
	case "upgrade":
		return c.tenantUpgrade(ctx, args)
	case "upgrade-status":
		return c.upgradeStatus(ctx, args)
	case "pin-runtime":
		return c.tenantPinRuntime(ctx, args)
	case "destroy":
		return c.tenantDestroy(ctx, args)
	case "logs":
		return c.tenantLogs(ctx, args)
	case "owner":
		slug, err := one(args, "owner")
		if err != nil {

			return err
		}
		return c.printGet(ctx, "/api/v1/tenants/"+slug+"/owner", renderOwner)
	default:
		return fmt.Errorf("unknown tenant subcommand %q", sub)
	}
}

func (c *client) tenantCreate(ctx context.Context, args []string) error {

	var req api.CreateTenantRequest
	for i := 0; i < len(args); i++ {

		var err error
		switch args[i] {

		case "--slug":
			req.Slug, err = next(args, &i, "--slug")
		case "--pb-version":
			req.PBVersion, err = next(args, &i, "--pb-version")
		case "--owner":
			req.Owner, err = next(args, &i, "--owner")
		case "--app-dir":
			var dir string
			dir, err = next(args, &i, "--app-dir")
			if err == nil {

				// Resolved client-side: the daemon reads this path, and a
				// relative path would resolve against the daemon's cwd rather
				// than the operator's.
				req.AppDir, err = filepath.Abs(dir)
			}
		case "--disk-mib":
			var v string
			if v, err = next(args, &i, "--disk-mib"); err == nil {

				req.DiskMiB, err = strconv.Atoi(v)
			}
		case "--mem-mib":
			var v string
			if v, err = next(args, &i, "--mem-mib"); err == nil {

				req.MemMiB, err = strconv.Atoi(v)
			}
		case "--cpus":
			var v string
			if v, err = next(args, &i, "--cpus"); err == nil {

				req.CPUs, err = strconv.ParseFloat(v, 64)
			}
		case "--body-cap":
			req.BodyCap, err = next(args, &i, "--body-cap")
		default:
			err = fmt.Errorf("unknown flag %q", args[i])
		}
		if err != nil {

			return err
		}
	}
	if req.Slug == "" || req.PBVersion == "" {

		return errors.New("tenant create needs --slug and --pb-version")
	}
	if c.principal == "" {

		return errors.New("no acting principal: pass --as <principal> or set $CITADEL_PRINCIPAL " +
			"(every state change needs a real actor in the audit log)")
	}
	if req.AppDir != "" {

		if st, err := os.Stat(req.AppDir); err != nil || !st.IsDir() {

			return fmt.Errorf("--app-dir %s is not a directory", req.AppDir)
		}
	}
	raw, err := c.call(ctx, http.MethodPost, "/api/v1/admin/tenants", req)
	if err != nil {

		return err
	}
	return c.emit(raw, func(b []byte) error {

		t, err := decodeTenant(b)
		if err != nil {

			return printJSON(b)
		}
		fmt.Printf("created %s\n  hostname   %s\n  pb version %s\n  subnet     %s (tenant %s, edge %s)\n  digest     %s\n",
			t.ID, t.Hostname, t.RuntimeVersion, t.Subnet, t.ContainerIP, t.EdgeIP, t.ImageDigest)
		return nil
	})
}

func (c *client) tenantDestroy(ctx context.Context, args []string) error {

	var slug string
	body := api.DestroyRequest{}
	for _, arg := range args {

		switch arg {

		case "--no-backup":
			body.NoBackup = true
		case "--purge":
			body.Purge = true
		default:
			if slug != "" {

				return fmt.Errorf("unexpected argument %q", arg)
			}
			slug = arg
		}
	}
	if slug == "" {

		return errors.New("destroy needs a tenant")
	}
	raw, err := c.call(ctx, http.MethodDelete, "/api/v1/admin/tenants/"+slug, body)
	if err != nil {

		return err
	}
	return c.emit(raw, func([]byte) error {

		fmt.Printf("%s: marked for destruction; teardown happens on the next reconcile tick\n", slug)
		if body.Purge {

			fmt.Printf("%s: data image, mount point and encryption keys will be DESTROYED\n", slug)

		} else {

			fmt.Printf("%s: data is retained on disk (D10); pass --purge to destroy it\n", slug)
		}
		fmt.Printf("%s: audit rows are retained\n", slug)
		return nil
	})
}

func (c *client) tenantLogs(ctx context.Context, args []string) error {

	var slug, tail string
	follow := false
	for i := 0; i < len(args); i++ {

		switch args[i] {

		case "--follow", "-f":
			follow = true
		case "--tail":
			v, err := next(args, &i, "--tail")
			if err != nil {

				return err
			}
			tail = v
		default:
			slug = args[i]
		}
	}
	if slug == "" {

		return errors.New("logs needs a tenant")
	}
	q := map[string]string{"tail": tail}
	if follow {

		q["follow"] = "1"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://controlplane/api/v1/tenants/"+slug+"/logs"+query(q), nil)
	if err != nil {

		return err
	}
	if c.principal != "" {

		req.Header.Set(api.PrincipalHeader, c.principal)
	}
	resp, err := c.http().Do(req)
	if err != nil {

		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {

		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("logs: %s: %s", http.StatusText(resp.StatusCode), raw)
	}
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

func (c *client) principalCmd(ctx context.Context, args []string) error {

	if len(args) == 0 {

		return errors.New("principal needs a subcommand: create|list|suspend|set-password")
	}
	switch args[0] {

	case "suspend":
		// Orphan reclamation (§14.1). Without --reassign-to-platform the
		// suspension is REFUSED while this principal owns anything: INV-17 is
		// never broken, and an orphaned tenant becomes a visible backlog item
		// rather than a NULL nobody notices.
		var id string
		reassign := false
		for _, a := range args[1:] {

			switch a {

			case "--reassign-to-platform":
				reassign = true
			default:
				if id != "" {

					return fmt.Errorf("unexpected argument %q", a)
				}
				id = a
			}
		}
		if id == "" {

			return errors.New("principal suspend needs an id")
		}
		raw, err := c.call(ctx, http.MethodPost, "/api/v1/admin/principals/"+id+"/suspend",
			map[string]bool{"reassign_to_platform": reassign})
		if err != nil {

			return err
		}
		return c.emit(raw, func([]byte) error {

			fmt.Printf("%s: suspended\n", id)
			if reassign {

				fmt.Println("  their tenants now belong to the platform principal and are flagged")
				fmt.Println("  owner_orphaned in the fleet view; transfer them to a real owner")
			}
			return nil
		})

	case "set-password":
		return c.setPassword(ctx, args[1:])
	case "list":
		return c.printGet(ctx, "/api/v1/admin/principals", renderPrincipals)
	case "create":
		var req api.CreatePrincipalRequest
		rest := args[1:]
		for i := 0; i < len(rest); i++ {

			var err error
			switch rest[i] {

			case "--name":
				req.DisplayName, err = next(rest, &i, "--name")
			case "--email":
				req.Email, err = next(rest, &i, "--email")
			default:
				if req.ID != "" {

					err = fmt.Errorf("unexpected argument %q", rest[i])
				}
				req.ID = rest[i]
			}
			if err != nil {

				return err
			}
		}
		if req.ID == "" {

			return errors.New("principal create needs an id, e.g. person:alice or svc:ci")
		}
		raw, err := c.call(ctx, http.MethodPost, "/api/v1/admin/principals", req)
		if err != nil {

			return err
		}
		return c.emit(raw, func(b []byte) error {

			fmt.Printf("created principal %s\n", req.ID)
			return nil
		})
	default:
		return fmt.Errorf("unknown principal subcommand %q", args[0])
	}
}

func (c *client) runtimeVersion(ctx context.Context, args []string) error {

	if len(args) == 0 {

		return errors.New("runtime-version needs a subcommand: add|list|set-state")
	}
	switch args[0] {

	case "list":
		return c.printGet(ctx, "/api/v1/admin/runtime-versions", renderRuntimeVersions)
	case "set-state":
		return c.versionSetState(ctx, args[1:])
	case "add":
		var req api.AddRuntimeVersionRequest
		rest := args[1:]
		for i := 0; i < len(rest); i++ {

			var err error
			switch rest[i] {

			case "--digest":
				req.ImageDigest, err = next(rest, &i, "--digest")
			case "--state":
				req.State, err = next(rest, &i, "--state")
			case "--hardening-rev":
				var v string
				if v, err = next(rest, &i, "--hardening-rev"); err == nil {

					req.HardeningRev, err = strconv.Atoi(v)
				}
			case "--arch":
				req.Arch, err = next(rest, &i, "--arch")
			default:
				req.Version = rest[i]
			}
			if err != nil {

				return err
			}
		}
		if req.Version == "" {

			return errors.New("runtime-version add needs a version, e.g. 0.42.2")
		}
		raw, err := c.call(ctx, http.MethodPost, "/api/v1/admin/runtime-versions", req)
		if err != nil {

			return err
		}
		return c.emit(raw, func(b []byte) error {

			rv, err := decodeRuntimeVersion(b)
			if err != nil {

				return printJSON(b)
			}
			fmt.Printf("registered %s h%d -> %s (%s)\n", rv.Version, rv.HardeningRev, rv.ImageDigest, rv.State)
			return nil
		})
	default:
		return fmt.Errorf("unknown runtime-version subcommand %q", args[0])
	}
}

func (c *client) audit(ctx context.Context, args []string) error {

	if len(args) == 0 {

		return errors.New("audit needs a subcommand: query|verify|export")
	}
	switch args[0] {

	case "export":
		q := map[string]string{}
		rest := args[1:]
		for i := 0; i < len(rest); i++ {

			if rest[i] != "--tenant" {

				return fmt.Errorf("unknown flag %q", rest[i])
			}
			v, err := next(rest, &i, "--tenant")
			if err != nil {

				return err
			}
			q["tenant"] = v
		}
		// Raw JSON, always. An export is evidence handed to somebody else, and
		// a pretty-printed table is not something they can recompute a hash
		// chain from.
		raw, err := c.call(ctx, http.MethodGet, "/api/v1/admin/audit/export"+query(q), nil)
		if err != nil {

			return err
		}
		return printJSON(raw)

	case "verify":
		raw, status, err := c.do(ctx, http.MethodGet, "/api/v1/admin/audit/verify", nil)
		if err != nil {

			return err
		}
		if err := c.emit(raw, renderVerify); err != nil {

			return err
		}
		if status != http.StatusOK {

			// Non-zero exit so CI and operators can gate on it: a broken
			// chain is a security alert, not an informational result (design.md §15).
			return errors.New("audit chain verification FAILED")
		}
		return nil
	case "query":
		q := map[string]string{}
		rest := args[1:]
		for i := 0; i < len(rest); i++ {

			var err error
			var v string
			switch rest[i] {

			case "--tenant":
				v, err = next(rest, &i, "--tenant")
				q["tenant"] = v
			case "--actor":
				v, err = next(rest, &i, "--actor")
				q["actor"] = v
			case "--action":
				v, err = next(rest, &i, "--action")
				q["action"] = v
			case "--limit":
				v, err = next(rest, &i, "--limit")
				q["limit"] = v
			case "--since":
				v, err = next(rest, &i, "--since")
				q["since"] = v
			default:
				err = fmt.Errorf("unknown flag %q", rest[i])
			}
			if err != nil {

				return err
			}
		}
		return c.printGet(ctx, "/api/v1/admin/audit"+query(q), renderAudit)
	default:
		return fmt.Errorf("unknown audit subcommand %q", args[0])
	}
}

func one(args []string, cmd string) (string, error) {

	if len(args) != 1 {

		return "", fmt.Errorf("%s needs exactly one tenant", cmd)
	}
	return args[0], nil
}

// tenantResize changes a tenant's memory limit. The daemon only records it; the
// next reconcile tick recreates the container with the new limit, data intact.
func (c *client) tenantResize(ctx context.Context, args []string) error {

	var slug string
	mem := 0
	for i := 0; i < len(args); i++ {

		var err error
		switch args[i] {

		case "--mem-mib":
			var v string
			if v, err = next(args, &i, "--mem-mib"); err == nil {

				mem, err = strconv.Atoi(v)
			}
		default:
			if slug != "" {

				err = fmt.Errorf("unexpected argument %q", args[i])

			} else {

				slug = args[i]
			}
		}
		if err != nil {

			return err
		}
	}
	if slug == "" || mem == 0 {

		return errors.New("tenant resize needs a slug and --mem-mib")
	}

	raw, err := c.call(ctx, http.MethodPost, "/api/v1/admin/tenants/"+slug+"/resize", map[string]int{"mem_mib": mem})
	if err != nil {

		return err
	}
	return c.emit(raw, func(b []byte) error {

		var out struct {
			MemMiB     int  `json:"mem_mib"`
			FromMemMiB int  `json:"from_mem_mib"`
			Changed    bool `json:"changed"`
		}
		if err := decodeInto(b, &out); err != nil {

			return err
		}
		if !out.Changed {

			fmt.Printf("%s already has %d MiB\n", slug, out.MemMiB)
			return nil
		}
		fmt.Printf("%s: memory %d -> %d MiB; the container is recreated on the next reconcile tick\n",
			slug, out.FromMemMiB, out.MemMiB)
		return nil
	})
}
