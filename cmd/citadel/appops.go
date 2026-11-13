package main

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ---- releases and deploys --------------------------------------------------

func (c *client) release(ctx context.Context, args []string) error {

	if len(args) == 0 {

		return errors.New("release needs a subcommand: upload|list|download")
	}
	sub, args := args[0], args[1:]

	switch sub {

	case "upload":
		return c.releaseUpload(ctx, args)
	case "list":
		slug, err := one(args, "list")
		if err != nil {

			return err
		}
		return c.printGet(ctx, "/api/v1/tenants/"+slug+"/releases", renderReleases)
	case "download":
		return c.releaseDownload(ctx, args)
	default:
		return fmt.Errorf("unknown release subcommand %q", sub)
	}
}

// releaseDownload fetches the zip a release was uploaded as. The file is
// written beside its destination and renamed into place, so a failed or
// interrupted download never leaves a truncated zip under the final name.
func (c *client) releaseDownload(ctx context.Context, args []string) error {

	var pos []string
	out := ""
	for i := 0; i < len(args); i++ {

		var err error
		switch args[i] {

		case "-o", "--output":
			out, err = next(args, &i, args[i])
		default:
			pos = append(pos, args[i])
		}
		if err != nil {

			return err
		}
	}
	if len(pos) != 2 {

		return errors.New("release download needs <slug> <rid>")
	}
	slug, rid := pos[0], pos[1]
	path := "/api/v1/tenants/" + slug + "/releases/" + rid + "/download"

	if out == "-" {

		return c.download(ctx, path, os.Stdout)
	}
	if out == "" {

		out = rid + ".zip"
	}
	tmp, err := os.CreateTemp(filepath.Dir(out), "."+filepath.Base(out)+".part-*")
	if err != nil {

		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if err := c.download(ctx, path, tmp); err != nil {

		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {

		return err
	}
	if err := os.Rename(tmp.Name(), out); err != nil {

		return err
	}
	fmt.Fprintln(os.Stderr, "wrote "+out)
	return nil
}

func (c *client) releaseUpload(ctx context.Context, args []string) error {

	var slug, file, appDir string
	deploy := false
	for i := 0; i < len(args); i++ {

		var err error
		switch args[i] {

		case "--file":
			file, err = next(args, &i, "--file")
		case "--app-dir":
			appDir, err = next(args, &i, "--app-dir")
		case "--deploy":
			deploy = true
		default:
			if strings.HasPrefix(args[i], "-") || slug != "" {

				err = fmt.Errorf("unexpected argument %q", args[i])

			} else {

				slug = args[i]
			}
		}
		if err != nil {

			return err
		}
	}
	if slug == "" {

		return errors.New("release upload needs a tenant")
	}
	if (file == "") == (appDir == "") {

		return errors.New("release upload needs exactly one of --file <pkg.zip> or --app-dir <dir>")
	}
	if c.principal == "" {

		return errors.New("no acting principal: pass --as, or set $CITADEL_PRINCIPAL")
	}

	var body io.Reader
	name := filepath.Base(file)
	if appDir != "" {

		// Zipping here rather than adding a directory upload path to the API:
		// the wire format is one zip (§6), and a directory on the daemon's host
		// is not the same directory the operator is looking at.
		tmp, err := zipDir(appDir)
		if err != nil {

			return err
		}
		defer os.Remove(tmp.Name())
		defer tmp.Close()
		body, name = tmp, filepath.Base(appDir)+".zip"

	} else {

		f, err := os.Open(file)
		if err != nil {

			return err
		}
		defer f.Close()
		body = f
	}

	raw, err := c.upload(ctx, "/api/v1/tenants/"+slug+"/releases", name, body)
	if err != nil {

		return err
	}
	var rel struct {
		ID     string `json:"id"`
		Sha256 string `json:"sha256"`
	}
	if err := c.emit(raw, func(b []byte) error { return renderRelease(b, &rel) }); err != nil {

		return err
	}
	if !deploy {

		return nil
	}
	if rel.ID == "" {

		if err := decodeInto(raw, &rel); err != nil {

			return err
		}
	}
	return c.runDeploy(ctx, slug, "/api/v1/tenants/"+slug+"/releases/"+rel.ID+"/deploy", nil)
}

// deploy handles both `citadel deploy` and `citadel rollback`, which run the same
// §8.5 ladder and differ only in which release they target.
func (c *client) deploy(ctx context.Context, args []string, rollback bool) error {

	var slug, releaseID string
	for i := 0; i < len(args); i++ {

		var err error
		switch args[i] {

		case "--release":
			releaseID, err = next(args, &i, "--release")
		default:
			if strings.HasPrefix(args[i], "-") || slug != "" {

				err = fmt.Errorf("unexpected argument %q", args[i])

			} else {

				slug = args[i]
			}
		}
		if err != nil {

			return err
		}
	}
	if slug == "" {

		return errors.New("needs a tenant")
	}
	if c.principal == "" {

		return errors.New("no acting principal: pass --as, or set $CITADEL_PRINCIPAL")
	}
	if rollback {

		var body any
		if releaseID != "" {

			body = map[string]string{"release_id": releaseID}
		}
		return c.runDeploy(ctx, slug, "/api/v1/tenants/"+slug+"/rollback", body)
	}
	if releaseID == "" {

		return errors.New("deploy needs --release <rid>; `citadel release list <slug>` shows them")
	}
	return c.runDeploy(ctx, slug, "/api/v1/tenants/"+slug+"/releases/"+releaseID+"/deploy", nil)
}

// runDeploy prints the deploy report whether it succeeded or not.
//
// A failed deploy answers 422 with the whole report — which step broke, the
// snapshot the data came back from, the container logs — so the error path
// prints that rather than only the one-line message.
func (c *client) runDeploy(ctx context.Context, slug, path string, body any) error {

	raw, status, err := c.do(ctx, http.MethodPost, path, body)
	if err != nil {

		return err
	}
	if status/100 != 2 && status != http.StatusUnprocessableEntity {

		return serverError(raw, status, http.MethodPost, path)
	}
	if renderErr := c.emit(raw, renderDeploy); renderErr != nil {

		return renderErr
	}
	if status == http.StatusUnprocessableEntity {

		return fmt.Errorf("%s: deploy failed", slug)
	}
	return nil
}

// zipDir packs a tenant package directory into a temporary zip.
func zipDir(dir string) (*os.File, error) {

	info, err := os.Stat(dir)
	if err != nil {

		return nil, err
	}
	if !info.IsDir() {

		return nil, fmt.Errorf("--app-dir %s is not a directory", dir)
	}
	tmp, err := os.CreateTemp("", "citadel-pkg-*.zip")
	if err != nil {

		return nil, err
	}
	zw := zip.NewWriter(tmp)
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {

		if err != nil {

			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {

			return err
		}
		if rel == "." {

			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {

			return nil
		}
		// The daemon validates the package properly (§6). This only skips the
		// editor droppings that would otherwise fail that validation after the
		// upload, which is a worse place to learn about them.
		if base := filepath.Base(rel); strings.HasPrefix(base, ".") {

			return nil
		}
		w, err := zw.Create(rel)
		if err != nil {

			return err
		}
		f, err := os.Open(path)
		if err != nil {

			return err
		}
		defer f.Close()
		_, err = io.Copy(w, f)
		return err
	})
	if err != nil {

		_ = zw.Close()
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, err
	}
	if err := zw.Close(); err != nil {

		return nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {

		return nil, err
	}
	return tmp, nil
}

// ---- backups ---------------------------------------------------------------

func (c *client) backup(ctx context.Context, args []string) error {

	if len(args) == 0 {

		return errors.New("backup needs a subcommand: list|create|restore")
	}
	sub, args := args[0], args[1:]
	if sub == "restore" {

		// Two positionals, unlike list and create, so it does not go through
		// one().
		return c.backupRestore(ctx, args)
	}
	slug, err := one(args, sub)
	if err != nil {

		return err
	}
	switch sub {

	case "list":
		return c.printGet(ctx, "/api/v1/tenants/"+slug+"/backups", renderBackups)
	case "create":
		raw, err := c.call(ctx, http.MethodPost, "/api/v1/tenants/"+slug+"/backups", nil)
		if err != nil {

			return err
		}
		return c.emit(raw, func(b []byte) error {

			var out struct {
				ID        string `json:"id"`
				SizeBytes int64  `json:"size_bytes"`
				Path      string `json:"path"`
			}
			if err := decodeInto(b, &out); err != nil {

				return err
			}
			fmt.Printf("%s: snapshot %s (%s)\n  %s\n", slug, out.ID, humanBytes(uint64(out.SizeBytes)), out.Path)
			return nil
		})
	default:
		return fmt.Errorf("unknown backup subcommand %q", sub)
	}
}

// ---- egress and grants -----------------------------------------------------

func (c *client) egress(ctx context.Context, args []string) error {

	slug, err := one(args, "egress")
	if err != nil {

		return err
	}
	return c.printGet(ctx, "/api/v1/tenants/"+slug+"/egress", renderEgress)
}

// quarantine flips the edge onto a 503 for one tenant, or back off it (§12).
//
// The data is untouched and the container is left alone: this is an ingress
// decision, which is what makes it usable mid-incident when a forced upgrade —
// the other half of §12 — would be too slow and too destructive.
func (c *client) quarantine(ctx context.Context, args []string, on bool) error {

	verb := "quarantine"
	method := http.MethodPost
	if !on {

		verb, method = "unquarantine", http.MethodDelete
	}

	var slug, reason string
	for i := 0; i < len(args); i++ {

		var err error
		switch args[i] {

		case "--reason":
			reason, err = next(args, &i, "--reason")
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
	if slug == "" {

		return fmt.Errorf("%s needs a tenant slug", verb)
	}
	if on && reason == "" {

		// Shown to the tenant verbatim. Making someone's application
		// unreachable with no stated cause is the kind of unattributed action
		// §14 exists to make impossible.
		return errors.New("quarantine needs --reason: it is shown to the tenant verbatim")
	}

	var body any
	if on {

		body = map[string]string{"reason": reason}
	}
	raw, err := c.call(ctx, method, "/api/v1/admin/tenants/"+slug+"/quarantine", body)
	if err != nil {

		return err
	}
	return c.emit(raw, func(b []byte) error {

		var out struct {
			Quarantined bool `json:"quarantined"`
			Changed     bool `json:"changed"`
		}
		if err := decodeInto(b, &out); err != nil {

			return err
		}
		switch {

		case !out.Changed:
			fmt.Printf("%s was already %s\n", slug, stateWord(out.Quarantined))
		case out.Quarantined:
			fmt.Printf("%s is quarantined: the edge now returns 503. Data and container untouched.\n", slug)
		default:
			fmt.Printf("%s is serving again\n", slug)
		}
		return nil
	})
}

// unfreeze lifts the §14.5 freeze an enforcement_without_grant attestation
// put on a tenant. The reason records that the investigation is over.
func (c *client) unfreeze(ctx context.Context, args []string) error {

	var slug, reason string
	for i := 0; i < len(args); i++ {

		var err error
		switch args[i] {

		case "--reason":
			reason, err = next(args, &i, "--reason")
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
	if slug == "" || reason == "" {

		return errors.New("unfreeze needs a tenant slug and --reason")
	}
	raw, err := c.call(ctx, http.MethodDelete, "/api/v1/admin/tenants/"+slug+"/freeze",
		map[string]string{"reason": reason})
	if err != nil {

		return err
	}
	return c.emit(raw, func(b []byte) error {

		var out struct {
			Changed bool `json:"changed"`
		}
		if err := decodeInto(b, &out); err != nil {

			return err
		}
		if out.Changed {

			fmt.Printf("%s is no longer frozen\n", slug)

		} else {

			fmt.Printf("%s was not frozen\n", slug)
		}
		return nil
	})
}

func stateWord(quarantined bool) string {

	if quarantined {

		return "quarantined"
	}
	return "serving"
}

func (c *client) grant(ctx context.Context, args []string) error {

	if len(args) == 0 {

		return errors.New("grant needs a subcommand: list|revoke|reaffirm|approve|deny")
	}
	sub, args := args[0], args[1:]

	switch sub {

	case "list":
		var slug, decision string
		for i := 0; i < len(args); i++ {

			var err error
			switch args[i] {

			case "--decision":
				decision, err = next(args, &i, "--decision")
			default:
				slug = args[i]
			}
			if err != nil {

				return err
			}
		}
		if slug == "" {

			// No tenant means the platform-wide queue, which is what an
			// operator wants: pending grants rot unseen (§15).
			return c.printGet(ctx, "/api/v1/admin/grants"+query(map[string]string{"decision": decision}), renderGrantQueue)
		}
		return c.printGet(ctx, "/api/v1/tenants/"+slug+"/grants"+query(map[string]string{"decision": decision}), renderGrants)

	case "revoke":
		if len(args) != 2 {

			return errors.New("grant revoke needs <slug> <grant-id>")
		}
		raw, err := c.call(ctx, http.MethodDelete, "/api/v1/tenants/"+args[0]+"/grants/"+args[1], nil)
		if err != nil {

			return err
		}
		return c.emit(raw, func([]byte) error {

			fmt.Printf("%s: revoked %s\n", args[0], args[1])
			fmt.Println("  re-requesting this subject later needs a human decision, whatever its tier")
			return nil
		})

	case "reaffirm":
		if len(args) != 2 {

			return errors.New("grant reaffirm needs <slug> <grant-id>")
		}
		raw, err := c.call(ctx, http.MethodPost,
			"/api/v1/tenants/"+args[0]+"/grants/"+args[1]+"/reaffirm", nil)
		if err != nil {

			return err
		}
		return c.emit(raw, func([]byte) error {

			fmt.Printf("%s: re-affirmed %s\n", args[0], args[1])
			return nil
		})

	case "approve", "deny":
		return c.grantDecide(ctx, sub, args)
	default:
		return fmt.Errorf("unknown grant subcommand %q", sub)
	}
}

func (c *client) grantDecide(ctx context.Context, verb string, args []string) error {

	var gid, note string
	days := 0
	for i := 0; i < len(args); i++ {

		var err error
		switch args[i] {

		case "--justification", "--reason":
			note, err = next(args, &i, args[i])
		case "--days":
			var v string
			if v, err = next(args, &i, "--days"); err == nil {

				days, err = strconv.Atoi(v)
			}
		default:
			if gid != "" {

				err = fmt.Errorf("unexpected argument %q", args[i])

			} else {

				gid = args[i]
			}
		}
		if err != nil {

			return err
		}
	}
	if gid == "" {

		return fmt.Errorf("grant %s needs a grant id", verb)
	}
	if note == "" {

		return fmt.Errorf("grant %s needs --justification/--reason: it is recorded and shown to the tenant", verb)
	}
	body := map[string]any{}
	if verb == "approve" {

		body["justification"] = note

	} else {

		body["reason"] = note
	}
	if days > 0 {

		body["expires_in_days"] = days
	}
	raw, err := c.call(ctx, http.MethodPost, "/api/v1/admin/grants/"+gid+"/"+verb, body)
	if err != nil {

		return err
	}
	return c.emit(raw, func(b []byte) error {

		var g struct {
			Subject  string `json:"subject"`
			Decision string `json:"decision"`
			TenantID string `json:"tenant_id"`
		}
		if err := decodeInto(b, &g); err != nil {

			return err
		}
		fmt.Printf("%s: %s %s\n", g.TenantID, g.Decision, g.Subject)
		return nil
	})
}

// ---- ownership -------------------------------------------------------------

func (c *client) owner(ctx context.Context, args []string) error {

	if len(args) == 0 {

		return errors.New("owner needs a subcommand: transfer|accept|decline|cancel")
	}
	sub, args := args[0], args[1:]

	if sub == "transfer" {

		var slug, to, reason string
		for i := 0; i < len(args); i++ {

			var err error
			switch args[i] {

			case "--to":
				to, err = next(args, &i, "--to")
			case "--reason":
				reason, err = next(args, &i, "--reason")
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
		if slug == "" || to == "" {

			return errors.New("owner transfer needs <slug> --to <principal>")
		}
		raw, err := c.call(ctx, http.MethodPost, "/api/v1/tenants/"+slug+"/owner/transfer",
			map[string]string{"to": to, "reason": reason})
		if err != nil {

			return err
		}
		return c.emit(raw, func([]byte) error {

			fmt.Printf("%s: offered to %s\n", slug, to)
			fmt.Println("  ownership moves when they accept, and not before")
			if reason != "" {

				// An operator can reassign a tenant they do not own, but not
				// quietly: the reason lands in the tenant's own feed.
				fmt.Println("  the tenant has been told, with your reason verbatim")
			}
			return nil
		})
	}

	slug, err := one(args, sub)
	if err != nil {

		return err
	}
	switch sub {

	case "accept", "decline", "cancel":
		raw, err := c.call(ctx, http.MethodPost, "/api/v1/tenants/"+slug+"/owner/"+sub, nil)
		if err != nil {

			return err
		}
		return c.emit(raw, func([]byte) error {

			fmt.Printf("%s: transfer %sed\n", slug, strings.TrimSuffix(sub, "e"))
			return nil
		})
	default:
		return fmt.Errorf("unknown owner subcommand %q", sub)
	}
}

// ---- tokens ----------------------------------------------------------------

func (c *client) token(ctx context.Context, args []string) error {

	if len(args) == 0 {

		return errors.New("token needs a subcommand: create|list|revoke")
	}
	sub, args := args[0], args[1:]

	switch sub {

	case "create":
		var principal, name string
		days := 0
		for i := 0; i < len(args); i++ {

			var err error
			switch args[i] {

			case "--principal":
				principal, err = next(args, &i, "--principal")
			case "--name":
				name, err = next(args, &i, "--name")
			case "--days":
				var v string
				if v, err = next(args, &i, "--days"); err == nil {

					days, err = strconv.Atoi(v)
				}
			default:
				err = fmt.Errorf("unknown flag %q", args[i])
			}
			if err != nil {

				return err
			}
		}
		if principal == "" || name == "" {

			return errors.New("token create needs --principal <id> --name <label>")
		}
		body := map[string]any{"principal": principal, "name": name}
		if days > 0 {

			body["expires_in_days"] = days
		}
		raw, err := c.call(ctx, http.MethodPost, "/api/v1/admin/tokens", body)
		if err != nil {

			return err
		}
		return c.emit(raw, renderToken)

	case "list":
		var principal string
		for i := 0; i < len(args); i++ {

			var err error
			switch args[i] {

			case "--principal":
				principal, err = next(args, &i, "--principal")
			default:
				err = fmt.Errorf("unknown flag %q", args[i])
			}
			if err != nil {

				return err
			}
		}
		return c.printGet(ctx, "/api/v1/admin/tokens"+query(map[string]string{"principal": principal}), renderTokens)

	case "revoke":
		id, err := one(args, "revoke")
		if err != nil {

			return err
		}
		raw, err := c.call(ctx, http.MethodDelete, "/api/v1/admin/tokens/"+id, nil)
		if err != nil {

			return err
		}
		return c.emit(raw, func([]byte) error {

			fmt.Printf("revoked %s\n", id)
			return nil
		})
	default:
		return fmt.Errorf("unknown token subcommand %q", sub)
	}
}

// setPassword is the portal bootstrap: a principal with no credential cannot
// sign in, and the socket is the only place an operator can set one.
func (c *client) setPassword(ctx context.Context, args []string) error {

	var id, password string
	for i := 0; i < len(args); i++ {

		var err error
		switch args[i] {

		case "--password":
			password, err = next(args, &i, "--password")
		default:
			if id != "" {

				err = fmt.Errorf("unexpected argument %q", args[i])

			} else {

				id = args[i]
			}
		}
		if err != nil {

			return err
		}
	}
	if id == "" {

		return errors.New("principal set-password needs a principal id")
	}
	if password == "" {

		password = os.Getenv("CITADEL_PASSWORD")
	}
	if password == "" {

		return errors.New("pass --password <secret> or set $CITADEL_PASSWORD")
	}
	raw, err := c.call(ctx, http.MethodPost, "/api/v1/admin/principals/"+id+"/password",
		map[string]string{"password": password})
	if err != nil {

		return err
	}
	return c.emit(raw, func([]byte) error {

		fmt.Printf("%s: portal password set\n", id)
		return nil
	})
}
