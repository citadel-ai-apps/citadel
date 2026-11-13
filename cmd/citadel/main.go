// Command citadel is the operator CLI: a thin HTTP client over the control
// plane's unix socket (design §8.4).
//
// It holds no state and talks to no database. Every mutation goes through the
// daemon, which is the single writer of state.db and therefore the single writer
// of the audit chain.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/api"
	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/identity"
)

func main() {

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {

		fmt.Fprintln(os.Stderr, "citadel:", err)
		os.Exit(1)
	}
}

const usage = `citadel — control-plane CLI

  citadel tenant create --slug <slug> --pb-version <ver> [--owner <principal>] [--app-dir <dir>]
  citadel tenant list
  citadel tenant status <slug>
  citadel tenant start|stop|restart <slug>
  citadel tenant resize <slug> --mem-mib <MiB>
  citadel tenant destroy <slug> [--no-backup] [--purge]
  citadel tenant logs <slug> [--follow] [--tail N]
  citadel tenant owner <slug>
  citadel tenant upgrade <slug> --to <ver> [--rehearse-only] [--no-rehearse] [--force] [--watch]
  citadel tenant upgrade-status <slug> [<jobid>]
  citadel tenant pin-runtime <slug> --to <ver> --justification <text>

  citadel release upload <slug> (--file <pkg.zip> | --app-dir <dir>) [--deploy]
  citadel release list <slug>
  citadel release download <slug> <rid> [-o <file>|-]
  citadel deploy <slug> --release <rid>
  citadel rollback <slug> [--release <rid>]

  citadel backup list <slug>
  citadel backup create <slug>
  citadel backup restore <slug> <bid> [--force]

  citadel egress <slug>
  citadel quarantine <slug> --reason <text>
  citadel unquarantine <slug>
  citadel unfreeze <slug> --reason <text>
  citadel grant list <slug> [--decision pending|approved|denied]
  citadel grant revoke <slug> <gid>
  citadel grant approve <gid> --justification <text> [--days N]
  citadel grant deny <gid> --reason <text>
  citadel grant reaffirm <slug> <gid>

  citadel owner transfer <slug> --to <principal> [--reason <text>]
  citadel owner accept|decline|cancel <slug>
  citadel principal suspend <id> [--reassign-to-platform]

  citadel attest show [<slug>]
  citadel attest generate <slug>
  citadel breakglass list
  citadel breakglass open <slug> --reason <text> [--scope <what>]
  citadel breakglass review <gid> --outcome justified|unjustified --notes <text>

  citadel token create --principal <id> --name <label> [--days N]
  citadel token list [--principal <id>]
  citadel token revoke <id>
  citadel principal set-password <id> --password <secret>

  citadel principal create <id> [--name <display>] [--email <addr>]
  citadel principal list

  citadel runtime-version add <ver> [--digest <ref>] [--state current|supported|deprecated|eol]
  citadel runtime-version list
  citadel runtime-version set-state <ver> --state <s> [--eol-at YYYY-MM-DD]

  citadel audit query [--tenant <id>] [--actor <id>] [--action <name|family.>] [--limit N]
  citadel audit verify
  citadel audit export [--tenant <id>]
  citadel fleet

Global flags:
  --socket <path>   control-plane socket (default %s)
  --as <principal>  acting principal; else $CITADEL_PRINCIPAL, else person:$SUDO_USER
  --json            print raw JSON instead of a table
`

func run(ctx context.Context, args []string) error {

	g, rest, err := parseGlobal(args)
	if err != nil {

		return err
	}
	if len(rest) == 0 {

		fmt.Printf(usage, config.Default().SocketPath)
		return nil
	}
	c := &client{socket: g.socket, principal: g.principal, json: g.json}

	switch rest[0] {

	case "tenant":
		return c.tenant(ctx, rest[1:])
	case "principal":
		return c.principalCmd(ctx, rest[1:])
	case "runtime-version":
		return c.runtimeVersion(ctx, rest[1:])
	case "audit":
		return c.audit(ctx, rest[1:])
	case "release":
		return c.release(ctx, rest[1:])
	case "deploy":
		return c.deploy(ctx, rest[1:], false)
	case "rollback":
		return c.deploy(ctx, rest[1:], true)
	case "backup":
		return c.backup(ctx, rest[1:])
	case "egress":
		return c.egress(ctx, rest[1:])
	case "quarantine":
		return c.quarantine(ctx, rest[1:], true)
	case "unquarantine":
		return c.quarantine(ctx, rest[1:], false)
	case "unfreeze":
		return c.unfreeze(ctx, rest[1:])
	case "grant":
		return c.grant(ctx, rest[1:])
	case "owner":
		return c.owner(ctx, rest[1:])
	case "token":
		return c.token(ctx, rest[1:])
	case "attest":
		return c.attest(ctx, rest[1:])
	case "breakglass":
		return c.breakglass(ctx, rest[1:])
	case "fleet":
		return c.printGet(ctx, "/api/v1/admin/fleet", renderFleet)
	case "help", "-h", "--help":
		fmt.Printf(usage, config.Default().SocketPath)
		return nil
	default:
		return fmt.Errorf("unknown command %q (try `citadel help`)", rest[0])
	}
}

type globals struct {
	socket    string
	principal string
	json      bool
}

// parseGlobal pulls the global flags out from anywhere in the argument list, so
// `citadel --json tenant list` and `citadel tenant list --json` both work.
func parseGlobal(args []string) (globals, []string, error) {

	g := globals{socket: config.Default().SocketPath}
	if v := os.Getenv("CITADEL_SOCKET"); v != "" {

		g.socket = v
	}
	var rest []string
	for i := 0; i < len(args); i++ {

		switch args[i] {

		case "--socket":
			v, err := next(args, &i, "--socket")
			if err != nil {

				return g, nil, err
			}
			g.socket = v
		case "--as":
			v, err := next(args, &i, "--as")
			if err != nil {

				return g, nil, err
			}
			g.principal = v
		case "--json":
			g.json = true
		default:
			rest = append(rest, args[i])
		}
	}
	if g.principal == "" {

		g.principal = defaultPrincipal()
	}
	return g, rest, nil
}

// defaultPrincipal derives the acting principal when none is named.
//
// $SUDO_USER is the real human behind a `sudo citadel`, which is exactly what the
// audit log needs. If there is no such user, the field is left empty and the
// daemon rejects the mutation — it never falls back to the platform principal,
// because that would attribute a person's action to the platform (§14.1).
func defaultPrincipal() string {

	if v := os.Getenv("CITADEL_PRINCIPAL"); v != "" {

		return v
	}
	for _, env := range []string{"SUDO_USER", "USER", "LOGNAME"} {

		if v := os.Getenv(env); v != "" && v != "root" {

			return identity.CanonicalID(identity.KindPerson, strings.ToLower(v))
		}
	}
	return ""
}

func next(args []string, i *int, flag string) (string, error) {

	if *i+1 >= len(args) {

		return "", fmt.Errorf("%s needs a value", flag)
	}
	*i++
	return args[*i], nil
}

type client struct {
	socket    string
	principal string
	json      bool
}

func (c *client) http() *http.Client {

	return &http.Client{
		Timeout: 5 * time.Minute, // provisioning waits for a tenant's first boot
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {

				var d net.Dialer
				return d.DialContext(ctx, "unix", c.socket)
			},
		},
	}
}

func (c *client) do(ctx context.Context, method, path string, body any) ([]byte, int, error) {

	var rdr io.Reader
	if body != nil {

		b, err := json.Marshal(body)
		if err != nil {

			return nil, 0, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://controlplane"+path, rdr)
	if err != nil {

		return nil, 0, err
	}
	if body != nil {

		req.Header.Set("Content-Type", "application/json")
	}
	if c.principal != "" {

		req.Header.Set(api.PrincipalHeader, c.principal)
	}
	resp, err := c.http().Do(req)
	if err != nil {

		return nil, 0, fmt.Errorf("cannot reach the control plane at %s: %w "+
			"(is controlplaned running, and are you root?)", c.socket, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	return raw, resp.StatusCode, err
}

// upload posts a package as multipart/form-data.
//
// The zip is streamed through a pipe rather than buffered: the §6 cap is 50 MiB
// and there is no reason for the CLI to hold that in memory on a host that is
// also running every tenant.
func (c *client) upload(ctx context.Context, path, filename string, body io.Reader) ([]byte, error) {

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {

		part, err := mw.CreateFormFile(api.PackageField, filename)
		if err == nil {

			_, err = io.Copy(part, body)
		}
		if err != nil {

			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.CloseWithError(mw.Close())
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://controlplane"+path, pr)
	if err != nil {

		return nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if c.principal != "" {

		req.Header.Set(api.PrincipalHeader, c.principal)
	}
	resp, err := c.http().Do(req)
	if err != nil {

		return nil, fmt.Errorf("cannot reach the control plane at %s: %w "+
			"(is controlplaned running, and are you root?)", c.socket, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {

		return nil, err
	}
	if resp.StatusCode/100 != 2 {

		return raw, serverError(raw, resp.StatusCode, "POST", path)
	}
	return raw, nil
}

// download streams a GET response body into w, never buffering it whole.
func (c *client) download(ctx context.Context, path string, w io.Writer) error {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://controlplane"+path, nil)
	if err != nil {

		return err
	}
	if c.principal != "" {

		req.Header.Set(api.PrincipalHeader, c.principal)
	}
	resp, err := c.http().Do(req)
	if err != nil {

		return fmt.Errorf("cannot reach the control plane at %s: %w "+
			"(is controlplaned running, and are you root?)", c.socket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {

		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return serverError(raw, resp.StatusCode, http.MethodGet, path)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

func serverError(raw []byte, status int, method, path string) error {

	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error != "" {

		return errors.New(e.Error)
	}
	return fmt.Errorf("%s %s: %s: %s", method, path, http.StatusText(status), strings.TrimSpace(string(raw)))
}

// call performs a request and turns a non-2xx into the server's error message.
func (c *client) call(ctx context.Context, method, path string, body any) ([]byte, error) {

	raw, status, err := c.do(ctx, method, path, body)
	if err != nil {

		return nil, err
	}
	if status/100 != 2 {

		return raw, serverError(raw, status, method, path)
	}
	return raw, nil
}

// printGet fetches and renders, honouring --json.
func (c *client) printGet(ctx context.Context, path string, render func([]byte) error) error {

	raw, err := c.call(ctx, http.MethodGet, path, nil)
	if err != nil {

		return err
	}
	return c.emit(raw, render)
}

func (c *client) emit(raw []byte, render func([]byte) error) error {

	if c.json || render == nil {

		return printJSON(raw)
	}
	return render(raw)
}

func printJSON(raw []byte) error {

	var v any
	if err := json.Unmarshal(raw, &v); err != nil {

		fmt.Println(strings.TrimSpace(string(raw)))
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func query(kv map[string]string) string {

	if len(kv) == 0 {

		return ""
	}
	v := url.Values{}
	for k, val := range kv {

		if val != "" {

			v.Set(k, val)
		}
	}
	if len(v) == 0 {

		return ""
	}
	return "?" + v.Encode()
}
