package docker

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
	"github.com/citadel-ai-apps/citadel/internal/pbauth"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

// EnsureSuperuser creates (or, from 0.23, upserts) a superuser account in a
// tenant's pb_data using a throwaway CLI container. The control plane uses it
// for the owner seat, with a password it discards.
//
// Three constraints shape this:
//
//   - It runs BEFORE the server ever starts, so there is never a second process
//     with pb_data open.
//   - It is a fresh container with `--network none`, not an exec into a live one
//
// . The image has no shell, so there is nothing to exec anyway.
//   - PocketBase 0.22.x's `admin create` fails on an uninitialised pb_data with
//     "Migration are not initialized yet" and still EXITS 0
//     (design.md §5). So pre-0.23 runs `migrate up` first, and the
//     exit code is never the success signal — the caller's later data-plane auth
//     call is (see health.go).
func (d *Driver) EnsureSuperuser(ctx context.Context, spec driver.InstanceSpec, pbVersion, email, password string) error {

	if pbauth.IsLegacy(pbVersion) {

		if out, err := d.oneShot(ctx, spec, "migrate", "up"); err != nil {

			return fmt.Errorf("docker: migrate up for %s: %w: %s", spec.TenantID, err, out)
		}
		out, err := d.oneShot(ctx, spec, "admin", "create", email, password)
		if err != nil {

			return fmt.Errorf("docker: admin create for %s: %w: %s", spec.TenantID, err, out)
		}
		return nil
	}
	out, err := d.oneShot(ctx, spec, "superuser", "upsert", email, password)
	if err != nil {

		return fmt.Errorf("docker: superuser upsert for %s: %w: %s", spec.TenantID, err, out)
	}
	return nil
}

// oneShot runs a PocketBase subcommand against the tenant's data and waits for
// it to finish, returning its combined output.
func (d *Driver) oneShot(ctx context.Context, spec driver.InstanceSpec, args ...string) (string, error) {

	if err := d.ensureImage(ctx, spec.ImageDigest); err != nil {

		return "", err
	}
	cmd := append([]string{}, args...)
	cmd = append(cmd, "--dir", DataMount, "--encryptionEnv", "PB_ENCRYPTION_KEY")

	env := make([]string, 0, len(spec.Env))
	for k, v := range spec.Env {

		env = append(env, k+"="+v)
	}

	cfg := &container.Config{
		Image: spec.ImageDigest,
		// The image ENTRYPOINT is `pocketbase serve …`; a CLI subcommand has to
		// replace it rather than be appended to it.
		Entrypoint: []string{"/pb/pocketbase"},
		Cmd:        cmd,
		Env:        env,
		// Labelled so recovery can find one a crash left behind: it has
		// pb_data open read-write, and must not outlive the lock (INV-3).
		Labels: map[string]string{netpolicy.LabelManaged: "true", LabelOneShot: spec.TenantID},
	}
	// The same ceilings as the instance: the one-shot runs the tenant's
	// pb_migrations against the tenant's data, which is tenant code (INV-1).
	mem := int64(spec.MemMiB) * 1024 * 1024
	pids := int64(spec.PidsLimit)
	host := &container.HostConfig{
		Binds:          []string{spec.DataDir + ":" + DataMount + ":rw"},
		ReadonlyRootfs: true,
		Tmpfs:          map[string]string{"/tmp": "rw,noexec,nosuid,size=64m"},
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges:true"},
		// No network at all: this container exists to touch a SQLite file.
		NetworkMode: "none",
		Runtime:     spec.Runtime,
		AutoRemove:  false, // removed explicitly, so its output can be read first
		LogConfig:   logConfig(spec),
	}
	if mem > 0 {

		host.Resources.Memory = mem
		host.Resources.MemorySwap = mem
	}
	if pids > 0 {

		host.Resources.PidsLimit = &pids
	}

	created, err := d.cli.ContainerCreate(ctx, cfg, host, nil, nil, "")
	if err != nil {

		return "", fmt.Errorf("docker: create one-shot: %w", err)
	}
	defer func() {

		// Not ctx: a caller that gave up (a client disconnect cancels a deploy)
		// would otherwise leave the container running with pb_data open after
		// the lock is released, and the next start would put a second process
		// on it (INV-3).
		_ = d.cli.ContainerRemove(context.WithoutCancel(ctx), created.ID, container.RemoveOptions{Force: true})
	}()

	if err := d.cli.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {

		return "", fmt.Errorf("docker: start one-shot: %w", err)
	}
	waitCh, errCh := d.cli.ContainerWait(ctx, created.ID, container.WaitConditionNotRunning)
	var code int64
	select {
	case err := <-errCh:
		return "", fmt.Errorf("docker: wait for one-shot: %w", err)
	case res := <-waitCh:
		code = res.StatusCode
	case <-ctx.Done():
		return "", ctx.Err()
	}

	out := d.oneShotLogs(ctx, created.ID)
	if code != 0 {

		return out, fmt.Errorf("one-shot %q exited %d", strings.Join(args, " "), code)
	}
	return out, nil
}

func (d *Driver) oneShotLogs(ctx context.Context, id string) string {

	rc, err := d.cli.ContainerLogs(ctx, id, container.LogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {

		return ""
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, 64<<10))
	if err != nil {

		return ""
	}
	return strings.TrimSpace(stripDockerStreamHeaders(b))
}

// stripDockerStreamHeaders removes the 8-byte multiplexing headers Docker
// prepends to each frame when a container has no TTY.
func stripDockerStreamHeaders(b []byte) string {

	var sb strings.Builder
	for len(b) >= 8 {

		n := int(b[4])<<24 | int(b[5])<<16 | int(b[6])<<8 | int(b[7])
		if n < 0 || 8+n > len(b) {

			sb.Write(b[8:])
			return sb.String()
		}
		sb.Write(b[8 : 8+n])
		b = b[8+n:]
	}
	sb.Write(b)
	return sb.String()
}

// LabelOneShot marks a throwaway CLI container with the tenant it ran for.
const LabelOneShot = "v2p.oneshot"

// RemoveOneShots force-removes every one-shot container. Called by recovery at
// start-up, when no one-shot can legitimately be running: one that is was left
// by a crash, still holding pb_data open (INV-3).
func (d *Driver) RemoveOneShots(ctx context.Context) ([]string, error) {

	list, err := d.cli.ContainerList(ctx, container.ListOptions{
		All: true, Filters: filters.NewArgs(filters.Arg("label", LabelOneShot)),
	})
	if err != nil {

		return nil, fmt.Errorf("docker: list one-shots: %w", err)
	}
	var removed []string
	for _, c := range list {

		if err := d.cli.ContainerRemove(ctx, c.ID, container.RemoveOptions{Force: true}); err != nil && !client.IsErrNotFound(err) {

			return removed, fmt.Errorf("docker: remove one-shot %s: %w", c.ID, err)
		}
		removed = append(removed, c.Labels[LabelOneShot])
	}
	return removed, nil
}

// RemoveOrphan force-removes a container by name, used by crash recovery.
func (d *Driver) RemoveOrphan(ctx context.Context, name string) error {

	err := d.cli.ContainerRemove(ctx, name, container.RemoveOptions{Force: true})
	if err == nil || client.IsErrNotFound(err) {

		return nil
	}
	return err
}
