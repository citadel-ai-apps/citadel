package docker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/stdcopy"
)

// maxExecStderr bounds what is kept of an exec's stderr for the error message.
// The process runs inside a tenant sandbox, so its output is hostile input.
const maxExecStderr = 16 << 10

// PbsnapPath is the in-sandbox copier shipped in pb-hardened from h2 on.
const PbsnapPath = "/pb/pbsnap"

// Snapshot streams a live copy of one database in pb_data to w, by running the
// platform's pbsnap inside the tenant's running sandbox.
//
// This is the ONLY exec into a live tenant container (INV-9), and it is not a
// general one: the program is fixed and the only argument is a bare database
// name. Under runsc `docker exec` runs inside the SAME gVisor sandbox as
// PocketBase, which is the point: a process there shares PocketBase's view of
// fcntl locks, and the host does not (design.md INV-20).
func (d *Driver) Snapshot(ctx context.Context, spec driver.InstanceSpec, dbName string, w io.Writer) error {

	if !driver.ValidDBName(dbName) {

		return fmt.Errorf("docker: %q is not a database name in pb_data", dbName)
	}
	return d.exec(ctx, spec, []string{PbsnapPath, dbName}, w)
}

func (d *Driver) exec(ctx context.Context, spec driver.InstanceSpec, argv []string, w io.Writer) error {

	created, err := d.cli.ContainerExecCreate(ctx, spec.Name, container.ExecOptions{
		Cmd:          argv,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {

		return fmt.Errorf("docker: exec create in %s: %w", spec.Name, err)
	}
	att, err := d.cli.ContainerExecAttach(ctx, created.ID, container.ExecAttachOptions{})
	if err != nil {

		return fmt.Errorf("docker: exec attach in %s: %w", spec.Name, err)
	}
	defer att.Close()

	// Close the hijacked connection if the caller gives up, or StdCopy would
	// block on a sandbox that stopped writing.
	stop := context.AfterFunc(ctx, att.Close)
	defer stop()

	stderr := &capped{max: maxExecStderr}
	_, copyErr := stdcopy.StdCopy(w, stderr, att.Reader)
	if ctx.Err() != nil {

		return ctx.Err()
	}

	insp, err := d.cli.ContainerExecInspect(ctx, created.ID)
	if err != nil {

		return fmt.Errorf("docker: exec inspect in %s: %w", spec.Name, err)
	}
	msg := strings.TrimSpace(stderr.String())
	switch {

	case insp.Running:
		return fmt.Errorf("docker: exec in %s still running after its output closed", spec.Name)

	// 126/127 are the runtime failing to start argv[0], not the program
	// exiting: the image predates the binary.
	case insp.ExitCode == 126 || insp.ExitCode == 127:
		return fmt.Errorf("%w: %s in %s: %s", driver.ErrExecNotFound, argv[0], spec.Name, msg)

	case insp.ExitCode != 0:
		return fmt.Errorf("docker: %s in %s exited %d: %s", argv[0], spec.Name, insp.ExitCode, msg)

	case copyErr != nil:
		return fmt.Errorf("docker: exec output from %s: %w", spec.Name, copyErr)
	}
	return nil
}

// capped keeps the first max bytes written to it and discards the rest.
type capped struct {
	bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {

	if room := c.max - c.Len(); room > 0 {

		if len(p) > room {

			c.Buffer.Write(p[:room])

		} else {

			c.Buffer.Write(p)
		}
	}
	return len(p), nil
}
