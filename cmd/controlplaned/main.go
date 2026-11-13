// Command controlplaned is the control plane: the reconciler, the driver,
// netpolicy, proxyctl and the single writer of the state database.
//
// It must run as root on the Docker host: it mounts loopback images, writes
// netfilter rules and chowns tenant data directories. It holds the Docker socket
// on the host side only — never mounted into any container.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/api"
	"github.com/citadel-ai-apps/citadel/internal/attest"
	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/authn"
	"github.com/citadel-ai-apps/citadel/internal/backup"
	"github.com/citadel-ai-apps/citadel/internal/config"
	dockerdrv "github.com/citadel-ai-apps/citadel/internal/driver/docker"
	"github.com/citadel-ai-apps/citadel/internal/egressctl"
	"github.com/citadel-ai-apps/citadel/internal/health"
	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/logcollect"
	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
	"github.com/citadel-ai-apps/citadel/internal/portal"
	"github.com/citadel-ai-apps/citadel/internal/proxyctl"
	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/release"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

func main() {

	if err := run(); err != nil {

		fmt.Fprintln(os.Stderr, "controlplaned:", err)
		os.Exit(1)
	}
}

func run() error {

	var (
		configPath = flag.String("config", "", "path to a JSON config file; defaults apply when empty")
		logLevel   = flag.String("log-level", "info", "debug | info | warn | error")
		seedFile   = flag.String("seed-digests", "", "register every version in a digests.txt at start-up")
		once       = flag.Bool("once", false, "run a single reconcile tick and exit")
	)
	flag.Parse()

	log := newLogger(*logLevel)

	cfg, err := config.Load(*configPath)
	if err != nil {

		return err
	}
	for _, w := range cfg.Warnings {

		log.Warn(w)
	}
	if os.Geteuid() != 0 {

		// Every operation here needs root. Failing now with a clear message
		// beats failing halfway through provisioning a tenant.
		return errors.New("must run as root: it mounts loopback images, writes netfilter rules and chowns tenant data")
	}

	fs := hostfs.New(cfg)
	if err := fs.EnsureLayout(); err != nil {

		return err
	}

	cli, err := dockerdrv.Connect()
	if err != nil {

		return fmt.Errorf("cannot reach the Docker daemon: %w", err)
	}
	defer cli.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	drv := dockerdrv.New(cli, log, fs.DataDeviceID)
	facts, err := drv.Inspect(ctx)
	if err != nil {

		return err
	}
	if err := checkHostFacts(cfg, facts, log); err != nil {

		return err
	}
	// INV-15: the flag leaves FORWARD's policy at ACCEPT, so anything
	// DOCKER-USER does not match is forwarded.
	if on, where := dockerdForwardNoDrop(); on {

		return fmt.Errorf("dockerd runs with --ip-forward-no-drop (%s); it voids the network model (INV-15)", where)
	}
	// INV-10: the data images and their rehearsal copies must be on a local
	// filesystem, not merely pb_data inside them.
	if err := hostfs.CheckLocal(cfg.PBRoot, cfg.TenantsDir(), cfg.ScratchDir(), cfg.BackupsDir()); err != nil {

		return err
	}

	// The remap base is read from /etc/subuid, never hardcoded: it is 100000 on
	// the development host but is assigned by useradd and differs between hosts
	// (design.md §4).
	usernsBase := 0
	if facts.UsernsRemap {

		usernsBase, err = hostfs.SubuidBase()
		if err != nil {

			return err
		}
		log.Info("userns-remap is active", "base_uid", usernsBase,
			"container_uid_on_host", usernsBase+hostfs.ContainerUID)
	}

	db, err := store.Open(ctx, cfg.StateDB())
	if err != nil {

		return err
	}
	defer db.Close()

	audit := auditlog.New()
	ident := identity.New(db.Reader(), audit)
	netMgr := netpolicy.New(cfg, cli, log)
	proxy := proxyctl.New(cfg, cli, log, usernsBase)
	egress := egressctl.New(cfg, cli, log, usernsBase)
	logs := logcollect.New(cfg, drv, log)
	defer logs.Close()
	// Health goes through the edge, never a tenant's bridge IP: the
	// host-protection INPUT drop also blocks host→tenant (design.md
	// §9.3).
	hc := health.NewChecker("127.0.0.1", cfg.EdgeHTTPPort)

	bkp := backup.New(cfg, db, fs, audit, log, usernsBase)
	releases := release.New(cfg, db, fs, audit)

	// The key that signs chain anchors and access attestations. Generated on
	// first use and never rotated: rotating it would invalidate every record
	// ever signed, which is the opposite of what those records are for.
	signer, err := fs.EnsureSigner()
	if err != nil {

		return err
	}
	attestor := attest.New(attest.Options{
		Config: cfg, DB: db, Net: netMgr, Egress: egress, Proxy: proxy,
		Docker: cli, Signer: signer, Audit: audit, Log: log,
	})

	rec := reconcile.New(reconcile.Options{
		Config: cfg, DB: db, FS: fs, Driver: drv, Backup: bkp, NetPolicy: netMgr,
		Proxy: proxy, Egress: egress, Logs: logs, Health: hc, Audit: audit, Log: log,
		UsernsBase: usernsBase, Attest: attestor, Signer: signer,
	})

	if *seedFile != "" {

		if err := seedDigests(ctx, db, audit, *seedFile, cfg, log); err != nil {

			return err
		}
	}

	// Synchronously, before the API can accept a request: provisioning needs
	// the platform firewall rules and the edge proxy to already exist, and a
	// request that raced the first tick would find neither.
	if err := rec.Bootstrap(ctx); err != nil {

		return fmt.Errorf("bootstrap: %w", err)
	}

	if *once {

		rec.Tick(ctx)
		return nil
	}

	srv := api.New(api.Options{
		Config: cfg, DB: db, FS: fs, Identity: ident, Releases: releases, Backups: bkp,
		Reconciler: rec, Driver: drv, Audit: audit, Log: log,
		Attest: attestor, Signer: signer,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ctx) }()
	go rec.Run(ctx)

	if cfg.PortalEnabled() {

		sessions, err := authn.LoadSessions(cfg.SessionKeyPath(), cfg.PortalSessionTTL.D())
		if err != nil {

			return err
		}
		// The portal listener gets the API with bearer-token authentication
		// mounted under /api/. X-V2P-Principal is stripped there: on the socket
		// it is attribution, on a TCP port it would be impersonation.
		p, err := portal.New(portal.Options{
			Config: cfg, DB: db, FS: fs, Identity: ident, Releases: releases,
			Reconciler: rec, Driver: drv, Audit: audit, Sessions: sessions,
			API: srv.APIHandler(), Logs: logs, Log: log,
			Attest: attestor, Signer: signer,
		})
		if err != nil {

			return err
		}
		go func() { errCh <- p.Serve(ctx) }()
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		return nil
	}
}

// checkHostFacts refuses to run on a host that does not match the verified
// runtime contract, rather than discovering the mismatch as a tenant escape.
func checkHostFacts(cfg config.Config, f dockerdrv.HostFacts, log *slog.Logger) error {

	log.Info("docker daemon", "version", f.ServerVersion, "firewall_backend", f.FirewallBackend,
		"userns_remap", f.UsernsRemap, "runsc", f.HasRunsc)

	if f.FirewallBackend != "" && f.FirewallBackend != "iptables" {

		// Docker 29's nftables backend changes the rule layout and requires
		// migrating DOCKER-USER rules. A backend change is a hardening-rev bump
		// with a full probe re-run (design.md §4), not something to tolerate silently.
		return fmt.Errorf("docker firewall backend is %q; the verified contract pins \"iptables\" "+
			"(set {\"firewall-backend\": \"iptables\"} in daemon.json, or re-run test/netprobe and "+
			"update the pin deliberately)", f.FirewallBackend)
	}
	if cfg.TenantRuntime == "runsc" && !f.HasRunsc {

		return errors.New("tenant_runtime is runsc (D2) but the daemon has no runsc runtime registered")
	}
	if cfg.UsernsRemap && !f.UsernsRemap {

		// Enabling userns-remap re-pulls the whole image store, because it is
		// per-remap-namespace. It must be on before first production use, never
		// as a later migration (D3, design.md §4).
		return errors.New("userns_remap is configured on (D3) but the daemon has none; " +
			"add {\"userns-remap\": \"default\"} to daemon.json and restart Docker " +
			"(this re-pulls the image store), or set userns_remap:false in the config")
	}
	if !cfg.UsernsRemap && f.UsernsRemap {

		return errors.New("the daemon has userns-remap but userns_remap is configured off; " +
			"tenant data directories would be chowned to the wrong uid")
	}
	return nil
}

// seedDigests registers every entry of a digests.txt as a runtime version.
//
// This is the hand-off from the image build (§5). Digests only: a tag could be
// retagged and silently change what a tenant runs.
func seedDigests(ctx context.Context, db *store.DB, audit *auditlog.Logger, path string, cfg config.Config, log *slog.Logger) error {

	entries, err := store.ParseDigestsFile(path)
	if err != nil {

		return err
	}
	seeded := 0
	for _, e := range entries {

		if e.Arch != cfg.Arch || e.HardeningRev != cfg.HardeningRev {

			continue
		}
		err := db.Tx(ctx, func(tx bun.Tx) error {

			if err := store.UpsertRuntimeVersion(ctx, tx, store.RuntimeVersion{
				Version: e.Version, HardeningRev: e.HardeningRev, ImageDigest: e.Ref,
				State: store.VersionSupported,
			}); err != nil {

				return err
			}
			_, err := audit.Append(ctx, tx, auditlog.Event{
				ActorID:    identity.PlatformPrincipal,
				ActorKind:  identity.KindPlatform,
				Action:     auditlog.ActionRuntimeVersionAdded,
				SubjectRef: "runtime_version/" + e.Version,
				Detail:     map[string]any{"digest": e.Ref, "source": path},
			})
			return err
		})
		if err != nil {

			return err
		}
		seeded++
	}
	log.Info("seeded runtime versions from digests file", "path", path, "count", seeded)
	return nil
}

func newLogger(level string) *slog.Logger {

	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {

		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
