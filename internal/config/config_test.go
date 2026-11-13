package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) string {

	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {

		t.Fatal(err)
	}
	return p
}

func load(t *testing.T, dir, body string) (Config, error) {

	t.Helper()
	return Load(writeFile(t, dir, "config.json", body))
}

// Left unset, the edge and proxy images come from the digests the image
// builds recorded, newest entry for this architecture.
func TestImagesResolveFromTheDigestsFiles(t *testing.T) {

	dir := t.TempDir()
	edge := writeFile(t, dir, "edge.txt",
		"2.10.1 r1 arm64 reg/edge@sha256:old\n2.10.1 r1 amd64 reg/edge@sha256:x86\n2.10.2 r1 arm64 reg/edge@sha256:new\n")
	egress := writeFile(t, dir, "egress.txt", "6.9 r2 arm64 reg/egress-proxy@sha256:sq\n")
	probe := writeFile(t, dir, "probe.txt", "r1 arm64 reg/probe@sha256:p1\nr2 arm64 reg/probe@sha256:p2\n")
	cfg, err := load(t, dir, `{"arch":"arm64","edge_digests_file":"`+edge+`","egress_digests_file":"`+egress+
		`","probe_digests_file":"`+probe+`"}`)
	if err != nil {

		t.Fatal(err)
	}
	if cfg.EdgeImage != "reg/edge@sha256:new" || cfg.EgressProxyImage != "reg/egress-proxy@sha256:sq" {

		t.Fatalf("resolved edge=%q egress=%q", cfg.EdgeImage, cfg.EgressProxyImage)
	}
	if cfg.ProbeImage != "reg/probe@sha256:p2" {

		t.Fatalf("resolved probe=%q", cfg.ProbeImage)
	}
	if len(cfg.Warnings) != 0 {

		t.Fatalf("warnings for pinned images: %v", cfg.Warnings)
	}
}

// Nothing built for this architecture: the unpinned fallback, said out loud.
func TestUnresolvedImagesFallBackWithAWarning(t *testing.T) {

	dir := t.TempDir()
	cfg, err := load(t, dir, `{"arch":"riscv64","edge_digests_file":"`+filepath.Join(dir, "none.txt")+`"}`)
	if err != nil {

		t.Fatal(err)
	}
	if cfg.EdgeImage != fallbackEdgeImage || len(cfg.Warnings) != 3 {

		t.Fatalf("edge=%q warnings=%v", cfg.EdgeImage, cfg.Warnings)
	}
	if !strings.Contains(cfg.Warnings[0], "make edge-image") {

		t.Fatalf("warning does not say how to fix it: %q", cfg.Warnings[0])
	}
	// The probe has no fallback: it stays empty, which disables rehearsal.
	if cfg.ProbeImage != "" || !strings.Contains(cfg.Warnings[2], "make probe-image") {

		t.Fatalf("probe=%q warning=%q", cfg.ProbeImage, cfg.Warnings[2])
	}
}

// A configured probe_image wins over the digests file, and must be a digest
// even with allow_unpinned_images: the probe has no tag worth trusting.
func TestAConfiguredProbeImageOverridesTheDigestsFile(t *testing.T) {

	dir := t.TempDir()
	probe := writeFile(t, dir, "probe.txt", "r2 arm64 reg/probe@sha256:p2\n")
	cfg, err := load(t, dir, `{"arch":"arm64","probe_digests_file":"`+probe+`","probe_image":"reg/probe@sha256:mine"}`)
	if err != nil || cfg.ProbeImage != "reg/probe@sha256:mine" {

		t.Fatalf("probe=%q err=%v", cfg.ProbeImage, err)
	}
	if _, err := load(t, dir, `{"probe_image":"reg/probe:r2","allow_unpinned_images":true}`); err == nil {

		t.Fatal("probe_image as a tag was accepted")
	}
}

// A configured tag is refused: these containers parse every tenant's
// traffic, and a tag is whatever was pushed under it last.
func TestAConfiguredTagIsRefusedUnlessAllowed(t *testing.T) {

	dir := t.TempDir()
	if _, err := load(t, dir, `{"edge_image":"caddy:2"}`); err == nil {

		t.Fatal("edge_image as a tag was accepted")
	}
	if _, err := load(t, dir, `{"egress_proxy_image":"v2p-squid:6-r2"}`); err == nil {

		t.Fatal("egress_proxy_image as a tag was accepted")
	}
	cfg, err := load(t, dir, `{"edge_image":"caddy:2","egress_proxy_image":"v2p-squid:6-r2","allow_unpinned_images":true}`)
	if err != nil || cfg.EdgeImage != "caddy:2" {

		t.Fatalf("allow_unpinned_images: %v, %q", err, cfg.EdgeImage)
	}
	cfg, err = load(t, dir, `{"edge_image":"reg/edge@sha256:abc"}`)
	if err != nil || cfg.EdgeImage != "reg/edge@sha256:abc" {

		t.Fatalf("a digest was refused: %v", err)
	}
}

// Tenant code is hostile (INV-1): runsc is the only tenant runtime, and a
// config that names anything else does not load.
func TestTenantRuntimeMustBeRunsc(t *testing.T) {

	dir := t.TempDir()
	if _, err := load(t, dir, `{"tenant_runtime":"runc"}`); err == nil {

		t.Fatal("tenant_runtime runc was accepted")
	}
	if cfg, err := load(t, dir, `{}`); err != nil || cfg.TenantRuntime != "runsc" {

		t.Fatalf("the default: %v, %q", err, cfg.TenantRuntime)
	}
}
