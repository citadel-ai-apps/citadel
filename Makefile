# Hardened image build (design §5).
# All docker targets run against the daemon on the current host; on macOS use
# ./hack/in-vm.sh to execute them inside the development VM (a UTM guest — see
# hack/vm/README.md).
#
#   make check                                   # EVERYTHING: lint, unit, images, suites
#   make lint                                    # ast-grep rules + shellcheck
#   make licenses                                # fail on any non-permissive Go dependency
#
#   make registry                                # local zot on 127.0.0.1:5000
#   make image PB_VERSION=0.42.2 HARDENING_REV=2 # build+push one image, print digest
#   make image-matrix HARDENING_REV=2            # every version in versions.txt
#   make smoke PB_VERSION=0.42.2                 # image self-checks, by digest
#   make edge-image                              # Caddy + rate-limit module, by digest
#   make egress-image                            # Squid WITH OpenSSL (ssl_bump needs it)
#   make probe-image                             # FROM-scratch rehearsal probe (§12), by digest

REGISTRY      ?= 127.0.0.1:5000
HARDENING_REV ?= 2
IMG_DIR       := images/pb-hardened
DIGESTS       := $(IMG_DIR)/digests.txt
# Fixed, not the commit time: the image config's created date and history are
# then a function of the inputs only, so a rebuild reproduces the digest and
# digests.txt gains no line. The Containerfiles pin file mtimes to the same 0.
SOURCE_DATE_EPOCH := 0

# uname -m → Docker/PB arch name
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),aarch64)
  ARCH ?= arm64
else ifeq ($(UNAME_M),arm64)
  ARCH ?= arm64
else
  ARCH ?= amd64
endif

REPO := $(REGISTRY)/pb-hardened
TAG  := $(PB_VERSION)-h$(HARDENING_REV)

.PHONY: image image-matrix edge-image egress-image probe-image registry smoke

image:
ifndef PB_VERSION
	$(error PB_VERSION is required, e.g. make image PB_VERSION=0.42.2)
endif
	@test -f $(IMG_DIR)/checksums/pocketbase_$(PB_VERSION)_linux_$(ARCH).sha256 || \
	  { echo "no pinned checksum for $(PB_VERSION)/$(ARCH); run $(IMG_DIR)/fetch-checksum.sh $(PB_VERSION)"; exit 1; }
	docker build \
	  --provenance=false \
	  --build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
	  -f $(IMG_DIR)/Containerfile \
	  --build-arg PB_VERSION=$(PB_VERSION) \
	  --build-arg HARDENING_REV=$(HARDENING_REV) \
	  --build-arg PB_SHA256=$$(cut -d' ' -f1 $(IMG_DIR)/checksums/pocketbase_$(PB_VERSION)_linux_$(ARCH).sha256) \
	  -t $(REPO):$(TAG) \
	  .
	docker push $(REPO):$(TAG)
	@# The digest, not the tag, is what the control plane will schedule.
	@digest=$$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' $(REPO):$(TAG) \
	           | grep '^$(REPO)@' | head -1); \
	 test -n "$$digest" || { echo "no repo digest found after push"; exit 1; }; \
	 grep -qF "$$digest" $(DIGESTS) 2>/dev/null || \
	   echo "$(PB_VERSION) h$(HARDENING_REV) $(ARCH) $$digest" >> $(DIGESTS); \
	 echo "IMAGE DIGEST: $$digest"

# The edge proxy, with the rate-limit module compiled in (§10). Built and
# pushed by digest like pb-hardened: the control plane schedules digests, never
# tags.
EDGE_DIR      := images/edge-caddy
EDGE_DIGESTS  := $(EDGE_DIR)/digests.txt
CADDY_VERSION ?= 2.10.2
RATELIMIT_REV ?= 1

edge-image:
	docker build \
	  --provenance=false \
	  --build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
	  -f $(EDGE_DIR)/Containerfile \
	  --build-arg CADDY_VERSION=$(CADDY_VERSION) \
	  -t $(REGISTRY)/edge-caddy:$(CADDY_VERSION)-r$(RATELIMIT_REV) \
	  $(EDGE_DIR)
	docker push $(REGISTRY)/edge-caddy:$(CADDY_VERSION)-r$(RATELIMIT_REV)
	@digest=$$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' \
	             $(REGISTRY)/edge-caddy:$(CADDY_VERSION)-r$(RATELIMIT_REV) \
	           | grep '^$(REGISTRY)/edge-caddy@' | head -1); \
	 test -n "$$digest" || { echo "no repo digest found after push"; exit 1; }; \
	 grep -qF "$$digest" $(EDGE_DIGESTS) 2>/dev/null || \
	   echo "$(CADDY_VERSION) r$(RATELIMIT_REV) $(ARCH) $$digest" >> $(EDGE_DIGESTS); \
	 echo "EDGE IMAGE DIGEST: $$digest"

# The rehearsal probe (§12). A FROM-scratch image holding one static binary,
# which is the only thing that can check an upgrade rehearsal: the rehearsal
# bridge matches `br-t-+` on purpose, so the host-protection INPUT drop stops
# the control plane dialling in and something has to ask from inside.
#
# Built from the repo root, not the image directory: it compiles cmd/pbprobe out
# of this tree. Recorded by digest like the edge: the control plane resolves its
# default probe_image from digests.txt for the host's architecture.
PROBE_DIR     := images/rehearse-probe
PROBE_DIGESTS := $(PROBE_DIR)/digests.txt
PROBE_REV     ?= 2

probe-image:
	docker build \
	  --provenance=false \
	  --build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
	  -f $(PROBE_DIR)/Containerfile \
	  -t $(REGISTRY)/rehearse-probe:r$(PROBE_REV) \
	  .
	docker push $(REGISTRY)/rehearse-probe:r$(PROBE_REV)
	@digest=$$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' \
	             $(REGISTRY)/rehearse-probe:r$(PROBE_REV) \
	           | grep '^$(REGISTRY)/rehearse-probe@' | head -1); \
	 test -n "$$digest" || { echo "no repo digest found after push"; exit 1; }; \
	 grep -qF "$$digest" $(PROBE_DIGESTS) 2>/dev/null || \
	   echo "r$(PROBE_REV) $(ARCH) $$digest" >> $(PROBE_DIGESTS); \
	 echo "PROBE IMAGE DIGEST: $$digest"

# The egress forward proxy (§9.4). Built rather than pulled because the distro
# images that are easy to pull are built without OpenSSL, and a Squid without
# ssl_bump can only filter the CONNECT target — see the Containerfile.
#
# Pushed and recorded by digest like the edge: the control plane resolves its
# default egress_proxy_image from digests.txt for the host's architecture. The
# local v2p-squid tag is kept for the netprobe scripts that run Squid by hand.
PROXY_DIR     := images/egress-proxy
PROXY_DIGESTS := $(PROXY_DIR)/digests.txt
PROXY_REV     ?= 2
PROXY_TAG     ?= v2p-squid:6-r$(PROXY_REV)
PROXY_REF     := $(REGISTRY)/egress-proxy:6-r$(PROXY_REV)

egress-image:
	docker build \
	  --provenance=false \
	  --build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
	  -f $(PROXY_DIR)/Containerfile \
	  -t $(PROXY_TAG) -t $(PROXY_REF) \
	  $(PROXY_DIR)
	docker push $(PROXY_REF)
	@squid=$$(docker run --rm --entrypoint squid $(PROXY_REF) -v | sed -n '1s/.*Version \([0-9.]*\).*/\1/p'); \
	 digest=$$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' $(PROXY_REF) \
	           | grep '^$(REGISTRY)/egress-proxy@' | head -1); \
	 test -n "$$digest" || { echo "no repo digest found after push"; exit 1; }; \
	 grep -qF "$$digest" $(PROXY_DIGESTS) 2>/dev/null || \
	   echo "$$squid r$(PROXY_REV) $(ARCH) $$digest" >> $(PROXY_DIGESTS); \
	 echo "EGRESS PROXY IMAGE DIGEST: $$digest (squid $$squid)"

image-matrix:
	@set -e; \
	 grep -Ev '^\s*(#|$$)' $(IMG_DIR)/versions.txt | while read -r v; do \
	   echo "=== pb-hardened $$v h$(HARDENING_REV) ==="; \
	   $(MAKE) --no-print-directory image PB_VERSION=$$v HARDENING_REV=$(HARDENING_REV); \
	 done

# Local OCI registry (zot), platform container on runc, loopback only — never
# reachable from a tenant bridge.
registry:
	@docker inspect -f '{{.State.Running}}' citadel-registry 2>/dev/null | grep -q true || { \
	   docker rm -f citadel-registry 2>/dev/null || true; \
	   docker run -d --name citadel-registry --restart unless-stopped \
	     -p 127.0.0.1:5000:5000 \
	     -v citadel-registry-data:/var/lib/registry \
	     -v $(CURDIR)/deploy/registry/zot-config.json:/etc/zot/config.json:ro \
	     ghcr.io/project-zot/zot-linux-$(ARCH):v2.1.8 ; }
	@for i in $$(seq 1 20); do \
	   curl -fsS http://127.0.0.1:5000/v2/ >/dev/null 2>&1 && { echo "registry OK at 127.0.0.1:5000"; exit 0; }; \
	   sleep 0.5; \
	 done; echo "registry did not come up"; exit 1

smoke:
ifndef PB_VERSION
	$(error PB_VERSION is required, e.g. make smoke PB_VERSION=0.42.2)
endif
	@digest=$$(grep "^$(PB_VERSION) h$(HARDENING_REV) $(ARCH) " $(DIGESTS) | tail -1 | awk '{print $$4}'); \
	 test -n "$$digest" || { echo "no digest for $(PB_VERSION) h$(HARDENING_REV) in $(DIGESTS); run make image first"; exit 1; }; \
	 bash $(IMG_DIR)/smoke.sh "$$digest" "$(PB_VERSION)"

# ── Control plane ────────────────────────────────────────────────────────────
# The control plane must run as root on the Docker host: it mounts loopback
# images, writes netfilter rules and chowns tenant data. On macOS build here and
# run inside the development VM via hack/in-vm.sh.
#
#   make build                  # static linux/arm64 binaries into bin/
#   make test                   # unit tests, natively
#   make accept                 # all four acceptance suites, in the VM
#   make accept-controlplane    # provision, reconcile, destroy, audit
#   make accept-packages        # package pipeline and portal
#   make accept-egress          # egress enforcement
#   make accept-upgrade         # backups and independent upgrades
#   make netprobe               # the network-posture probes
#   make redteam                # §13.3: every probe must FAIL to reach its goal
#   make vm-create              # a UTM dev VM from nothing (then vm-up, vm-provision)
#   make vm-bootstrap           # enable userns-remap on a fresh host
#   make vm-doctor              # duplicate/orphan UTM VMs (ARGS=--fix clears them)

GOFLAGS_STATIC := CGO_ENABLED=0
# modernc.org/sqlite is pure Go, so the whole control plane cross-compiles.
GOOS_TARGET    ?= linux
GOARCH_TARGET  ?= $(ARCH)

.PHONY: build test vet lint licenses accept accept-controlplane accept-packages \
        accept-egress accept-upgrade netprobe redteam bootstrap-vm vm-bootstrap \
        clean-bin check images-all vm-create vm-up vm-down vm-status vm-ssh vm-provision vm-doctor

build:
	@mkdir -p bin
	$(GOFLAGS_STATIC) GOOS=$(GOOS_TARGET) GOARCH=$(GOARCH_TARGET) \
	  go build -trimpath -o bin/controlplaned ./cmd/controlplaned
	$(GOFLAGS_STATIC) GOOS=$(GOOS_TARGET) GOARCH=$(GOARCH_TARGET) \
	  go build -trimpath -o bin/citadel ./cmd/citadel
	@echo "built bin/controlplaned and bin/citadel for $(GOOS_TARGET)/$(GOARCH_TARGET)"

test:
	go test ./...

vet:
	go vet ./...

# ast-grep rules live in rules/, their test cases in rule-tests/. The empty-line
# rules have no autofix; hack/lint/blankline-fix.py applies them mechanically.
# shellcheck covers every tracked shell script; its config is .shellcheckrc.
lint:
	ast-grep scan
	ast-grep test
	git ls-files -z '*.sh' | xargs -0 shellcheck

# Citadel ships under FSL-1.1-ALv2 (LICENSE). Every module compiled into the
# binaries must be permissive, or that licence stops being ours to choose. The
# classifier does not know FSL, so our own module is skipped. A failure here
# also means NOTICE needs the new module listed. The "non-Go code" warnings
# about .s files are expected.
GO_LICENSES_VERSION ?= v2.0.1
ALLOWED_LICENSES    ?= Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC
# Built for the host, then pointed at the target platform: the dependency set
# is what ships, not what compiles on a Mac.
licenses:
	@mkdir -p bin
	GOBIN=$(CURDIR)/bin go install github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION)
	GOOS=$(GOOS_TARGET) GOARCH=$(GOARCH_TARGET) bin/go-licenses check ./... \
	  --ignore=github.com/citadel-ai-apps/citadel \
	  --allowed_licenses=$(ALLOWED_LICENSES) --stderrthreshold=ERROR

# The acceptance suites all run against the same VM and the same daemon, so they
# are sequential, not parallel.
accept: accept-controlplane accept-packages accept-egress accept-upgrade

accept-controlplane: build
	hack/in-vm.sh bash test/acceptance/controlplane.sh $(ARGS)

# The package suite needs a portal listener a browser can reach, so the script
# writes its own config with portal_addr on the VM's address.
accept-packages: build
	hack/in-vm.sh bash test/acceptance/packages.sh $(ARGS)

# The egress suite brings up the egress proxy and the per-grant rules, and needs
# a portal listener for the denial surface.
accept-egress: build
	hack/in-vm.sh bash test/acceptance/egress.sh $(ARGS)

# Backups and independent upgrades (§11, §12). Needs TWO pb-hardened images —
# `make image PB_VERSION=$(PB_FROM)` and `PB_VERSION=$(PB_TO)` — plus the probe
# image, since a rehearsal without a probe cannot report anything.
accept-upgrade: build
	hack/in-vm.sh bash test/acceptance/upgrade.sh $(ARGS)

# The §13.3 matrix. Every probe must FAIL to achieve its goal; the target exits
# non-zero if any of them succeeds. Run it after a Docker daemon upgrade and
# after any firewall-backend change, both of which can move the rules out from
# under the platform (§13.3).
redteam: build
	hack/in-vm.sh bash test/redteam/run-all.sh $(ARGS)

# The network-posture probes, in order. Each one exits 0 when the posture holds
# and non-zero on an escape. The runner provisions two throwaway tenants first so
# the probes that inspect live tenants (08, 09) run rather than skip, and tears
# them down afterwards; ARGS=--keep leaves them up.
netprobe: build
	hack/in-vm.sh bash test/netprobe/run-all.sh $(ARGS)

clean-bin:
	rm -rf bin

# ── Development VM ───────────────────────────────────────────────────────────
# A UTM guest running a stock Ubuntu kernel, from nothing:
#
#   make vm-create && make vm-up && make vm-provision && make vm-bootstrap
#
# These targets are the only UTM-specific ones: set PB_VM_HOST and
# hack/in-vm.sh will talk to any ssh-reachable Linux host instead.
PB_VM ?= citadel

# Downloads a pinned Ubuntu cloud image, builds a cloud-init seed and registers
# the VM with UTM. Pass ARGS=--recreate to replace an existing one — which
# deletes all of its data.
vm-create:
	bash hack/vm/create.sh $(ARGS)

# UTM is addressed by UUID, never by name: hack/vm/resolve.sh refuses a name
# that two VMs share, which UTM silently allows.
VM_UUID = $$(bash hack/vm/resolve.sh $(PB_VM))

vm-up:
	@uuid=$(VM_UUID) || exit 1; \
	  test "$$(utmctl status $$uuid)" = started || utmctl start $$uuid
	@echo "waiting for ssh… (the first boot runs cloud-init and takes minutes)"
	@for i in $$(seq 1 180); do \
	   PB_VM_NO_SYNC=1 hack/in-vm.sh true >/dev/null 2>&1 && \
	     { echo "$(PB_VM) is up"; exit 0; }; \
	   sleep 2; \
	 done; echo "$(PB_VM) started but ssh never answered"; exit 1

vm-down:
	@uuid=$(VM_UUID) || exit 1; utmctl stop $$uuid

vm-status:
	@PB_VM=$(PB_VM) bash hack/vm/doctor.sh || true
	@uuid=$(VM_UUID) || exit 1; echo "utm:    $$(utmctl status $$uuid) ($$uuid)"
	@PB_VM_NO_SYNC=1 hack/in-vm.sh true >/dev/null 2>&1 && echo "ssh:    ok" || \
	  { echo "ssh:    unreachable"; exit 1; }
	@PB_VM_NO_SYNC=1 hack/in-vm.sh docker info \
	  --format 'docker: {{.ServerVersion}}{{range $$n, $$_ := .Runtimes}} {{$$n}}{{end}}' \
	  2>/dev/null || echo "docker: not installed — run 'make vm-provision'"

# Ghost registry entries and orphan QEMU processes, which utmctl cannot see
# and which are what leave UTM with two VMs of one name. ARGS=--fix clears them.
vm-doctor:
	@PB_VM=$(PB_VM) bash hack/vm/doctor.sh $(ARGS)

vm-ssh:
	@PB_VM_NO_SYNC=1 hack/in-vm.sh bash -l

# Docker CE, gVisor/runsc and the test-suite dependencies. Must precede
# vm-bootstrap, which only CHECKS for runsc and dies if it is missing.
vm-provision:
	hack/in-vm.sh bash hack/vm/provision.sh $(ARGS)

# userns-remap (D3), the local registry, and the image matrix. `bootstrap-vm`
# is the older name, kept working.
vm-bootstrap bootstrap-vm:
	hack/in-vm.sh bash hack/bootstrap-vm.sh $(ARGS)

# ── Everything ───────────────────────────────────────────────────────────────
# Build every image the suites need, in the VM. The upgrade suite needs a
# version PAIR whose JSVM APIs differ, which is why PB_FROM and PB_TO are built
# by name rather than left to the matrix.
PB_FROM ?= 0.22.55
PB_TO   ?= 0.42.2

# Lets scripts outside make read the defaults above instead of duplicating
# them (hack/bootstrap-vm.sh): `make -s print-HARDENING_REV`.
print-%:
	@echo '$($*)'

images-all:
	hack/in-vm.sh make registry
	hack/in-vm.sh make image-matrix HARDENING_REV=$(HARDENING_REV)
	hack/in-vm.sh make image PB_VERSION=$(PB_FROM) HARDENING_REV=$(HARDENING_REV)
	hack/in-vm.sh make image PB_VERSION=$(PB_TO) HARDENING_REV=$(HARDENING_REV)
	hack/in-vm.sh make edge-image
	hack/in-vm.sh make egress-image
	hack/in-vm.sh make probe-image

# One command for the whole test surface. Strictly ordered and strictly serial:
# the suites share one VM and one daemon, and the red team runs last because it
# is the gate, not a smoke test.
.NOTPARALLEL: check images-all accept
check: vet lint licenses test build images-all accept netprobe redteam
	@echo
	@echo "all suites green"
