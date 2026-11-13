package pkgvalidate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"unicode"
)

// ManifestName is the one file a package carries outside the three directories.
const ManifestName = "pbapp.json"

// SchemaVersion is the only manifest schema this platform understands.
const SchemaVersion = 1

// Manifest is pbapp.json (design §6).
type Manifest struct {
	SchemaVersion int            `json:"schemaVersion"`
	Name          string         `json:"name"`
	Version       string         `json:"version"`
	PocketBase    PBRange        `json:"pocketbase"`
	Egress        []string       `json:"egress,omitempty"`
	Healthcheck   Healthcheck    `json:"healthcheck"`
	Smoke         []SmokeRequest `json:"smoke,omitempty"`
}

// PBRange is the runtime window a release declares. It gates scheduling in both
// directions: the platform refuses to deploy this release onto an incompatible
// runtime, and refuses a runtime upgrade this release declares incompatible.
type PBRange struct {
	Min string `json:"min"`
	Max string `json:"max"`
}

// Healthcheck is the request that must succeed before a deploy is accepted.
type Healthcheck struct {
	Path         string `json:"path"`
	ExpectStatus int    `json:"expectStatus"`
}

// SmokeRequest is one request replayed after a deploy and during upgrade
// rehearsal (§12). This is how the platform tells a tenant "your app still
// works on 0.40.4" with evidence rather than with a health endpoint that lies
// .
type SmokeRequest struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	ExpectStatus int    `json:"expectStatus"`
}

// DefaultHealthcheck is what a manifest that omits the block gets.
func DefaultHealthcheck() Healthcheck {

	return Healthcheck{Path: "/api/health", ExpectStatus: http.StatusOK}
}

var smokeMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true,
	http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
}

// ParseManifest decodes and checks pbapp.json.
//
// Unknown fields are tolerated on purpose: a manifest written for a later
// schema should fail on schemaVersion with a sentence a human can act on, not
// on an unknown key three lines further down.
func ParseManifest(raw []byte, opt Options) (Manifest, error) {

	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {

		return Manifest{}, fmt.Errorf("%w: %s does not parse: %v", ErrManifest, ManifestName, err)
	}
	if m.SchemaVersion != SchemaVersion {

		return Manifest{}, fmt.Errorf("%w: schemaVersion is %d; this platform understands %d",
			ErrManifest, m.SchemaVersion, SchemaVersion)
	}
	if err := checkText("name", m.Name, 64); err != nil {

		return Manifest{}, err
	}
	if err := checkText("version", m.Version, 64); err != nil {

		return Manifest{}, err
	}
	if err := ValidRange(m.PocketBase.Min, m.PocketBase.Max); err != nil {

		return Manifest{}, err
	}
	if len(opt.Supported) > 0 {

		ok, err := IntersectsSupported(m.PocketBase.Min, m.PocketBase.Max, opt.Supported)
		if err != nil {

			return Manifest{}, err
		}
		if !ok {

			return Manifest{}, fmt.Errorf("%w: pocketbase %s–%s matches none of the supported runtimes (%s)",
				ErrNoSupportedRuntime, orAny(m.PocketBase.Min), orAny(m.PocketBase.Max),
				strings.Join(opt.Supported, ", "))
		}
	}

	if m.Healthcheck.Path == "" {

		m.Healthcheck = DefaultHealthcheck()
	}
	if m.Healthcheck.ExpectStatus == 0 {

		m.Healthcheck.ExpectStatus = http.StatusOK
	}
	if err := checkRequest("healthcheck", http.MethodGet, m.Healthcheck.Path, m.Healthcheck.ExpectStatus); err != nil {

		return Manifest{}, err
	}
	for i := range m.Smoke {

		s := &m.Smoke[i]
		if s.Method == "" {

			s.Method = http.MethodGet
		}
		s.Method = strings.ToUpper(s.Method)
		if s.ExpectStatus == 0 {

			s.ExpectStatus = http.StatusOK
		}
		if !smokeMethods[s.Method] {

			return Manifest{}, fmt.Errorf("%w: smoke[%d] method %q is not a request method", ErrManifest, i, s.Method)
		}
		if err := checkRequest(fmt.Sprintf("smoke[%d]", i), s.Method, s.Path, s.ExpectStatus); err != nil {

			return Manifest{}, err
		}
	}

	seen := make(map[string]bool, len(m.Egress))
	for _, host := range m.Egress {

		if seen[host] {

			return Manifest{}, fmt.Errorf("%w: egress names %q twice", ErrManifest, host)
		}
		seen[host] = true
		if err := ValidateEgressHost(host, opt.HostPolicy); err != nil {

			return Manifest{}, err
		}
		// §14.7: a subject this tenant previously had denied or revoked may be
		// re-requested, but never auto-granted. Rejecting it at validation
		// would make "revoke" a permanent ban; the deploy path instead sends it
		// to a human. Only an explicit Refused hook that says "reject" gets us
		// here, which is the operator-chosen hard-block case.
		if opt.Refused != nil && opt.Refused(host) {

			return Manifest{}, fmt.Errorf("%w: %s", ErrRefusedSubject, host)
		}
	}
	return m, nil
}

func checkText(field, value string, max int) error {

	if strings.TrimSpace(value) == "" {

		return fmt.Errorf("%w: %s is required", ErrManifest, field)
	}
	if len(value) > max {

		return fmt.Errorf("%w: %s is longer than %d characters", ErrManifest, field, max)
	}
	for _, r := range value {

		if !unicode.IsPrint(r) {

			return fmt.Errorf("%w: %s contains a non-printable character", ErrManifest, field)
		}
	}
	return nil
}

func checkRequest(field, method, path string, status int) error {

	if !strings.HasPrefix(path, "/") {

		return fmt.Errorf("%w: %s path %q must start with /", ErrManifest, field, path)
	}
	if strings.Contains(path, "..") {

		return fmt.Errorf("%w: %s path %q contains ..", ErrManifest, field, path)
	}
	if status < 100 || status > 599 {

		return fmt.Errorf("%w: %s expectStatus %d is not an HTTP status", ErrManifest, field, status)
	}
	if method == "" {

		return fmt.Errorf("%w: %s has no method", ErrManifest, field)
	}
	return nil
}

func orAny(v string) string {

	if v == "" {

		return "any"
	}
	return v
}
