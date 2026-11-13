package pkgvalidate_test

import (
	"testing"

	"github.com/citadel-ai-apps/citadel/internal/pkgvalidate"
)

// The version gate runs in both directions (§6): it decides whether a release
// may be deployed onto a runtime, and whether a runtime upgrade may be applied
// to a release. Both read this one function, so its edges matter.
func TestSatisfiesHandlesWildcardAndOpenBounds(t *testing.T) {

	cases := []struct {
		runtime, min, max string
		want              bool
	}{
		{"0.40.4", "0.38.0", "0.40.x", true},
		{"0.40.4", "0.38.0", "0.40.4", true},
		{"0.40.5", "0.38.0", "0.40.4", false},
		{"0.41.0", "0.38.0", "0.40.x", false},
		{"0.37.9", "0.38.0", "0.40.x", false},
		{"0.40.4", "", "0.40.x", true},
		{"0.40.4", "0.38.0", "", true},
		{"0.40.4", "", "", true},
		{"0.22.55", "0.22", "0.22.x", true},
		{"0.40.4", "0.x", "", true},
	}

	for _, c := range cases {

		got, err := pkgvalidate.Satisfies(c.runtime, c.min, c.max)
		if err != nil {

			t.Errorf("Satisfies(%q,%q,%q) errored: %v", c.runtime, c.min, c.max, err)
			continue
		}
		if got != c.want {

			t.Errorf("Satisfies(%q,%q,%q) = %v, want %v", c.runtime, c.min, c.max, got, c.want)
		}
	}
}

func TestIntersectsSupportedRejectsARangeNothingCanSchedule(t *testing.T) {

	supported := []string{"0.22.55", "0.38.2", "0.40.4"}

	ok, err := pkgvalidate.IntersectsSupported("0.38.0", "0.40.x", supported)
	if err != nil || !ok {

		t.Fatalf("IntersectsSupported = %v, %v; want true, nil", ok, err)
	}
	ok, err = pkgvalidate.IntersectsSupported("0.19.0", "0.19.x", supported)
	if err != nil || ok {

		t.Fatalf("IntersectsSupported = %v, %v; want false, nil", ok, err)
	}
}

// A wildcard is a legal request that is never auto-granted: internal/grantpolicy
// reads this to send it to a human (Tier 2, §14.3).
func TestIsWildcardSeparatesTheTiers(t *testing.T) {

	if !pkgvalidate.IsWildcard("*.stripe.com") {

		t.Error("*.stripe.com is not reported as a wildcard")
	}
	if pkgvalidate.IsWildcard("api.stripe.com") {

		t.Error("api.stripe.com is reported as a wildcard")
	}
}

func TestValidateEgressHostAcceptsTheHappyPath(t *testing.T) {

	p := pkgvalidate.HostPolicy{PlatformDomains: []string{"apps.localhost"}}
	for _, h := range []string{"api.stripe.com", "hooks.slack.com", "*.stripe.com", "a-b.example.co.uk"} {

		if err := pkgvalidate.ValidateEgressHost(h, p); err != nil {

			t.Errorf("ValidateEgressHost(%q) = %v, want nil", h, err)
		}
	}
	for _, h := range []string{"API.stripe.com", "api.stripe.com:443", "10.0.0.1", "localhost",
		"db.internal", "", "-bad.example.com", "apps.localhost"} {

		if err := pkgvalidate.ValidateEgressHost(h, p); err == nil {

			t.Errorf("ValidateEgressHost(%q) = nil, want a refusal", h)
		}
	}
}

// inet_aton reads these as addresses; a proxy built on it would connect to the
// metadata endpoint or loopback for a "hostname".
func TestValidateEgressHostRefusesShorthandAddresses(t *testing.T) {

	p := pkgvalidate.HostPolicy{}
	for _, h := range []string{"10.0.1", "169.254.43518", "0x7f.1", "0x7f.0x0.0x0.0x1", "127.1", "example.123", "*.10.0.1"} {

		if err := pkgvalidate.ValidateEgressHost(h, p); err == nil {

			t.Errorf("ValidateEgressHost(%q) = nil, want a refusal", h)
		}
	}
	// Numeric and hex-looking labels are fine when the name is a name.
	for _, h := range []string{"0x1.example.com", "123.example.com", "s3.eu-west-1.amazonaws.com"} {

		if err := pkgvalidate.ValidateEgressHost(h, p); err != nil {

			t.Errorf("ValidateEgressHost(%q) = %v, want nil", h, err)
		}
	}
}

func TestValidateEgressHostRefusesPublicSuffixWildcards(t *testing.T) {

	for _, h := range []string{"*.co.uk", "*.github.io", "*.com.au"} {

		if err := pkgvalidate.ValidateEgressHost(h, pkgvalidate.HostPolicy{}); err == nil {

			t.Errorf("ValidateEgressHost(%q) = nil, want a refusal", h)
		}
	}
	for _, h := range []string{"*.example.co.uk", "*.stripe.com", "*.user.github.io"} {

		if err := pkgvalidate.ValidateEgressHost(h, pkgvalidate.HostPolicy{}); err != nil {

			t.Errorf("ValidateEgressHost(%q) = %v, want nil", h, err)
		}
	}
}
