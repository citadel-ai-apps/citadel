package authn_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/authn"
)

func TestPasswordRoundTrip(t *testing.T) {

	h, err := authn.HashPassword("correct horse battery staple")
	if err != nil {

		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {

		t.Fatalf("hash %q is not an encoded argon2id hash", h)
	}
	if !authn.VerifyPassword(h, "correct horse battery staple") {

		t.Error("the right password did not verify")
	}
	if authn.VerifyPassword(h, "correct horse battery stapl") {

		t.Error("a wrong password verified")
	}
	if authn.VerifyPassword("not a hash", "correct horse battery staple") {

		t.Error("a malformed hash verified")
	}
}

// Length, not composition: a rule demanding symbols produces shorter
// passwords, which is the opposite of the goal.
func TestShortPasswordsAreRefused(t *testing.T) {

	_, err := authn.HashPassword("short")
	if !errors.Is(err, authn.ErrWeakPassword) {

		t.Fatalf("err = %v, want ErrWeakPassword", err)
	}
}

// The plaintext is shown once and never stored: what lands in the database must
// not be usable as a token.
func TestTokenSecretIsNotRecoverableFromItsHash(t *testing.T) {

	plaintext, hash := authn.NewToken("tk-1234")
	id, secret, err := authn.SplitToken(plaintext)
	if err != nil {

		t.Fatal(err)
	}
	if id != "tk-1234" {

		t.Errorf("id = %q, want tk-1234", id)
	}
	if strings.Contains(hash, secret) {

		t.Error("the stored hash contains the secret")
	}
	if !authn.EqualTokenHash(hash, authn.HashToken(secret)) {

		t.Error("the presented secret does not hash to the stored value")
	}
	if authn.EqualTokenHash(hash, authn.HashToken(secret+"x")) {

		t.Error("a wrong secret matched")
	}
}

func TestMalformedTokensAreRejectedBeforeAnyLookup(t *testing.T) {

	for _, bad := range []string{"", "v2p", "v2p_only", "other_id_secret", "v2p__secret", "v2p_id_"} {

		if _, _, err := authn.SplitToken(bad); !errors.Is(err, authn.ErrBadToken) {

			t.Errorf("SplitToken(%q) err = %v, want ErrBadToken", bad, err)
		}
	}
}

func sessions(t *testing.T, ttl time.Duration) *authn.Sessions {

	t.Helper()
	s, err := authn.LoadSessions(filepath.Join(t.TempDir(), "portal-session.key"), ttl)
	if err != nil {

		t.Fatal(err)
	}
	return s
}

func TestSessionCookieRoundTrip(t *testing.T) {

	s := sessions(t, time.Hour)
	c := s.Issue("person:alice")
	got, err := s.Verify(c)
	if err != nil || got != "person:alice" {

		t.Fatalf("Verify = %q, %v; want person:alice, nil", got, err)
	}
}

// A cookie is the portal's only authorisation, so a forged or edited one must
// fail closed rather than be parsed for what it claims.
func TestForgedOrExpiredSessionsAreRefused(t *testing.T) {

	s := sessions(t, time.Hour)
	c := s.Issue("person:alice")

	forged := strings.Replace(c, "person:alice", "person:root_", 1)
	if _, err := s.Verify(forged); !errors.Is(err, authn.ErrBadSession) {

		t.Errorf("a re-written principal verified: %v", err)
	}
	if _, err := s.Verify("person:alice.99999999999.notasignature"); !errors.Is(err, authn.ErrBadSession) {

		t.Error("an unsigned cookie verified")
	}
	if _, err := s.Verify("garbage"); !errors.Is(err, authn.ErrBadSession) {

		t.Error("a malformed cookie verified")
	}

	past := sessions(t, -time.Minute)
	if _, err := past.Verify(past.Issue("person:alice")); !errors.Is(err, authn.ErrBadSession) {

		t.Error("an expired cookie verified")
	}
}

// Rotating the key file is the logout-everyone lever, so a cookie from one key
// must not verify under another.
func TestADifferentKeyInvalidatesEverySession(t *testing.T) {

	a, b := sessions(t, time.Hour), sessions(t, time.Hour)
	if _, err := b.Verify(a.Issue("person:alice")); err == nil {

		t.Error("a cookie signed with another key verified")
	}
}

func TestCSRFTokenIsBoundToTheSession(t *testing.T) {

	s := sessions(t, time.Hour)
	c1, c2 := s.Issue("person:alice"), s.Issue("person:bob")
	if !s.ValidCSRF(c1, s.CSRFToken(c1)) {

		t.Error("the session's own CSRF token did not validate")
	}
	if s.ValidCSRF(c1, s.CSRFToken(c2)) {

		t.Error("another session's CSRF token validated")
	}
	if s.ValidCSRF(c1, "") {

		t.Error("an empty CSRF token validated")
	}
}
