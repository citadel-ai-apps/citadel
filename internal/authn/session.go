package authn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ErrBadSession is returned for a cookie that is missing, malformed, forged or
// expired.
var ErrBadSession = errors.New("authn: session is not valid")

// SessionCookie is the portal's cookie name.
const SessionCookie = "v2p_session"

// Sessions issues and verifies signed session cookies.
//
// Stateless by design: the cookie carries the principal, the principal's
// session epoch and an expiry, signed with a host-side key. Revocation is per
// principal rather than per cookie: bumping the stored epoch ends every
// session that principal holds. Deleting or rotating the key file invalidates
// every live session at once.
type Sessions struct {
	key []byte
	ttl time.Duration
}

// LoadSessions reads (creating on first start) the HMAC key at path.
func LoadSessions(path string, ttl time.Duration) (*Sessions, error) {

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {

		return nil, err
	}
	key, err := os.ReadFile(path)
	if os.IsNotExist(err) {

		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {

			return nil, err
		}
		if err := os.WriteFile(path, key, 0o600); err != nil {

			return nil, fmt.Errorf("authn: write session key: %w", err)
		}

	} else if err != nil {

		return nil, err
	}
	if len(key) < 32 {

		return nil, fmt.Errorf("authn: session key %s is %d bytes; delete it to have a new one generated", path, len(key))
	}
	return &Sessions{key: key, ttl: ttl}, nil
}

// TTL is how long an issued session lasts.
func (s *Sessions) TTL() time.Duration { return s.ttl }

// Issue returns a signed cookie value for a principal at epoch 0.
func (s *Sessions) Issue(principalID string) string { return s.IssueAt(principalID, 0) }

// IssueAt returns a signed cookie value for a principal, stamped with the
// principal's current session epoch.
//
// The cookie is still stateless; the epoch is what lets the portal end it
// early. Sign-out and a password change bump the stored epoch, and a cookie
// whose epoch is behind it is refused (see the portal's requireSession).
func (s *Sessions) IssueAt(principalID string, epoch int64) string {

	exp := time.Now().Add(s.ttl).Unix()
	body := principalID + "." + strconv.FormatInt(epoch, 10) + "." + strconv.FormatInt(exp, 10)
	return body + "." + s.sign(body)
}

// Verify returns the principal a cookie names, or ErrBadSession.
func (s *Sessions) Verify(cookie string) (string, error) {

	id, _, err := s.VerifyEpoch(cookie)
	return id, err
}

// VerifyEpoch returns the principal a cookie names and the epoch it was
// issued under, or ErrBadSession.
func (s *Sessions) VerifyEpoch(cookie string) (string, int64, error) {

	i := strings.LastIndex(cookie, ".")
	if i < 0 {

		return "", 0, ErrBadSession
	}
	body, mac := cookie[:i], cookie[i+1:]
	// Compare before parsing anything: an unsigned cookie must not reach code
	// that treats its contents as meaningful.
	if !hmac.Equal([]byte(mac), []byte(s.sign(body))) {

		return "", 0, ErrBadSession
	}
	j := strings.LastIndex(body, ".")
	if j < 0 {

		return "", 0, ErrBadSession
	}
	exp, err := strconv.ParseInt(body[j+1:], 10, 64)
	if err != nil {

		return "", 0, ErrBadSession
	}
	if time.Now().Unix() >= exp {

		return "", 0, fmt.Errorf("%w: expired", ErrBadSession)
	}
	rest := body[:j]
	k := strings.LastIndex(rest, ".")
	if k < 0 {

		return "", 0, ErrBadSession
	}
	epoch, err := strconv.ParseInt(rest[k+1:], 10, 64)
	if err != nil {

		return "", 0, ErrBadSession
	}
	return rest[:k], epoch, nil
}

// CSRFToken is a per-session value the portal puts in a hidden field on every
// mutating form. It is derived from the session rather than stored, so it needs
// no server state and cannot be replayed across sessions.
func (s *Sessions) CSRFToken(cookie string) string {

	return s.sign("csrf." + cookie)
}

// ValidCSRF compares a submitted token against the session's.
func (s *Sessions) ValidCSRF(cookie, token string) bool {

	if cookie == "" || token == "" {

		return false
	}
	return hmac.Equal([]byte(token), []byte(s.CSRFToken(cookie)))
}

func (s *Sessions) sign(body string) string {

	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
