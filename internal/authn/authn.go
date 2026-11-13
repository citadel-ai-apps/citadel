// Package authn holds the control plane's own credentials: portal passwords,
// API tokens and session cookies.
//
// Control-plane identity is separate from every tenant's PocketBase.
// The tenant is superuser of their own instance and can delete any account the
// platform creates there, so an account in a tenant's database can never be the
// thing that authorises a platform operation.
//
// D6 (own store) and D16 (local accounts) are decided. The shape is what keeps
// SSO a drop-in: a principal authenticates, and everything downstream works
// from the resulting identity.Actor. Under SSO the credential source changes
// and nothing else does.
package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Errors callers branch on.
var (
	ErrBadCredentials = errors.New("authn: unknown principal or wrong password")
	ErrBadToken       = errors.New("authn: token is not valid")
	ErrWeakPassword   = errors.New("authn: password is too short")
)

// MinPasswordLen is deliberately about length rather than character classes:
// composition rules push people towards shorter, more guessable passwords.
const MinPasswordLen = 12

// Algo is the password hashing algorithm recorded on every credential row, so
// a later migration can tell old hashes from new ones without guessing.
const Algo = "argon2id"

// argon2id parameters. Interactive use, so the cost is tuned for a login that
// feels instant while staying expensive per guess: 64 MiB is far beyond what a
// GPU attack amortises well.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword returns an encoded argon2id hash of pw.
func HashPassword(pw string) (string, error) {

	if len(pw) < MinPasswordLen {

		return "", fmt.Errorf("%w: %d characters, minimum %d", ErrWeakPassword, len(pw), MinPasswordLen)
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {

		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks pw against an encoded hash in constant time.
//
// The parameters come from the stored hash, not from the constants above, so
// credentials written before a cost change keep verifying.
func VerifyPassword(encoded, pw string) bool {

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {

		return false
	}
	var version, memory, time, threads int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {

		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {

		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {

		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {

		return false
	}
	got := argon2.IDKey([]byte(pw), salt, uint32(time), uint32(memory), uint8(threads), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// TokenPrefix marks a control-plane API token in logs, config files and
// secret scanners.
const TokenPrefix = "v2p"

// NewToken mints a token for a token row id and returns the plaintext to show
// once, plus the hash to store.
//
// The id travels in the token so a presented token can be looked up by primary
// key rather than by scanning every row's hash.
func NewToken(tokenID string) (plaintext, hash string) {

	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {

		panic("authn: crypto/rand failed: " + err.Error())
	}
	secret := base64.RawURLEncoding.EncodeToString(b[:])
	return TokenPrefix + "_" + tokenID + "_" + secret, HashToken(secret)
}

// HashToken is the stored form of a token's secret half. A plain sha256 is
// right here and argon2 is not: the secret is 256 bits of entropy this package
// generated, so there is no guessing attack to slow down — only a database
// leak to make useless.
func HashToken(secret string) string {

	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// SplitToken pulls the row id and secret out of a presented token.
func SplitToken(token string) (id, secret string, err error) {

	// SplitN, not Split: the secret is base64url, whose alphabet includes the
	// separator. Splitting greedily would reject most valid tokens.
	parts := strings.SplitN(token, "_", 3)
	if len(parts) != 3 || parts[0] != TokenPrefix || parts[1] == "" || parts[2] == "" {

		return "", "", fmt.Errorf("%w: expected %s_<id>_<secret>", ErrBadToken, TokenPrefix)
	}
	return parts[1], parts[2], nil
}

// EqualTokenHash compares two stored token hashes in constant time.
func EqualTokenHash(a, b string) bool {

	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
