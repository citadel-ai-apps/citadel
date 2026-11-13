package pkgvalidate

import "errors"

// One sentinel per checklist row in design §6, so a caller can tell a
// zip-structure problem from a manifest problem from a policy refusal, and so
// each rule's test can name the error it expects rather than matching on text.
//
// Every error returned by this package wraps one of these AND names the
// offending path or host: §6 calls the upload path "a developer-facing product
// surface", and "invalid package" is not a product.
var (
	ErrNotZip             = errors.New("pkgvalidate: not a readable zip archive")
	ErrTooLarge           = errors.New("pkgvalidate: package is too large")
	ErrTooManyFiles       = errors.New("pkgvalidate: package has too many files")
	ErrZipBomb            = errors.New("pkgvalidate: compression ratio is implausible")
	ErrForeignPath        = errors.New("pkgvalidate: entry is outside the allowed directories")
	ErrTraversal          = errors.New("pkgvalidate: entry path escapes the package")
	ErrSymlink            = errors.New("pkgvalidate: entry is a link")
	ErrNodeType           = errors.New("pkgvalidate: entry is not a regular file or directory")
	ErrExecBit            = errors.New("pkgvalidate: entry is executable or setuid/setgid")
	ErrNonJS              = errors.New("pkgvalidate: entry must be a .js file")
	ErrManifest           = errors.New("pkgvalidate: pbapp.json is invalid")
	ErrRange              = errors.New("pkgvalidate: pocketbase version range is invalid")
	ErrEgressPolicy       = errors.New("pkgvalidate: egress host is not allowlistable")
	ErrRefusedSubject     = errors.New("pkgvalidate: egress host was previously denied or revoked for this tenant")
	ErrNoSupportedRuntime = errors.New("pkgvalidate: version range matches no supported runtime")
)
