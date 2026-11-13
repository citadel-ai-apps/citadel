# Egress proxy (§9.4)

The Squid configuration template lives in `internal/egressctl/squid.conf.tmpl`. It is
`//go:embed`ed, because the control plane renders it from the active grants on every
reconcile tick and cannot rely on a repository path. What it renders, and why, is
documented in the template's header comment.

`deploy/registry/` holds the zot configuration.
