# egress-proxy

The forward proxy that is the only way out of the sandbox (design §9.4).

```
make egress-image      # builds, pushes 127.0.0.1:5000/egress-proxy:6-r2, records its digest
```

The control plane schedules it by digest. Unless `egress_proxy_image` is set, it uses
the newest entry for the host's architecture in `digests.txt` (`<squid> r<rev> <arch>
<digest>`). The build also tags `v2p-squid:6-r2` locally for the netprobe scripts that
run Squid by hand.

**What is pinned.** The Alpine base is pinned by its multi-arch index digest. The
packages are not: Alpine keeps only the newest build of a package in a stable branch,
so a pinned version stops installing at its first security fix. The built image is
what gets scheduled, so a rebuild that picks up newer packages shows up as a new line
in `digests.txt`. A running proxy never changes silently. Bumping the base digest
is a `PROXY_REV` bump.

**Builds are reproducible.** Rebuilding unchanged inputs gives the same digest, and
`make egress-image` adds no line. Every mtime is pinned, `/etc/shadow`'s day stamp is
cleared, and nothing random is generated at build time. A new line for the same
`<squid> r<rev> <arch>` means Alpine shipped newer packages or the Containerfile changed.

**Why it is built rather than pulled.** SNI filtering needs Squid built with OpenSSL, and
`ubuntu/squid` is not. With CONNECT-target-only filtering, a hook could CONNECT to an
allowed host and negotiate TLS for another. The image uses Alpine's package, and the build
fails if OpenSSL support disappears.

**The startup certificate is not a MITM.** Squid only consults `ssl_bump` on an
`ssl-bump` port, and that port will not start without `tls-cert=` and `sslcrtd_program`,
even though nothing is ever bumped. The entrypoint (`start.sh`) generates a throwaway
certificate under `/run` each time the container starts, so no key ships in the image.
`/etc/squid/bump.pem` is a symlink to it. Two things keep it honest. `deny_info TCP_RESET all`
resets refusals instead of serving an error page inside TLS. And
`test/netprobe/10-sni-mismatch.sh` requires spliced sessions to verify against the real
origin certificate.
