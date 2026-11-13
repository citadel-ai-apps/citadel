# edge-caddy

The edge proxy image, with the Caddy rate-limit module compiled in.

```
make edge-image                       # build, push by digest, record it
```

The digest lands in `images/edge-caddy/digests.txt` and goes into the control plane's
`edge_image` setting. Never schedule by tag.

Design §10 needs per-tenant rate limits, which stock `caddy:2` cannot express. Without this
image, `internal/proxyctl` publishes routes *without* limits and records a `rate_limit` drift
entry.

The edge runs no tenant code, so it keeps its shell and upstream base and runs on `runc`. Like
every platform container it gets no Docker socket and no `--privileged`. It drops every
capability and adds back only `NET_BIND_SERVICE`, to bind the edge ports (design INV-15).
Its admin API is a unix socket, not a port (§10).
