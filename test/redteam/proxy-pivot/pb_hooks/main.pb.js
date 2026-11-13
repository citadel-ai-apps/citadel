// Red-team: proxy-pivot — a granted NAME that points somewhere no grant may go.
//
// The egress proxy is the one platform component a granted tenant can make
// connect anywhere, and it connects from the platform's side of every netfilter
// rule. The allowlist is by name, and a name is only as good as what it
// resolves to: a host the tenant controls can be approved while it points at a
// public address and then re-pointed at the metadata endpoint, at another
// tenant's bridge, at the host itself, or at the edge's public listener —
// which routes by Host header to every other tenant (§9.1 route 3 through the
// proxy). Squid's `v2p_blocked_dst` condition on every allow line is what must
// refuse those, whatever name led there (§9.5).
//
// /redteam/pivot?url=...&host=... sends one request through HTTP_PROXY, the way
// any cooperating hook would, optionally with a Host header, and reports what
// it got. That is not the verdict: from in here, "the proxy cut the bumped TLS
// session" and "the proxy dialled the edge and its certificate failed" look the
// same. The driver judges each request by the proxy's access log instead, where
// TCP_DENIED with no upstream hop is the only refusal.
//
// EVERYTHING LIVES INSIDE THE HANDLER (design.md §9.4).

routerAdd("GET", "/redteam/pivot", (e) => {
    const q = e.request.url.query();
    const url = q.get("url");
    const host = q.get("host");
    let out;
    try {
        const req = { url: url, method: "GET", timeout: 8 };
        if (host) {
            req.headers = { "Host": host };
        }
        const res = $http.send(req);
        const refused = res.statusCode === 403 || res.statusCode === 407;
        out = { reached: !refused, refused: refused, status: res.statusCode };
    } catch (err) {
        // A refused CONNECT is a reset (deny_info TCP_RESET, §9.4); "network is
        // unreachable" means the tenant is not on the egress network at all.
        const msg = String(err);
        out = { reached: false, refused: /reset|EOF|broken pipe|connection refused/i.test(msg), error: msg };
    }
    out.fixture = "proxy-pivot";
    out.url = url;
    return e.json(200, out);
});

routerAdd("GET", "/redteam/ping", (e) => e.json(200, { ok: true }));
