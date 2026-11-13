// Red-team: the two halves of an egress grant (design §13.3).
//
// The manifest names exactly one host, `example.com`, which is a concrete FQDN
// outside every denied range and therefore Tier 1 — auto-granted, recorded,
// with the platform principal as the decider (§14.3).
//
// So this package tests both directions at once:
//
//   egress-allowed  the granted host must be reachable. A platform that denies
//                   by default and then also denies what it approved is not
//                   secure, it is broken, and the difference matters.
//   egress-denied   every other host must be refused BY THE PROXY — a 403 with
//                   a log line naming this tenant — rather than by a timeout.
//
// The manifest is the REQUEST. Nothing here can grant anything: if the request
// had named a wildcard or a previously revoked subject, the deploy would have
// shipped with it pending and this route would report it unreachable.
//
// EVERYTHING LIVES INSIDE THE HANDLER, deliberately. PocketBase serialises a
// handler and runs it in a pooled goja runtime that does not carry the
// enclosing module scope, so a top-level `const` or helper is a
// `ReferenceError` at request time and nowhere else. This was found the
// slow way (design.md §9.4).

routerAdd("GET", "/redteam/egress", (e) => {
    const ALLOWED = "https://example.com/";
    const DENIED = "https://www.google.com/";

    // probe returns what actually happened, distinguishing the three outcomes a
    // developer needs to tell apart: it worked, the proxy said no, or nothing
    // answered at all.
    const probe = (url) => {
        try {
            const res = $http.send({ url: url, method: "GET", timeout: 8 });
            if (res.statusCode === 403 || res.statusCode === 407) {
                return { reached: false, refused: true, status: res.statusCode };
            }
            return { reached: true, refused: false, status: res.statusCode };
        } catch (err) {
            // Two different failures arrive here, and telling them apart is
            // the whole point of §9.4's four reasons:
            //
            //   refused  the proxy answered and said no. With TLS that is a
            //            connection RESET rather than a 403 body — the proxy
            //            resets a denied request precisely so it never has to
            //            generate a certificate to carry an error page.
            //   no route the netfilter DROP, before any proxy was involved.
            //            This is what a tenant with no grant at all sees.
            const msg = String(err);
            const refused = /reset|EOF|broken pipe|connection refused/i.test(msg);
            return { reached: false, refused: refused, error: msg };
        }
    };

    // The route answers 200 whatever happens. PocketBase's generic 400 tells
    // the driver nothing about which boundary was hit, and "the hook threw" and
    // "the host was unreachable" are the two answers that most need telling
    // apart.
    let allowed, denied, err = "";
    try {
        allowed = probe(ALLOWED);
        denied = probe(DENIED);
    } catch (e2) {
        err = String(e2);
    }
    return e.json(200, {
        fixture: "egress-probe",
        allowed: allowed || { reached: false, error: err },
        denied: denied || { reached: false, error: err },
        hook_error: err,
    });
});

routerAdd("GET", "/redteam/ping", (e) => e.json(200, { ok: true }));
