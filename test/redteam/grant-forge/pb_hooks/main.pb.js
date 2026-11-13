// Red-team: grant-forge (design §13.3) — a manifest declaration is a request,
// never a grant.
//
// The manifest declares a WILDCARD host. §14.3 puts wildcards at Tier 2: a
// named human approver, a justification and an expiry. And §14.3 also says a
// deploy never blocks on a Tier-2 grant, so this package ships — successfully,
// healthy, serving — with the host pending and unreachable.
//
// That combination is the whole test. If a manifest declaration were enforced,
// editing one file would grant a tenant external access with no approver, no
// expiry and no record of the decision. Here the file is edited, the deploy
// succeeds, and the host is still unreachable; the only thing the tenant got
// was a place in an approval queue with their name on it.
//
// The portal names it as awaiting approval rather than reporting a failure,
// which is the §9.4 position that a denial is a product surface.

routerAdd("GET", "/redteam/forge", (e) => {
    // Same three outcomes as egress-probe: it worked, the proxy said no, or
    // nothing answered. The driver asserts the SECOND, so a hook that threw or
    // a host that never resolved cannot pass as "contained".
    let outcome;
    try {
        const res = $http.send({ url: "https://hooks.slack.com/services/x", method: "GET", timeout: 8 });
        const refused = res.statusCode === 403 || res.statusCode === 407;
        outcome = { reached: !refused, refused: refused, status: res.statusCode };
    } catch (err) {
        const msg = String(err);
        outcome = { reached: false, refused: /reset|EOF|broken pipe|connection refused/i.test(msg), error: msg };
    }
    return e.json(200, { fixture: "grant-forge", wildcard: outcome, hook_error: "" });
});

routerAdd("GET", "/redteam/ping", (e) => e.json(200, { ok: true }));
