// Red-team: tier2-kinds — kind confusion across the grant model (design §14.2,
// §14.3, §16).
//
// The manifest can only request `egress_host`. Every other kind is requested
// through the grants API, and the driver does that: it asks for an
// `oauth_provider`, an `object_storage` and a `custom_domain` grant whose
// subjects are exactly the hostnames probed below, then approves them.
//
// Nothing enforces those kinds yet (§16). So the boundary under test is that a
// grant of the WRONG KIND never opens egress: a hostname approved as an OAuth
// provider is not an approved egress host. Pending or approved, every probe
// here must be REFUSED BY THE PROXY.
//
// The targets are real, resolvable hosts on purpose. A host that does not
// resolve fails whatever the proxy does, and a probe that cannot fail proves
// nothing; the driver asserts `refused`, not merely "not reached".
//
// EVERYTHING LIVES INSIDE THE HANDLER, deliberately. PocketBase serialises a
// handler and runs it in a pooled goja runtime that does not carry the
// enclosing module scope (design.md §9.4).

routerAdd("GET", "/redteam/tier2", (e) => {
    // One subject per outbound Tier-2 kind. The driver requests grants with
    // these exact subjects, so the two lists must stay in step.
    const TARGETS = {
        oauth_provider: "https://accounts.google.com/",
        object_storage: "https://storage.googleapis.com/",
        custom_domain: "https://www.iana.org/",
    };

    // Same three outcomes as egress-probe: it worked, the proxy said no, or
    // nothing answered at all. Only the second one is a pass.
    const probe = (url) => {
        try {
            const res = $http.send({ url: url, method: "GET", timeout: 8 });
            if (res.statusCode === 403 || res.statusCode === 407) {
                return { reached: false, refused: true, status: res.statusCode };
            }
            return { reached: true, refused: false, status: res.statusCode };
        } catch (err) {
            const msg = String(err);
            const refused = /reset|EOF|broken pipe|connection refused/i.test(msg);
            return { reached: false, refused: refused, error: msg };
        }
    };

    // The route answers 200 whatever happens, and reports a thrown hook as
    // hook_error rather than PocketBase's generic 400: the driver treats a
    // missing or errored report as a broken probe, never as "contained".
    const targets = {};
    let err = "";
    try {
        for (const kind in TARGETS) {
            targets[kind] = probe(TARGETS[kind]);
        }
    } catch (e2) {
        err = String(e2);
    }
    return e.json(200, {
        fixture: "tier2-probe",
        targets: targets,
        hook_error: err,
    });
});

routerAdd("GET", "/redteam/ping", (e) => e.json(200, { ok: true }));
