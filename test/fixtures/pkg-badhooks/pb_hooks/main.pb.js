// A package whose hooks work on the 0.22 JSVM API and CANNOT work on a current
// one. The deliberately incompatible case of design §16's Phase 7 done-when.
//
// The breakage is real, not simulated. `onAfterBootstrap` was removed in the
// 0.23 rework; on a newer binary the call below is a ReferenceError, which
// aborts the whole hook file at registration time — so the route registered
// after it is never added and /fixture/ping answers 404.
//
// That ordering is the point. It produces BOTH signals a rehearsal has to
// catch: a hook-registration error on the instance's stdout, and a smoke
// request that fails from the probe's side. The manifest range deliberately
// ADMITS the target version, so the compatibility gate lets this through and
// the rehearsal is what stops it — which is the thing being tested.

onAfterBootstrap((e) => {
    console.log("fixture: legacy bootstrap hook ran");
});

routerAdd("GET", "/fixture/ping", (c) => {
    return c.json(200, { fixture: "pkg-badhooks", ok: true });
});
