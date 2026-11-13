// A package that works fine, and says so only up to 0.38.x.
//
// The compatibility-gate half of §12: an upgrade past the declared maximum is
// BLOCKED before anything is copied or booted, because the tenant has already
// told the platform their hooks were written against that range. Nothing is
// touched and no rehearsal runs — the refusal is cheaper than the evidence.

routerAdd("GET", "/fixture/ping", (c) => {
    return c.json(200, { fixture: "pkg-pinned", ok: true });
});
