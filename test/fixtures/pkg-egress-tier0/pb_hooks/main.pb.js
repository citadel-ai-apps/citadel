// Test fixture, rev 1 (PocketBase >= 0.23 JSVM API).
//
// The uploaded-package twin of test/fixtures/basic-hook: same self-write escape
// attempt, plus a ping whose payload identifies the revision, so
// a deploy and a rollback are distinguishable from outside the container.

routerAdd("GET", "/fixture/ping", (e) => {
    return e.json(200, { fixture: "pkg-basic", ok: true, rev: 1 });
});

onBootstrap((e) => {
    e.next();
    try {
        $os.writeFile("/pb/app/pb_hooks/ESCAPE_MARKER", "must never exist", 0o644);
        console.log("fixture: self-write UNEXPECTEDLY SUCCEEDED");
    } catch (err) {
        console.log("fixture: self-write failed as expected");
    }
});
