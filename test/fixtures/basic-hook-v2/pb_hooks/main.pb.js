// Test fixture (PocketBase >= 0.23 JSVM API), rev 2 of ../basic-hook.
// Deployed to prove a symlink-swap deploy makes new
// hook code live. Identical to rev 1 except for the "rev" field.

routerAdd("GET", "/fixture/ping", (e) => {
    return e.json(200, { fixture: "basic-hook", ok: true, rev: 2 });
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
