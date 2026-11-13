// Test fixture (PocketBase >= 0.23 JSVM API).
// Proves: hooks load from the read-only /pb/app mount, and a hook that tries
// to modify its own package fails. The authoritative check is
// host-side (marker file must not exist); the log line is a convenience.

routerAdd("GET", "/fixture/ping", (e) => {
    return e.json(200, { fixture: "basic-hook", ok: true });
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
