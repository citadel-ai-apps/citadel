// Test fixture for PocketBase 0.22.x (pre-0.23 JSVM API: echo context,
// onAfterBootstrap). Same assertions as ../basic-hook.

routerAdd("GET", "/fixture/ping", (c) => {
    return c.json(200, { fixture: "basic-hook", ok: true });
});

onAfterBootstrap((e) => {
    try {
        $os.writeFile("/pb/app/pb_hooks/ESCAPE_MARKER", "must never exist", 0o644);
        console.log("fixture: self-write UNEXPECTEDLY SUCCEEDED");
    } catch (err) {
        console.log("fixture: self-write failed as expected");
    }
});
