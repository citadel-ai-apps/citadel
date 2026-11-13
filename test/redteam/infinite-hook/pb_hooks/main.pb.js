// Red-team: infinite-hook (design §13.3) — a tenant that wedges or crashes its
// own instance must cost the platform a bounded amount, and nothing more.
//
// Two different shapes, because they stress different controls:
//
//   /redteam/hang?s=N  a handler that burns a CPU for N seconds. One of them is
//                      not a test of anything: PocketBase serves other requests
//                      on other goroutines and /api/health stays green. Several
//                      at once are, because they ask for more CPU than --cpus
//                      gives the sandbox, and the driver asserts that the OTHER
//                      tenant does not feel it.
//
//   /redteam/arm       writes a marker into pb_data and exits the process. The
//                      onBootstrap hook below exits again on every boot while
//                      the marker is there: a crash loop the tenant controls
//                      and cannot leave. This is what the restart ladder exists
//                      for — 1s, 5s, 30s, 2m, then `failed` (§8.3) — rather
//                      than Docker's restart policy, which has no backoff and
//                      would make this a restart storm on the host. The driver
//                      removes the marker from the host side afterwards.
//
// The `/redteam/ping` route never hangs, so the driver can tell "the instance
// is wedged" from "the instance is gone".
//
// EVERYTHING LIVES INSIDE THE HANDLER (design.md §9.4).

onBootstrap((e) => {
    let armed = false;
    try {
        $os.stat("/pb/pb_data/rt-crashloop");
        armed = true;
    } catch (_) {
        // no marker: boot normally
    }
    if (armed) {
        console.log("redteam: crash-loop marker present; exiting during bootstrap");
        $os.exit(1);
    }
    e.next();
});

routerAdd("GET", "/redteam/ping", (e) => e.json(200, { ok: true }));

routerAdd("GET", "/redteam/hang", (e) => {
    // A busy loop rather than a sleep: a sleeping goroutine yields, and the
    // point is to hold the handler and burn the CPU share at the same time.
    const secs = parseInt(e.request.url.query().get("s") || "3600", 10);
    const until = Date.now() + 1000 * secs;
    let n = 0;
    while (Date.now() < until) {
        n++;
    }
    return e.json(200, { fixture: "infinite-hook", spun: n });
});

routerAdd("GET", "/redteam/arm", (e) => {
    $os.writeFile("/pb/pb_data/rt-crashloop", "armed by the red-team crash-loop probe\n", 0o644);
    console.log("redteam: crash-loop armed; exiting");
    $os.exit(1);
    return e.json(200, { unreachable: true });
});
