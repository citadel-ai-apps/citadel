// Red-team: memory-hog (design §13.3).
//
// Allocates until something stops it. What must hold: the OOM kill lands INSIDE
// the container and the host's own memory is never the thing under pressure.
//
// Two settings do that, and one of them is easy to get wrong: --memory bounds
// the cgroup, and --memory-swap set EQUAL to --memory is what disables swap. A
// zero memory-swap means "unlimited swap", at which point the memory limit
// stops bounding anything and this hook quietly eats the host's swap device
// instead (§4). 08-egress-acl.sh asserts the two are equal on the live
// container; this asserts the consequence.
//
// The expected outcome is the container being killed and the reconciler
// restarting it with backoff — 1s, 5s, 30s, 2m, then failed. A tenant that
// bricks itself this way is visible to an operator and costs nobody else
// anything.

routerAdd("GET", "/redteam/hog", (e) => {
    const blocks = [];
    let mib = 0;
    try {
        // The default allowance is 256 MiB (§4), so 4 GiB is far past any
        // plausible limit: reaching the end of this loop means there was none.
        for (let i = 0; i < 4096; i++) {
            blocks.push("x".repeat(1024 * 1024));
            mib++;
        }
        return e.json(200, {
            fixture: "memory-hog",
            allocated_mib: mib,
            bounded: false,
        });
    } catch (err) {
        // A JS-level allocation failure is also a pass: the limit held without
        // needing the kernel's OOM killer.
        return e.json(200, {
            fixture: "memory-hog",
            allocated_mib: mib,
            stopped_by: String(err),
            bounded: true,
        });
    }
});

routerAdd("GET", "/redteam/ping", (e) => e.json(200, { ok: true }));
