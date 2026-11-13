// Red-team: log-flood — stdout is a write path onto the HOST's disk.
//
// A tenant's writes to pb_data are bounded by its loopback image (D4). Its
// writes to stdout are not: they land in the container runtime's own log file
// under /var/lib/docker, outside every quota the platform enforces, and in the
// control plane's collected copy under <pb_root>/logs. Both must be bounded,
// or a hook printing in a loop fills the host disk the other tenants and the
// control plane share.
//
// The route writes `mib` MiB of 1 KiB lines. The driver picks a size well past
// the configured caps and asserts that what is on disk afterwards is not.
//
// EVERYTHING LIVES INSIDE THE HANDLER (design.md §9.4).

routerAdd("GET", "/redteam/flood", (e) => {
    const mib = parseInt(e.request.url.query().get("mib") || "64", 10);
    const line = "redteam-log-flood " + "x".repeat(1024 - 19 - 1);
    let lines = 0;
    let err = "";
    try {
        for (let i = 0; i < mib * 1024; i++) {
            console.log(line);
            lines++;
        }
    } catch (x) {
        err = String(x);
    }
    return e.json(200, {
        fixture: "log-flood",
        // The positive control: the bytes really were written to stdout.
        written_mib: Math.floor(lines / 1024),
        error: err,
    });
});

routerAdd("GET", "/redteam/ping", (e) => e.json(200, { ok: true }));
