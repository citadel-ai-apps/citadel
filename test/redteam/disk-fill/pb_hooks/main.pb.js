// Red-team: disk-fill (design §13.3).
//
// Writes into pb_data until the filesystem refuses. What must hold:
//
//   - the write stops at the QUOTA, not at the host's disk. D4 chose a loopback
//     ext4 image precisely so the quota is enforced by construction: ENOSPC
//     comes from the image boundary and the host never notices
//     (design.md §7);
//   - the host is unaffected — no other tenant loses write capacity;
//   - the instance is still there afterwards. A full disk is a tenant problem,
//     not a platform outage.
//
// Deliberately not run on the same instance as anything else: it ends with a
// full data volume, and the next test would then be measuring the wrong thing.

// Everything inside the handler: PocketBase runs a serialised handler in a
// pooled goja runtime with no access to the enclosing module scope, so a
// top-level const is a ReferenceError at request time (design.md §9.4).
routerAdd("GET", "/redteam/fill", (e) => {
    const CHUNK = "x".repeat(1024 * 1024); // 1 MiB
    let written = 0;
    let stoppedBy = "";
    try {
        // The quota is 2 GiB by default (§4 sizing); the cap here is well above
        // it so the filesystem is what stops the loop, not the loop itself.
        for (let i = 0; i < 4096; i++) {
            $os.writeFile("/pb/pb_data/redteam-fill-" + i, CHUNK, 0o600);
            written++;
        }
        stoppedBy = "nothing — the loop finished, which means there was no quota";
    } catch (err) {
        stoppedBy = String(err);
    }
    return e.json(200, {
        fixture: "disk-fill",
        written_mib: written,
        stopped_by: stoppedBy,
        // The driver asserts this: a loop that completes has found no boundary.
        bounded: written < 4096,
    });
});

routerAdd("GET", "/redteam/ping", (e) => e.json(200, { ok: true }));
