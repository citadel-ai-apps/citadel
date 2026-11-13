// Red-team: backup-bomb — a file whose SIZE the quota does not bound.
//
// The loopback image bounds the blocks a tenant can write (D4), not the size a
// file claims. $os.truncate extends a file to any length without writing a
// byte: on ext4 that is a sparse file, a terabyte that occupies nothing. The
// tenant's quota never notices.
//
// The host does, if it reads one. Routine backups copy pb_data's plain files
// into a scratch directory on the HOST'S filesystem, outside every quota, and a
// plain copy of a sparse file writes every hole out as zeroes. One `truncate`
// in a hook turns the next nightly backup into a write of whatever size the
// hook chose — onto the disk the whole fleet shares.
//
// The driver picks a size above the tenant's image (so a copy that honoured
// the quota could never hold it) and well below the host's free space (so the
// probe cannot itself take the host down), then watches routine backups run.
//
// EVERYTHING LIVES INSIDE THE HANDLER (design.md §9.4).

routerAdd("GET", "/redteam/sparse", (e) => {
    const bytes = parseInt(e.request.url.query().get("bytes") || "0", 10);
    const path = "/pb/pb_data/storage/rt-sparse.bin";
    let size = 0;
    let err = "";
    try {
        $os.mkdirAll("/pb/pb_data/storage", 0o755);
        // truncate needs an existing file.
        $os.writeFile(path, "", 0o644);
        $os.truncate(path, bytes);
        size = $os.stat(path).size();
    } catch (x) {
        err = String(x);
    }
    // The positive control: the file really claims the size asked for.
    return e.json(200, { fixture: "backup-bomb", path: path, size: size, error: err });
});

routerAdd("GET", "/redteam/unsparse", (e) => {
    let err = "";
    try {
        $os.remove("/pb/pb_data/storage/rt-sparse.bin");
    } catch (x) {
        err = String(x);
    }
    return e.json(200, { fixture: "backup-bomb", removed: err === "", error: err });
});

routerAdd("GET", "/redteam/ping", (e) => e.json(200, { ok: true }));
