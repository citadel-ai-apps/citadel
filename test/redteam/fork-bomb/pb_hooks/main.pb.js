// Red-team: fork-bomb (design §13.3).
//
// --pids-limit and --memory are what contain this. Process exhaustion inside
// one sandbox must not become process exhaustion on the host, where it would
// take every other tenant and the control plane with it.
//
// The image is FROM scratch, so the classic `sh -c 'while :; do :; done &'`
// never starts — and a probe built on it spawns nothing and reports "bounded"
// without having touched a limit. The image is not empty, though: /pb/pbsnap
// and /pb/pocketbase are real executables. pbsnap streaming data.db into a
// pipe nobody reads blocks once the pipe fills, so every child stays alive and
// holds a process slot, its threads and its memory until it is killed.
//
// The driver asserts that at least one child started (the positive control:
// otherwise nothing was tested), that the loop stopped on a RESOURCE error
// rather than finishing, and which one it was.
//
// EVERYTHING LIVES INSIDE THE HANDLER (design.md §9.4).

routerAdd("GET", "/redteam/fork", (e) => {
    const MAX = 4096;
    const children = [];
    let stoppedBy = "";
    try {
        for (let i = 0; i < MAX; i++) {
            const cmd = $os.cmd("/pb/pbsnap", "data.db");
            cmd.stdoutPipe(); // never read: the child blocks once the pipe is full
            cmd.start();
            children.push(cmd);
        }
        stoppedBy = "nothing — " + MAX + " processes started, so there is no limit";
    } catch (err) {
        stoppedBy = String(err);
    }
    const spawned = children.length;
    // Release them, so the instance answers the driver's next request.
    for (const c of children) {
        try { c.process.kill(); } catch (_) {}
        try { c.wait(); } catch (_) {}
    }
    let limit = "none";
    if (/resource temporarily unavailable|EAGAIN/i.test(stoppedBy)) {
        limit = "pids";
    } else if (/cannot allocate memory|ENOMEM|out of memory/i.test(stoppedBy)) {
        limit = "memory";
    }
    return e.json(200, {
        fixture: "fork-bomb",
        spawned: spawned,
        stopped_by: stoppedBy,
        limit: limit,
        bounded: spawned < MAX,
    });
});

routerAdd("GET", "/redteam/ping", (e) => e.json(200, { ok: true }));
