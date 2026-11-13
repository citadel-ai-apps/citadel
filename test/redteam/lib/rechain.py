#!/usr/bin/env python3
"""Recompute the audit hash chain the way an operator with root would.

This is the wholesale-rewrite attack of design §14.4: edit a row, then
recompute every hash after it so the table agrees with itself again. A
verification that only recomputes locally passes such a table; only an anchor
signed before the rewrite can contradict it.

It mirrors internal/auditlog/auditlog.go (chainHash, chainHashV2). Mirrors
drift, so `selfcheck` comes first: it recomputes the stored chain untouched,
and if the mirror cannot reproduce it, the red-team driver reports a broken
probe rather than a contained attack.

Usage:
  rechain.py selfcheck <state.db>
  rechain.py rewrite   <state.db> <seq>     # set action='tampered' at seq, re-chain to the head
"""
import hashlib
import sqlite3
import struct
import sys

V2_DOMAIN = b"citadel-audit-v2\x00"
GENESIS = "0" * 64
COLS = ("seq, id, occurred_at, actor_id, actor_kind, on_behalf_of, tenant_id, action, "
        "subject_ref, detail_json, request_id, source_ip, prev_hash, hash, hash_version")


def be64(n):
    return struct.pack(">Q", n)


def lp(h, s):
    b = (s or "").encode()
    h.update(be64(len(b)))
    h.update(b)


def go_ts(s):
    """occurred_at as time.Format("2006-01-02T15:04:05.999999Z") would print it:
    the fractional part loses trailing zeros, and the dot goes with an empty one."""
    if "." not in s:
        return s
    head, frac = s.split(".", 1)
    digits = frac.rstrip("Z").rstrip("0")
    return head + ("." + digits if digits else "") + "Z"


def hash_row(r, prev):
    if r["hash_version"] == 2:
        h = hashlib.sha256()
        h.update(V2_DOMAIN)
        h.update(be64(r["seq"]))
        for k in ("occurred_at", "id", "actor_id", "actor_kind", "on_behalf_of", "tenant_id",
                  "action", "subject_ref", "detail_json", "request_id", "source_ip"):
            lp(h, r[k])
        lp(h, prev)
        return h.hexdigest()
    h = hashlib.sha256()
    h.update(be64(r["seq"]))
    for v in (go_ts(r["occurred_at"]), r["actor_id"], r["action"], r["subject_ref"],
              r["detail_json"], prev):
        lp(h, v)
    return h.hexdigest()


def rows(db):
    db.row_factory = sqlite3.Row
    return [dict(r) for r in db.execute("SELECT " + COLS + " FROM audit_event ORDER BY seq")]


def selfcheck(db):
    prev = GENESIS
    rs = rows(db)
    for r in rs:
        if r["prev_hash"] != prev:
            return "seq %d: stored prev_hash does not chain (mirror or table is wrong)" % r["seq"]
        got = hash_row(r, prev)
        if got != r["hash"]:
            return "seq %d (v%d): mirror computes %s, table holds %s" % (
                r["seq"], r["hash_version"], got[:12], r["hash"][:12])
        prev = r["hash"]
    return "" if rs else "no audit rows"


def rewrite(db, seq):
    rs = rows(db)
    db.execute("DROP TRIGGER IF EXISTS audit_event_no_update")
    prev = GENESIS
    touched = 0
    for r in rs:
        if r["seq"] == seq:
            r["action"] = "tampered"
        if r["seq"] >= seq:
            r["prev_hash"] = prev
            r["hash"] = hash_row(r, prev)
            db.execute("UPDATE audit_event SET action=?, prev_hash=?, hash=? WHERE seq=?",
                       (r["action"], r["prev_hash"], r["hash"], r["seq"]))
            touched += 1
        prev = r["hash"]
    db.commit()
    return touched


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    db = sqlite3.connect(sys.argv[2])
    if sys.argv[1] == "selfcheck":
        msg = selfcheck(db)
        if msg:
            print("rechain: " + msg)
            return 3
        print("rechain: the mirror reproduces the stored chain")
        return 0
    if sys.argv[1] == "rewrite":
        n = rewrite(db, int(sys.argv[3]))
        # The rewritten table must agree with itself — that is the attack.
        msg = selfcheck(db)
        if msg:
            print("rechain: the rewrite is not self-consistent: " + msg)
            return 3
        print("rechain: rewrote seq %s and re-chained %d rows; the table verifies locally" % (sys.argv[3], n))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
