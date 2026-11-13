#!/usr/bin/env python3
"""Apply the empty-line ast-grep rules mechanically.

The three whitespace rules in rules/ have no `fix:` block, so this script applies
them. It drives every edit off ast-grep's own match ranges rather than a regex
over the source, which is what makes it safe: a `{` inside a string literal or a
comment is never a `block` node, so it can never be touched.

    hack/lint/blankline-fix.py brace  rules/empty-line-after-brace.yml
    hack/lint/blankline-fix.py switch rules/empty-line-after-switch-brace.yml
    hack/lint/blankline-fix.py else   rules/empty-line-before-else.yml

Run one mode at a time and re-scan between modes: every insertion shifts the byte
offsets that the next scan reports. Follow up with `gofmt -l .` — gofmt preserves
a blank line immediately after an opening brace, so the result stays gofmt-clean.
"""

import collections
import json
import re
import subprocess
import sys

# A `}` on its own line, preceded by a non-blank line, and followed by `else`.
# Group 1 is the newline that ends that preceding line — the insertion point.
ELSE_RE = re.compile(rb"\S([ \t]*\n)[ \t]*\}[ \t]*else\b")


def matches(rule_path, root):
    """Byte spans reported by `ast-grep scan`, grouped by file."""
    with open(rule_path) as fh:
        rule = fh.read()
    proc = subprocess.run(
        ["ast-grep", "scan", "--inline-rules", rule, "--json=stream", root],
        capture_output=True, text=True, check=False,
    )
    by_file = collections.defaultdict(list)
    for line in proc.stdout.splitlines():
        line = line.strip()
        # The trailing "Error: N error(s) found" summary is not JSON.
        if not line.startswith("{"):
            continue
        m = json.loads(line)
        span = m["range"]["byteOffset"]
        by_file[m["file"]].append((span["start"], span["end"]))
    return by_file


def offsets(mode, blob, start, end):
    """Where to insert a newline, for one match of one rule."""
    segment = blob[start:end]

    if mode == "brace":
        # The match is the block node itself, so it starts at the `{`.
        assert blob[start:start + 1] == b"{", (start, blob[start:start + 1])
        return [start + 1]

    if mode == "switch":
        # The rule's regex guarantees no `{` inside the switch header.
        return [start + segment.index(b"{") + 1]

    return [start + m.start(1) for m in ELSE_RE.finditer(segment)]


def main():
    mode, rule_path = sys.argv[1], sys.argv[2]
    root = sys.argv[3] if len(sys.argv) > 3 else "."
    if mode not in ("brace", "switch", "else"):
        sys.exit(f"unknown mode {mode!r}; want brace, switch or else")

    inserted = 0
    by_file = matches(rule_path, root)
    for path, spans in by_file.items():
        with open(path, "rb") as fh:
            blob = fh.read()
        points = set()
        for start, end in spans:
            points.update(offsets(mode, blob, start, end))
        # Descending, so an earlier insertion never shifts a later offset.
        for point in sorted(points, reverse=True):
            blob = blob[:point] + b"\n" + blob[point:]
            inserted += 1
        with open(path, "wb") as fh:
            fh.write(blob)

    print(f"{mode}: inserted {inserted} blank lines across {len(by_file)} files")


if __name__ == "__main__":
    main()
