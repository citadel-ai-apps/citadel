#!/usr/bin/env python3
"""Build a tenant package zip from a fixture directory.

The wire format is one zip (design §6), so the acceptance suite uploads a real
zip rather than leaning on citadel's --app-dir convenience: that is the path CI
and the portal's file input take. python3 rather than zip(1) because the VM has
the former (hack/bootstrap-vm.sh needs it) and not the latter.

Usage: pack.py <fixture-dir> <out.zip>
"""
import os
import sys
import zipfile


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: pack.py <fixture-dir> <out.zip>")
    src, out = sys.argv[1], sys.argv[2]
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(src):
            for name in files:
                path = os.path.join(root, name)
                # Relative, forward-slashed entry names with no directory
                # entries: exactly what internal/pkgvalidate expects to see.
                z.write(path, os.path.relpath(path, src).replace(os.sep, "/"))


if __name__ == "__main__":
    main()
