#!/usr/bin/env python3
"""Grow a qcow2 image's virtual size, in place.

    qcow2-resize.py <image.qcow2> <new-size-GiB>

This exists because UTM ships qemu-img as a library rather than an executable,
so there is no qemu-img on the PATH to call, and Ubuntu's cloud images are
3.5 GiB — enough for the OS and not enough for Docker. Requiring a Homebrew
QEMU just to change a header field is a poor trade, so this changes the header
field.

Growing a qcow2 is a header edit and nothing more, *provided* the larger L1
table still fits in the cluster already allocated to it. Each L1 entry covers
one L2 table, each L2 table maps `cluster_size / 8` clusters, and an L1 table
lives in whole clusters — so with the usual 64 KiB clusters one L1 cluster
covers 8192 * 512 MiB = 4 TiB. Well beyond any development VM. The script
refuses rather than guesses if that precondition does not hold.

Nothing else has to change: new L1 entries read as zero, which is exactly how
qcow2 spells "unallocated", and QEMU grows the refcount structures itself as
those clusters are written.

Growing only. Shrinking a qcow2 means finding and freeing the clusters past the
new end, which is a real implementation and not one worth having here.
"""

import struct
import sys

QCOW_MAGIC = 0x514649FB

# Header field offsets, from the qcow2 specification.
OFF_MAGIC = 0
OFF_VERSION = 4
OFF_CLUSTER_BITS = 20
OFF_SIZE = 24
OFF_L1_SIZE = 36
OFF_L1_OFFSET = 40


def die(msg):
    sys.exit("qcow2-resize: %s" % msg)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__.strip().splitlines()[2].strip())
    path, want_gib = sys.argv[1], float(sys.argv[2])
    new_size = int(want_gib * (1 << 30))

    with open(path, "r+b") as f:
        head = f.read(72)
        if len(head) < 72:
            die("%s is too short to be a qcow2 image" % path)

        (magic,) = struct.unpack_from(">I", head, OFF_MAGIC)
        if magic != QCOW_MAGIC:
            die("%s is not a qcow2 image" % path)
        (version,) = struct.unpack_from(">I", head, OFF_VERSION)
        if version not in (2, 3):
            die("unsupported qcow2 version %d" % version)

        (cluster_bits,) = struct.unpack_from(">I", head, OFF_CLUSTER_BITS)
        (old_size,) = struct.unpack_from(">Q", head, OFF_SIZE)
        (old_l1_size,) = struct.unpack_from(">I", head, OFF_L1_SIZE)
        (l1_offset,) = struct.unpack_from(">Q", head, OFF_L1_OFFSET)

        cluster_size = 1 << cluster_bits
        # One L2 table fills a cluster; each of its entries maps one cluster.
        l2_entries = cluster_size // 8
        bytes_per_l1_entry = l2_entries * cluster_size

        if new_size == old_size:
            print("already %.1f GiB" % (old_size / (1 << 30)))
            return
        if new_size < old_size:
            die("refusing to shrink %s from %.1f to %.1f GiB"
                % (path, old_size / (1 << 30), new_size / (1 << 30)))

        new_l1_size = (new_size + bytes_per_l1_entry - 1) // bytes_per_l1_entry

        # The precondition: the bigger L1 table must still fit inside the
        # clusters already reserved for it, or growing it would mean
        # reallocating and refcounting a new region — qemu-img's job, not this
        # script's.
        old_l1_clusters = max(
            1, (old_l1_size * 8 + cluster_size - 1) // cluster_size)
        if new_l1_size * 8 > old_l1_clusters * cluster_size:
            die("cannot grow to %.1f GiB: the L1 table would need %d bytes but "
                "only %d are reserved. Use qemu-img."
                % (new_size / (1 << 30), new_l1_size * 8,
                   old_l1_clusters * cluster_size))

        # New entries must read as zero. They should already, but the spec does
        # not promise it for the slack at the end of the L1 table's cluster.
        f.seek(l1_offset + old_l1_size * 8)
        f.write(b"\0" * ((new_l1_size - old_l1_size) * 8))

        f.seek(OFF_SIZE)
        f.write(struct.pack(">Q", new_size))
        f.seek(OFF_L1_SIZE)
        f.write(struct.pack(">I", new_l1_size))
        f.flush()

    print("%s: %.1f -> %.1f GiB (L1 %d -> %d entries)"
          % (path, old_size / (1 << 30), new_size / (1 << 30),
             old_l1_size, new_l1_size))


if __name__ == "__main__":
    main()
