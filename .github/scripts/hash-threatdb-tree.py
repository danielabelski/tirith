#!/usr/bin/env python3
"""Hash a reviewed source tree using Tirith's provenance stream format."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from typing import Iterator


def regular_files(path: bytes) -> Iterator[bytes]:
    metadata = os.lstat(path)
    if stat.S_ISREG(metadata.st_mode):
        yield path
        return
    if not stat.S_ISDIR(metadata.st_mode):
        return

    for directory, directories, filenames in os.walk(path, followlinks=False):
        directories[:] = [
            name
            for name in directories
            if stat.S_ISDIR(os.lstat(os.path.join(directory, name)).st_mode)
        ]
        for filename in filenames:
            candidate = os.path.join(directory, filename)
            if stat.S_ISREG(os.lstat(candidate).st_mode):
                yield candidate


def hash_file(path: bytes) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(arguments: list[str]) -> int:
    if not arguments:
        print("usage: hash-threatdb-tree.py PATH [PATH ...]", file=sys.stderr)
        return 2

    paths = sorted(
        path
        for source in arguments
        for path in regular_files(os.fsencode(source))
    )
    tree_digest = hashlib.sha256()
    for path in paths:
        tree_digest.update(path)
        tree_digest.update(b"\0")
        tree_digest.update(hash_file(path).encode("ascii"))
        tree_digest.update(b"\0")
    print(tree_digest.hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
