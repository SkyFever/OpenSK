#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fetch pinned Nordic CC310 dependencies and verify every file."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "tools/cc310-deps.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify cache without network access")
    args = parser.parse_args()
    cache = ROOT / "third_party/wasefire/.root/cc310"
    manifest = json.loads(MANIFEST.read_text())

    def ensure(entry):
        path = cache / entry["path"]
        if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"]:
            return
        if args.check:
            raise RuntimeError(f"Missing or changed dependency: {entry['path']}")
        data = urllib.request.urlopen(entry["url"], timeout=45).read()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise RuntimeError(f"SHA-256 mismatch: {entry['path']}")
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name(path.name + ".download")
        temp.write_bytes(data)
        temp.replace(path)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(ensure, manifest["files"]))
    print(f"CC310 dependencies verified: {len(manifest['files'])} files")
    print(f"nrfxlib: {manifest['nrfxlib_revision']}")
    print(f"Mbed TLS: {manifest['mbedtls_revision']}")


if __name__ == "__main__":
    main()
