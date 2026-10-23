#!/usr/bin/env python3
"""Provision a sealed, allowlisted read-only asset set for an isolated runner.

Run manually on the machine holding the authorized POCO F6 stock inputs.
Never copies .private/, signing secrets, root addons, or unrelated ROM files.
No network requests and no device access.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil

FILES = (
    ".cache/resukisu-uapi5-finalize/stock-module-public.pem",
    ".cache/global-single-recovery-ri2/source-images/images/boot.img",
    ".cache/global-single-recovery-ri2/source-images/images/vendor_boot.img",
    "00-manifest/resukisu-candidate/kernel_aarch64_Module.symvers",
    "builder/work/resukisu-susfs-addon/POCO-F6-HyperOS4-ReSukiSU-SUSFS-Addon-20261003.zip",
    "builder/work/resukisu-susfs-addon-uapi5-20261004/POCO-F6-HyperOS4-ReSukiSU-SUSFS-UAPI5-Update-20261004.zip",
    "builder/work/resukisu-susfs-addon-uapi5-fullbundle-20261004/POCO-F6-HyperOS4-ReSukiSU-SUSFS-UAPI5-FullBundle-Update-20261004.zip",
)
TREES = (
    ".cache/resukisu-candidate/system_dlkm-extracted/lib",
    ".cache/resukisu-candidate/vendor_dlkm-extracted/lib",
)


def sha_file(path: Path) -> str:
    with path.open("rb") as inp:
        return hashlib.file_digest(inp, "sha256").hexdigest()


def provision(source: Path, destination: Path) -> dict:
    source = source.resolve(strict=True)
    destination = destination.resolve()
    if destination.exists() or destination == source or source in destination.parents:
        raise ValueError("Asset destination must be a new directory outside original project")
    if source == destination or destination in source.parents:
        raise ValueError("Unsafe overlapping asset roots")
    for item in FILES + TREES:
        path = source / item
        if path.is_symlink() or not path.exists():
            raise ValueError("Missing or symlinked input: " + str(path))
    destination.mkdir(parents=True, mode=0o700)
    entries = []
    for item in FILES:
        original = source / item
        target = destination / item
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, target, follow_symlinks=False)
        if sha_file(original) != sha_file(target):
            raise RuntimeError("Asset copy differs from source: " + item)
        entries.append({"relative_path": item, "bytes": target.stat().st_size, "sha256": sha_file(target)})
    for name in TREES:
        source_dir = source / name
        for f in sorted(source_dir.rglob("*.ko")):
            if f.is_symlink() or not f.is_file():
                raise ValueError("Unexpected symlink/module source " + str(f))
            relative = f.relative_to(source).as_posix()
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, target, follow_symlinks=False)
            entries.append({"relative_path": relative, "bytes": target.stat().st_size,
                            "sha256": sha_file(target)})
    result = {
        "asset_set": "peridot-bakasu-stock-allowlist-v1",
        "copy_count": len(entries),
        "private_key_material_copied": False,
        "contains_signed_stock_modules": True,
        "sources": entries,
    }
    (destination / "asset-inventory.json").write_text(json.dumps(result, indent=2) + "\n")
    assert not (destination / ".private").exists()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--dest", type=Path, required=True)
    args = parser.parse_args()
    result = provision(args.source_root, args.dest)
    print(json.dumps({k: result[k] for k in ("asset_set", "copy_count", "private_key_material_copied")}, indent=2))


if __name__ == "__main__":
    main()
