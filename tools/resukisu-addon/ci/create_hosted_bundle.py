#!/usr/bin/env python3
"""Bundle existing authorized peridot source + allowlisted stock inputs once.

Never publish resulting archive or proprietary stock modules to a public
repository without considering their license/distribution restrictions.
Use privately accessible HTTPS storage and record the output SHA-256.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import tarfile


def bundle(source: Path, assets: Path, dest: Path) -> None:
    source, assets, dest = source.resolve(), assets.resolve(), dest.resolve()
    if dest.exists():
        raise ValueError("Output already exists")
    if source in dest.parents or assets in dest.parents:
        raise ValueError("Keep bundle outside source and asset trees")
    inputs = (
      (source / "common", "source/common"),
      (source / "susfs4ksu", "source/susfs4ksu"),
      (source / "out-uapi5/.config", "source/out-uapi5/.config"),
      (source / "out-uapi5/arch/arm64/boot/Image", "source/out-uapi5/arch/arm64/boot/Image"),
      (assets, "assets"),
    )
    for p, _ in inputs:
        if not p.exists():
            raise FileNotFoundError(str(p))
    if not (source / "common/.git").exists() or not (source / "susfs4ksu/.git").exists():
        raise ValueError("Preserved source directories need original Git provenance")
    def allow(meta: tarfile.TarInfo) -> tarfile.TarInfo | None:
        parts = Path(meta.name.lower()).parts
        private = {".private", ".ssh", "id_rsa", "id_ed25519", "signing_key.pem", "signing_key.x509", "signing_key.pk8"}
        if any(item in private for item in parts):
            return None
        if parts[-1].endswith((".key", ".p12", ".pfx", ".keystore", ".jks")):
            return None
        if parts[-1].endswith(".pem") and parts[-1] != "stock-module-public.pem":
            return None
        # Verify source symlinks remain relative; extraction rejects escapes.
        if meta.issym() or meta.islnk():
            if Path(meta.linkname).is_absolute():
                raise ValueError("Absolute symlink in source: " + meta.name)
        return meta
    with tarfile.open(dest, mode="w:gz", compresslevel=1, format=tarfile.PAX_FORMAT) as out:
        for path, name in inputs:
            out.add(path, arcname=name, recursive=True, filter=allow)
    with dest.open("rb") as f:
        digest = hashlib.file_digest(f, "sha256").hexdigest()
    print("CI INPUT BUNDLE:", dest)
    print("BYTES:", dest.stat().st_size)
    print("SHA-256:", digest)
    print("Store privately over HTTPS; set repo vars BAKASU_INPUT_BUNDLE_URL and BAKASU_INPUT_BUNDLE_SHA256.")


if __name__ == "__main__":
    arg = argparse.ArgumentParser(description=__doc__)
    arg.add_argument("--preserved-source", required=True, type=Path)
    arg.add_argument("--prepared-assets", required=True, type=Path)
    arg.add_argument("--output", required=True, type=Path)
    a = arg.parse_args()
    bundle(a.preserved_source, a.prepared_assets, a.output)
