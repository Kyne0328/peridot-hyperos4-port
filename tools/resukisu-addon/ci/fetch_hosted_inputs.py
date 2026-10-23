#!/usr/bin/env python3
"""Fetch/check owner's pinned POCO F6 hosted CI source+stock bundle.

The URL and SHA-256 are configured in GitHub Actions repository variables.
The bundle must be generated only from the owner's authorized local assets.
No untrusted GitHub artifact is auto-executed or signed here.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import re
import tarfile
from urllib.parse import urlsplit
from urllib.request import urlopen, Request

def fetch(url: str, expected: str, dest: Path) -> None:
    if urlsplit(url).scheme != "https" or not urlsplit(url).hostname:
        raise ValueError("BAKASU_INPUT_BUNDLE_URL must be HTTPS")
    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise ValueError("BAKASU_INPUT_BUNDLE_SHA256 must be a 64-digit lowercase SHA-256")
    if dest.exists():
        raise ValueError("Refusing to overwrite existing CI inputs")
    archive = dest.parent / "peridot-stock-inputs.tar.gz"
    h = hashlib.sha256()
    with urlopen(Request(url, headers={"User-Agent":"peridot-bakasu-kernel-ci"}), timeout=180) as response, archive.open("xb") as out:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            out.write(chunk)
    if h.hexdigest() != expected:
        archive.unlink(missing_ok=True)
        raise ValueError("Pinned input bundle SHA-256 mismatch")
    dest.mkdir(mode=0o700)
    with tarfile.open(archive, "r:gz") as pack:
        members = pack.getmembers()
        if not members:
            raise ValueError("Empty CI input bundle")
        for m in members:
            p = Path(m.name)
            if p.is_absolute() or ".." in p.parts or not p.parts or p.parts[0] not in ("source", "assets"):
                raise ValueError("Invalid CI input archive path: " + m.name)
            if m.ischr() or m.isblk() or m.isfifo() or m.isdev():
                raise ValueError("Unsafe archive entry: " + m.name)
            if any(t in m.name.lower() for t in ("/.private/", "/signing_key.pem", "/id_rsa", "/id_ed25519")):
                raise ValueError("Private key path in input archive: " + m.name)
        pack.extractall(dest, filter="data")
    source = dest / "source"
    assets = dest / "assets"
    for p in [
        source / "common/.git",
        source / "susfs4ksu/.git",
        source / "out-uapi5/.config",
        source / "out-uapi5/arch/arm64/boot/Image",
        assets / ".cache/resukisu-uapi5-finalize/stock-module-public.pem",
        assets / ".cache/global-single-recovery-ri2/source-images/images/boot.img",
        assets / ".cache/global-single-recovery-ri2/source-images/images/vendor_boot.img",
        assets / "00-manifest/resukisu-candidate/kernel_aarch64_Module.symvers",
    ]:
        if not p.exists():
            raise ValueError("Missing required source/stock input " + str(p))
    archive.unlink()
    print("Verified and unpacked checksum-pinned CI input bundle (no private keys).")

if __name__ == "__main__":
    fetch(os.environ["BAKASU_INPUT_BUNDLE_URL"], os.environ["BAKASU_INPUT_BUNDLE_SHA256"],
          Path(os.environ["GITHUB_WORKSPACE"]) / ".ci-inputs")
