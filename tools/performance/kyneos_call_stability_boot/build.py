#!/usr/bin/env python3
"""Build a small reproducible KernelSU module for validated peridot settings."""
from __future__ import annotations
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED
import hashlib

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parents[2]
OUT = PROJECT / "builder/work/call-stability-boot-20261017/KyneOS-CallStability-Boot-20261017.zip"
FILES = ("module.prop", "service.sh", "customize.sh", "README.md")


def validate() -> dict[str, bytes]:
    contents = {}
    for name in FILES:
        p = ROOT / name
        if not p.is_file() or p.is_symlink():
            raise ValueError(f"Unsafe source: {name}")
        contents[name] = p.read_bytes()
    script = contents["service.sh"].decode("utf-8")
    if not script.startswith("#!/system/bin/sh\n"):
        raise ValueError("Script shell header changed")
    forbidden = ("setenforce", "/proc/sys/vm", "thermal", "camera.provider",
                 "force-stop", "reboot", "ctl.stop", "mount -o", "iptables")
    if any(x in script for x in forbidden):
        raise ValueError("Unexpected device-mutating operation in bootstrap")
    if not contents["module.prop"].startswith(b"id=kyneos_call_stability_boot\n"):
        raise ValueError("Unexpected module identity")
    return contents


def build(path: Path = OUT) -> str:
    contents = validate()
    path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(path, "w") as archive:
        for name in FILES:
            zi = ZipInfo(name, (2026, 10, 17, 0, 0, 0))
            zi.compress_type = ZIP_DEFLATED
            zi.external_attr = ((0o100755 if name.endswith(".sh")
                                 else 0o100644) << 16)
            archive.writestr(zi, contents[name])
    with ZipFile(path) as archive:
        if archive.testzip() is not None or set(archive.namelist()) != set(FILES):
            raise ValueError("Archive membership/CRC mismatch")
        if any(archive.read(k) != v for k, v in contents.items()):
            raise ValueError("Archive content mismatch")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"{path} sha256={digest}")
    return digest


if __name__ == "__main__":
    build()
