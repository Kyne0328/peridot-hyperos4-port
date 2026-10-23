#!/usr/bin/env python3
"""Build tightly-scoped KernelSU GPU telemetry SELinux addon reproducibly."""
from __future__ import annotations

import hashlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parents[2]
DEST = PROJECT / "builder" / "work" / "gpu-telemetry-policy-20261017" / "KyneOS-GPUClock-Telemetry-SELinux-20261017.zip"
FILES = ("module.prop", "sepolicy.rule")
RULE = "allow system_app vendor_sysfs_kgsl_gpuclk file { open read getattr }\n"


def validate() -> dict[str, bytes]:
    data: dict[str, bytes] = {}
    for name in FILES:
        p = ROOT / name
        if p.is_symlink() or not p.is_file() or p.parent != ROOT:
            raise ValueError(f"Invalid file: {name}")
        data[name] = p.read_bytes()
    if data["sepolicy.rule"] != RULE.encode("utf-8"):
        raise ValueError("SELinux rule differs from exact allowed scope")
    if not data["module.prop"].startswith(b"id=kyneos_gpuclk_telemetry\n"):
        raise ValueError("Unexpected module identifier")
    return data


def build(out: Path = DEST) -> str:
    contents = validate()
    out.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(out, "w") as zf:
        for name in FILES:
            zi = ZipInfo(name, date_time=(2026, 10, 17, 0, 0, 0))
            zi.compress_type = ZIP_DEFLATED
            zi.external_attr = (0o100644 << 16)
            zf.writestr(zi, contents[name])
    with ZipFile(out, "r") as zf:
        if set(zf.namelist()) != set(FILES):
            raise ValueError("Unexpected ZIP payload")
        if zf.testzip() is not None:
            raise ValueError("Corrupt ZIP CRC")
        for name, expected in contents.items():
            if zf.read(name) != expected:
                raise ValueError(f"Content mismatch in {name}")
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    print(f"{out} sha256={digest}")
    return digest


if __name__ == "__main__":
    build()
