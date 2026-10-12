"""Exercise full-bundle installer hash branches with inert AnyKernel stubs.

No boot partition is opened or written. The real package scripts execute only
against temporary kernel files and a flash_boot stub.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import struct
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ROOT / "builder/work/resukisu-susfs-addon-uapi5-fullbundle-20261004"
AUDIT = ROOT / "builder/work/resukisu-uapi5-fullbundle-20261004"
MANIFEST = "POCO-F6-UAPI5-FULLBUNDLE-MANIFEST.json"

STOCK = "97b2c53022e8c0bd0b279c4c592a196126a6eb0a93647c2957b39dcd5f2dc1c9"
OLD = "f5b148001a01b6b3f498aa6a536ce128dbd4c6a658866e90f5f0b47842861310"
CORE = "142782663ee40536cc6bfbf0c999e9aa7430ae1489b04cc0388dca09d970f2c6"
FULL = "340c3470ece7408fbbf0f307db2d15f6528e9c7d73c0d239638f9e62d0b415e9"


def linux(path: Path) -> str:
    resolved = path.resolve().as_posix()
    return "/mnt/c/" + resolved[3:]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    template = ROOT / "builder/work/resukisu-susfs-addon/POCO-F6-HyperOS4-ReSukiSU-SUSFS-Addon-20261003.zip"
    with zipfile.ZipFile(template) as z:
        old = z.read("Image")
    assert sha(old) == OLD

    boot = (ROOT / ".cache/global-single-recovery-ri2/source-images/images/boot.img").read_bytes()
    stock = boot[4096:4096 + struct.unpack_from("<I", boot, 8)[0]]
    assert sha(stock) == STOCK

    core_package = ROOT / "builder/work/resukisu-susfs-addon-uapi5-20261004/POCO-F6-HyperOS4-ReSukiSU-SUSFS-UAPI5-Update-20261004.zip"
    with zipfile.ZipFile(core_package) as z:
        core = z.read("Image")
    assert sha(core) == CORE

    update_package = PACKAGES / "POCO-F6-HyperOS4-ReSukiSU-SUSFS-UAPI5-FullBundle-Update-20261004.zip"
    with zipfile.ZipFile(update_package) as z:
        full = z.read("Image")
    assert sha(full) == FULL

    fixtures = [
        ("stock", stock),
        ("old-uapi2", old),
        ("uapi5-core", core),
        ("fullbundle", full),
        ("unknown", b"not a kernel image; inert negative fixture"),
    ]

    cases = []
    with tempfile.TemporaryDirectory(dir=AUDIT, prefix="fullbundle-guard-stubs-") as td:
        temp = Path(td)
        for package in sorted(PACKAGES.glob("*.zip")):
            with zipfile.ZipFile(package) as z:
                script = z.read("anykernel.sh").decode("utf-8")
                manifest = json.loads(z.read(MANIFEST))
            assert script.count(". tools/ak3-core.sh") == 1
            assert "device.name1=peridot" in script
            assert "patch_vbmeta_flag=0" in script
            inert = script.replace(". tools/ak3-core.sh", ": # inert test core")
            (temp / "installer.sh").write_text(inert, encoding="utf-8", newline="\n")
            harness = (
                "#!/bin/sh\nset -eu\n"
                f'SPLITIMG="{linux(temp)}"\n'
                "ui_print() { :; }\n"
                "abort() { exit 77; }\n"
                "split_boot() { :; }\n"
                "flash_boot() { printf FLASH_STUB_OK; }\n"
                f'. "{linux(temp / "installer.sh")}"\n'
            )
            (temp / "harness.sh").write_text(harness, encoding="utf-8", newline="\n")

            for label, data in fixtures:
                (temp / "kernel").write_bytes(data)
                result = subprocess.run(
                    ["wsl.exe", "-d", "Ubuntu", "--", "sh", linux(temp / "harness.sh")],
                    capture_output=True,
                    text=True,
                )
                expected = sha(data) in manifest["accepted_input_image_sha256"]
                assert result.returncode == (0 if expected else 77), (
                    package.name, label, result.returncode, result.stderr
                )
                assert ("FLASH_STUB_OK" in result.stdout) == expected
                cases.append({
                    "package": package.name,
                    "input": label,
                    "input_sha256": sha(data),
                    "accepted": expected,
                    "passed": True,
                })

    assert len(cases) == 15
    report = {
        "schema_version": 1,
        "status": "passed",
        "cases": cases,
        "case_count": len(cases),
        "device_access": False,
        "real_boot_write": False,
        "flash_boot_is_stub": True,
    }
    (AUDIT / "package-guard-tests.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"{len(cases)} inert full-bundle guard cases passed; no device accessed")


if __name__ == "__main__":
    main()
