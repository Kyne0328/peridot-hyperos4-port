"""Exact pinned POCO F6 UAPI5 packaging contract, without ROM signing dependencies."""
from __future__ import annotations

TEMPLATE_SHA = "2f1c4b9c451e2f6e0161867ca13eb60f38f3f01ba828a33df0c999a0fbff9eba"
CORE_PACKAGE_SHA = "f82fc63dd86b9305420824bf7aa9d86b593a62de79cf8a0c904fa2a3311fed63"
STOCK_IMAGE = "97b2c53022e8c0bd0b279c4c592a196126a6eb0a93647c2957b39dcd5f2dc1c9"
OLD_WK_IMAGE = "f5b148001a01b6b3f498aa6a536ce128dbd4c6a658866e90f5f0b47842861310"
UAPI5_CORE_IMAGE = "142782663ee40536cc6bfbf0c999e9aa7430ae1489b04cc0388dca09d970f2c6"
FULL_IMAGE = "340c3470ece7408fbbf0f307db2d15f6528e9c7d73c0d239638f9e62d0b415e9"
FEATURE_SET = "SUSFS+NoMount+BBG+NET+DS+NTSync+Ptrace+Unicode+BPF+Perf"
PINS = {
    "common": "0c3d559bcd85c64dae9c9c9687abbe5347fff3ad",
    "resukisu": "8770c7e324a22895703c4916b8a16520e0b81c79",
    "susfs": "24743360ea08d98f6ad72b856851abed8de5854f",
    "wildkernels": "e0ecd61219baaa0c3eae821246e31136302fd0dc",
    "kernel_patches": "41ae18b35d20e0c6ac04116785a4a1089528ae94",
    "baseband_guard": "a54e0dc6cf0aff4dd87fec49644a02d2eb612905",
    "droidspaces": "ac38c11fef1402c0db8172ea8187db0401a0bc30",
    "nomount": "5fac312b143e632e483c3c8b9ab325b6d4527314",
}


def need(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError(message)


def installer_script(source: bytes, accepted: list[str], label: str) -> bytes:
    """Reproduce the October 4 AnyKernel3 original exact source-kernel guard."""
    text = source.decode("utf-8")
    old = (
        f'[ "$current_sha" = "{STOCK_IMAGE}" ] || abort '
        '"Current kernel is not the expected RI3/add-on kernel. Refusing to flash."'
    )
    need(text.count(old) == 1, "Original AnyKernel source-kernel guard changed")
    need(len(accepted) > 0 and all(len(x) == 64 and all(ch in "0123456789abcdef" for ch in x)
                                   for x in accepted), "Invalid accepted kernel digest")
    new = (
        'case "$current_sha" in\n'
        f'  {"|".join(accepted)}) ;;\n'
        '  *) abort "Current kernel is not an explicitly supported input. Refusing to flash." ;;\n'
        'esac'
    )
    text = text.replace(old, new)
    text = text.replace(
        "kernel.string=POCO F6 HyperOS 4 - ReSukiSU + SUSFS",
        "kernel.string=" + label,
    )
    text = text.replace(
        "Target base: F6-Global-HyperOS4-DEV2-RI3-20261003",
        "Exact kernel hash guards; full WildKernels UAPI5 package",
    )
    text = text.replace("Expected current kernel SHA-256:", "Accepted current kernel SHA-256:")
    text = text.replace(
        f'ui_print "{STOCK_IMAGE}"',
        "\n".join(f'ui_print "{value}"' for value in accepted),
    )
    need("device.name1=peridot" in text, "Peridot device guard missing")
    need("patch_vbmeta_flag=0" in text, "VBMeta patch must remain disabled")
    return text.encode("utf-8")
