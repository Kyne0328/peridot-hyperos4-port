"""Validate the UAPI5 full WildKernels bundle against POCO F6 stock modules.

Offline only: verifies exact build provenance/config, retained stock module trust,
exported-symbol CRC compatibility, module imports, and existing module signatures.
Never loads a module, touches a device, or flashes a partition.
"""
from __future__ import annotations

from pathlib import Path
import os
import shutil
import hashlib
import json
import struct
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

ROOT = Path(__file__).resolve().parents[2]
ASSET_ROOT = Path(os.environ.get("BAKASU_CI_ASSET_ROOT", str(ROOT)))
BUILD = Path(os.environ.get("BAKASU_CI_OUTPUT", str(ROOT / "builder/work/resukisu-uapi5-fullbundle-20261004")))
RECEIPT = BUILD / "build-receipt.json"
IMAGE = BUILD / "Image"
CONFIG = BUILD / "kernel.config"
SYMVERS = BUILD / "vmlinux.symvers"
CERT = Path(os.environ.get("BAKASU_CI_STOCK_CERT", str(ASSET_ROOT / ".cache/resukisu-uapi5-finalize/stock-module-public.pem")))
STOCK_SYMVERS = ASSET_ROOT / "00-manifest/resukisu-candidate/kernel_aarch64_Module.symvers"
VENDOR_BOOT = ASSET_ROOT / ".cache/global-single-recovery-ri2/source-images/images/vendor_boot.img"

EXPECTED_RELEASE = "6.1.138-android14-11-g0c3d559bcd85-ab14529422"
EXPECTED_FEATURE_SET = "SUSFS+NoMount+BBG+NET+DS+NTSync+Ptrace+Unicode+BPF+Perf"
EXPECTED_FEATURES = EXPECTED_FEATURE_SET.split("+")
EXPECTED_PINS = {
    "common": "0c3d559bcd85c64dae9c9c9687abbe5347fff3ad",
    "resukisu": os.environ.get("BAKASU_CI_SHA", "8770c7e324a22895703c4916b8a16520e0b81c79"),
    "susfs": "24743360ea08d98f6ad72b856851abed8de5854f",
    "wildkernels": "e0ecd61219baaa0c3eae821246e31136302fd0dc",
    "kernel_patches": "41ae18b35d20e0c6ac04116785a4a1089528ae94",
    "baseband_guard": "a54e0dc6cf0aff4dd87fec49644a02d2eb612905",
    "droidspaces": "ac38c11fef1402c0db8172ea8187db0401a0bc30",
    "nomount": "5fac312b143e632e483c3c8b9ab325b6d4527314",
}
REQUIRED_Y = [
    "KSU", "KSU_SUSFS", "BBG",
    "IP_SET", "TCP_CONG_BBR", "TCP_CONG_BBR3",
    "NET_SCH_FQ", "NET_SCH_FQ_CODEL", "NET_SCH_CAKE",
    "WIREGUARD", "CIFS",
    "PID_NS", "SYSVIPC", "POSIX_MQUEUE", "IPC_NS", "USER_NS",
    "NTSYNC", "DEBUG_INFO_BTF", "BPF_EVENTS", "KPROBE_EVENTS",
    "UPROBES", "UPROBE_EVENTS", "FUSE_FS", "BPF_SYSCALL", "FUSE_BPF",
    "NOMOUNT", "MODVERSIONS", "MODULE_SIG_PROTECT", "CFI_CLANG",
]

sys.path.insert(0, str(ROOT / "tools/resukisu-addon/ci"))
from kernel_abi import imports, ramdisk


def need(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError(message)


def digest(path: Path) -> str:
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def exports(data: bytes) -> set[str]:
    off = struct.unpack_from("<Q", data, 40)[0]
    ent, count, si = struct.unpack_from("<HHH", data, 58)
    need(ent == 64, "Expected ELF64 module")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, off + i * ent) for i in range(count)]
    sh = sections[si]
    names = data[sh[4]:sh[4] + sh[5]]
    for section in sections:
        if names[section[0]:].split(b"\0", 1)[0] == b"__ksymtab_strings":
            return {n.decode() for n in data[section[4]:section[4] + section[5]].split(b"\0") if n}
    return set()


def symbol_map(path: Path) -> dict[str, int]:
    result = {}
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        row = line.split()
        if len(row) >= 2:
            result[row[1]] = int(row[0], 16)
    return result


def collect_modules() -> list[tuple[str, str, bytes]]:
    modules: list[tuple[str, str, bytes]] = []
    for origin in ("system_dlkm", "vendor_dlkm"):
        tree = ASSET_ROOT / ".cache/resukisu-candidate" / (origin + "-extracted") / "lib"
        need(tree.is_dir(), f"Missing extracted module tree: {tree}")
        for path in sorted(tree.rglob("*.ko")):
            modules.append((origin, path.relative_to(tree).as_posix(), path.read_bytes()))

    need(VENDOR_BOOT.is_file(), "Missing vendor_boot.img")
    vb = VENDOR_BOOT.read_bytes()
    size = struct.unpack_from("<I", vb, 24)[0]
    synthetic = bytearray(4096)
    synthetic[:8] = b"ANDROID!"
    struct.pack_into("<II", synthetic, 8, 0, size)
    struct.pack_into("<I", synthetic, 40, 4)
    _, files = ramdisk(bytes(synthetic) + vb[4096:4096 + size])
    modules.extend(("vendor_boot", name, body) for name, body in files.items() if name.endswith(".ko"))
    return modules


def verify_module_signature(data: bytes, temp: Path) -> str:
    marker = b"~Module signature appended~\n"
    if not data.endswith(marker):
        return "unsigned"
    end = len(data) - len(marker)
    length = int.from_bytes(data[end - 4:end], "big")
    start = end - 12 - length
    need(start >= 0, "Malformed module signature trailer")
    sig = temp / "signature.der"
    content = temp / "content.bin"
    verified = temp / "verified.bin"
    sig.write_bytes(data[start:end - 12])
    content.write_bytes(data[:start])
    result = subprocess.run(
        [
            os.environ.get("BAKASU_CI_OPENSSL", shutil.which("openssl") or "C:/Program Files/Git/usr/bin/openssl.exe"), "cms", "-verify",
            "-binary", "-inform", "DER", "-in", str(sig),
            "-content", str(content), "-certfile", str(CERT),
            "-noverify", "-out", str(verified),
        ],
        capture_output=True,
    )
    need(result.returncode == 0, "Stock-key module signature verification failed")
    return "stock-key-signature-verified"


def main() -> None:
    for path in (RECEIPT, IMAGE, CONFIG, SYMVERS, CERT, STOCK_SYMVERS):
        need(path.is_file(), f"Missing required input: {path}")

    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    need(receipt["status"] == "kernel-build-complete", "Build receipt not complete")
    need(receipt["device"] == "peridot", "Wrong device in build receipt")
    need(receipt["kernel_release"] == EXPECTED_RELEASE, "Kernel release mismatch")
    need(receipt["resukisu_uapi_version"] == 5, "ReSukiSU UAPI is not 5")
    need(receipt["feature_set"] == EXPECTED_FEATURE_SET, "Full WildKernels feature set mismatch")
    need(receipt["features"] == EXPECTED_FEATURES, "Full feature list/order mismatch")
    need(receipt["source_pins"] == EXPECTED_PINS, "Source/dependency pin mismatch")
    need(receipt["ptrace"]["toggle_enabled"] is True, "Ptrace toggle not recorded enabled")
    need(receipt["ptrace"]["patch_applied"] is False, "Unexpected ptrace patch on kernel 6.1")
    need("6.1" in receipt["ptrace"]["reason"], "Ptrace no-op explanation missing")
    need(receipt["base_uapi5_tree_preserved"] is True, "Base UAPI5 preservation not recorded")
    need(receipt["device_flash_performed"] is False, "Build receipt unexpectedly records a flash")

    need(digest(IMAGE) == receipt["image"]["sha256"], "Image hash differs from build receipt")
    need(IMAGE.stat().st_size == receipt["image"]["bytes"], "Image size differs from build receipt")
    need(digest(CONFIG) == receipt["kernel_config"]["sha256"], "Config hash differs from build receipt")
    need(digest(SYMVERS) == receipt["vmlinux_symvers"]["sha256"], "vmlinux.symvers hash differs from receipt")

    config_lines = set(CONFIG.read_text(encoding="utf-8").splitlines())
    for key in REQUIRED_Y:
        need(f"CONFIG_{key}=y" in config_lines, f"Missing required CONFIG_{key}=y")
    need('CONFIG_DEFAULT_TCP_CONG="bbr"' in config_lines, "Default TCP congestion control is not bbr")
    need('CONFIG_SYSTEM_TRUSTED_KEYS="certs/peridot-stock-public.pem"' in config_lines,
         "Stock module trust key path is not retained")
    lsm = next((line for line in config_lines if line.startswith('CONFIG_LSM="')), "")
    need("baseband_guard" in lsm, "baseband_guard missing from CONFIG_LSM")

    image = IMAGE.read_bytes()
    cert_der = x509.load_pem_x509_certificate(CERT.read_bytes()).public_bytes(Encoding.DER)
    need(cert_der in image, "Stock public module certificate is absent from final Image")

    candidate = symbol_map(SYMVERS)
    stock = symbol_map(STOCK_SYMVERS)
    modules = collect_modules()
    module_exports = set().union(*(exports(data) for _, _, data in modules))

    rows = []
    signed_count = 0
    with tempfile.TemporaryDirectory(dir=BUILD, prefix="module-verify-") as tmp:
        temp = Path(tmp)
        for origin, name, data in modules:
            versions = imports(data)
            crc_mismatches = [
                {"symbol": symbol, "module_crc": hex(crc), "kernel_crc": hex(candidate[symbol])}
                for symbol, crc in versions
                if symbol in candidate and candidate[symbol] != crc
            ]
            unresolved = [
                symbol for symbol, _ in versions
                if symbol not in candidate and symbol not in module_exports
            ]
            signature = verify_module_signature(data, temp)
            if signature == "stock-key-signature-verified":
                signed_count += 1
            rows.append({
                "origin": origin,
                "path": name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "imports": len(versions),
                "crc_mismatches": crc_mismatches,
                "unresolved_imports": unresolved,
                "signature": signature,
            })

    shared = stock.keys() & candidate.keys()
    shared_mismatches = sorted(symbol for symbol in shared if stock[symbol] != candidate[symbol])
    summary = {
        origin: {
            "modules": sum(row["origin"] == origin for row in rows),
            "crc_mismatches": sum(len(row["crc_mismatches"]) for row in rows if row["origin"] == origin),
            "unresolved_imports": sum(len(row["unresolved_imports"]) for row in rows if row["origin"] == origin),
        }
        for origin in ("vendor_boot", "system_dlkm", "vendor_dlkm")
    }

    report = {
        "schema_version": 1,
        "status": "offline-fullbundle-compatibility-passed",
        "device": "peridot",
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "image_bytes": len(image),
        "kernel_release": EXPECTED_RELEASE,
        "uapi_version": 5,
        "feature_set": EXPECTED_FEATURE_SET,
        "features": EXPECTED_FEATURES,
        "source_pins": EXPECTED_PINS,
        "ptrace": receipt["ptrace"],
        "stock_certificate_embedded": True,
        "stock_key_module_signatures_verified": signed_count,
        "shared_stock_exports": len(shared),
        "shared_export_crc_mismatches": shared_mismatches,
        "summary": summary,
        "modules": rows,
        "compiler": "Ubuntu Clang 18.1.3; differs from stock Android Clang 17.0.2",
        "trim_unused_ksyms": False,
        "device_boot_tested": False,
        "runtime_root_tested": False,
        "device_access_performed": False,
    }

    need(not shared_mismatches, f"{len(shared_mismatches)} shared stock export CRC mismatches")
    gaps = [row for row in rows if row["crc_mismatches"] or row["unresolved_imports"]]
    need(not gaps, f"Stock module compatibility gaps remain in {len(gaps)} modules")

    out = BUILD / "compatibility.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "modules"}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
