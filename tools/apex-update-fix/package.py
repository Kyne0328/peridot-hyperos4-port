"""Build a deterministic, minimally scoped KernelSU/ReSukiSU module ZIP for UPDATE-001."""
from __future__ import annotations
import hashlib
from pathlib import Path
import zipfile

MODULE = Path(__file__).resolve().parent / "module"
OUT = Path("D:/hyperos4-peridot-apex-update-fix-20261008/outputs/KyneOS-UPDATE-001-APEX-FIEMAP-DECRYPT-v1.zip")
FILES = ("module.prop", "system.prop", "customize.sh")

def main() -> None:
    source = {name: (MODULE / name).read_bytes() for name in FILES}
    if set(p.name for p in MODULE.iterdir()) != set(FILES):
        raise ValueError("Unexpected module payload entry")
    if source["system.prop"].decode("ascii").splitlines()[-1] != "apexd.config.use_fiemap=false":
        raise ValueError("Property payload differs from reviewed UPDATE-001")
    props = source["module.prop"].decode("ascii")
    if "id=kyneos_apexd_fiemap_fix\n" not in props or "versionCode=1\n" not in props:
        raise ValueError("Module identity/version drift")
    if b"ro.product.device" not in source["customize.sh"] or b'"37"' not in source["customize.sh"]:
        raise ValueError("Target install guard missing")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    temp = OUT.with_suffix(".zip.partial")
    if temp.exists():
        raise FileExistsError(f"Refusing partial overwrite: {temp}")
    if OUT.exists():
        with zipfile.ZipFile(OUT) as existing:
            names = existing.namelist()
            if names == list(FILES) and all(existing.read(n) == source[n] for n in FILES):
                print(f"EXISTS_VERIFIED {OUT} SHA256={hashlib.sha256(OUT.read_bytes()).hexdigest()}")
                return
        raise FileExistsError(f"Refusing to overwrite drifted existing ZIP: {OUT}")
    try:
        with zipfile.ZipFile(temp, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for name, data in source.items():
                attr = zipfile.ZipInfo(name, date_time=(2026, 10, 8, 0, 0, 0))
                attr.compress_type = zipfile.ZIP_DEFLATED
                attr.external_attr = ((0o100755 if name.endswith(".sh") else 0o100644) << 16)
                z.writestr(attr, data)
        with zipfile.ZipFile(temp) as z:
            if z.testzip() is not None or z.namelist() != list(FILES):
                raise ValueError("ZIP CRC/manifest check failed")
            for name in FILES:
                if z.read(name) != source[name]:
                    raise ValueError(f"ZIP payload differs: {name}")
        temp.replace(OUT)
    finally:
        temp.unlink(missing_ok=True)
    print(f"BUILT_AND_VERIFIED {OUT}")
    print(f"SHA256 {hashlib.sha256(OUT.read_bytes()).hexdigest()}")
    print(f"ENTRIES {','.join(FILES)}")
if __name__ == "__main__":
    main()
