"""Extract immutable APEX package inputs for official host compatibility analysis."""
from __future__ import annotations
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "builder"))
from peridot_builder.errors import BuilderError
from peridot_builder.hashing import sha256_file
from peridot_builder.product_compose import ErofsExtractor
from peridot_builder.tools import Toolchain

def main() -> None:
    plan_path = ROOT / "builder/work/avb-dev/super-plan.json"
    output = ROOT / "builder/work/compatibility/apex-20261002"
    if output.exists():
        raise BuilderError("Refusing to overwrite an existing APEX evidence directory")
    if shutil.disk_usage(ROOT).free < 5 * 1024**3:
        raise BuilderError("APEX staging requires at least 5 GiB free working space")
    plan = json.loads(plan_path.read_text(encoding="utf-8-sig"))
    records = {item["partition"]: item for item in plan["inputs"]}
    targets = {"system": "/system/apex", "system_ext": "/apex", "product": "/apex", "vendor": "/apex"}
    tool = Toolchain(ROOT).require("extract.erofs")
    expected = "d7378ddb500c4338c4ef02f0da7601693a16807faafa453c1dc5750baf3b0dca"
    if sha256_file(tool) != expected:
        raise BuilderError("Extractor does not match the approved pinned hash")
    for partition in targets:
        item = records[partition]
        image = Path(item["path"]).resolve()
        if not image.is_relative_to(ROOT) or sha256_file(image) != item["sha256"]:
            raise BuilderError(f"Source image hash/path mismatch: {partition}")
    output.mkdir(parents=True)
    extractor = ErofsExtractor(tool)
    report = {"schema_version": 1, "purpose": "source_apex_packages_not_runtime_activation",
              "plan_sha256": sha256_file(plan_path), "extractor_sha256": expected,
              "packages": [], "sources": [], "compatibility_verified": False}
    for partition, logical in targets.items():
        print(f"Extracting {partition}:{logical}", flush=True)
        destination = output / partition
        extractor.extract_path(Path(records[partition]["path"]), logical, destination)
        packages = sorted(p for p in destination.rglob("*") if p.suffix in {".apex", ".capex"} and p.is_file())
        report["sources"].append({"partition": partition, "image_sha256": records[partition]["sha256"], "logical_path": logical, "package_count": len(packages)})
        for package in packages:
            if package.is_symlink() or not package.resolve().is_relative_to(output):
                raise BuilderError("Unexpected linked APEX package")
            report["packages"].append({"partition": partition, "path": package.relative_to(output).as_posix(),
                                       "size_bytes": package.stat().st_size, "sha256": sha256_file(package)})
        (output / "package-inventory.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"sources": report["sources"], "package_count": len(report["packages"]),
                      "package_bytes": sum(p["size_bytes"] for p in report["packages"])}, indent=2))

if __name__ == "__main__":
    try:
        main()
    except (BuilderError, OSError, ValueError, KeyError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
