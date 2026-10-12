"""Collect source-hashed VINTF XML evidence without changing input images."""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "builder"))

from peridot_builder.errors import BuilderError
from peridot_builder.hashing import sha256_file
from peridot_builder.product_compose import ErofsExtractor
from peridot_builder.tools import Toolchain

TARGETS = {
    "vendor": "/etc/vintf",
    "odm": "/etc/vintf",
    "system": "/system/etc/vintf",
    "system_ext": "/etc/vintf",
    "product": "/etc/vintf",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    plan_path = Path(args.plan).resolve()
    output = Path(args.out).resolve()
    if not output.is_relative_to(ROOT):
        raise BuilderError("Evidence output must stay inside this project")
    if output.exists():
        raise BuilderError(f"Refusing to overwrite evidence directory: {output}")
    plan = json.loads(plan_path.read_text(encoding="utf-8-sig"))
    records = {entry["partition"]: entry for entry in plan["inputs"]}
    tool = Toolchain(ROOT).require("extract.erofs")
    tools = json.loads((ROOT / "builder/tools/manifest.json").read_text(encoding="utf-8-sig"))
    expected_tool = next(entry for entry in tools["tools"] if entry["name"] == "extract.erofs.exe")
    tool_hash = sha256_file(tool)
    if tool_hash != expected_tool["sha256"]:
        raise BuilderError("extract.erofs hash does not match the recorded tool")
    # Verify all sources before running the extractor.
    for partition in TARGETS:
        record = records[partition]
        image = Path(record["path"]).resolve()
        if not image.is_relative_to(ROOT) or not image.is_file():
            raise BuilderError(f"Input image is outside the project or missing: {partition}")
        if image.stat().st_size != record["size_bytes"] or sha256_file(image) != record["sha256"]:
            raise BuilderError(f"Input image differs from the structural plan: {partition}")
    output.mkdir(parents=True)
    extractor = ErofsExtractor(tool)
    report = {
        "schema_version": 1,
        "purpose": "vintf_evidence_inventory_only",
        "compatibility_verified": False,
        "device_boot_tested": False,
        "plan_sha256": sha256_file(plan_path),
        "extractor_sha256": tool_hash,
        "sources": [],
        "xml_files": [],
        "limitations": [
            "This is a declaration inventory, not checkvintf.",
            "SKU selection, APEX fragments, mi_ext overlays and runtime registration are not resolved.",
            "Matching declarations do not prove version, transport or SELinux compatibility.",
        ],
    }
    for partition, logical_path in TARGETS.items():
        record = records[partition]
        destination = output / partition
        print(f"Extracting {partition}:{logical_path}", flush=True)
        source = {"partition": partition, "image_sha256": record["sha256"], "logical_path": logical_path}
        try:
            extractor.extract_path(Path(record["path"]), logical_path, destination)
            paths = sorted(destination.rglob("*.xml"))
            source["xml_count"] = len(paths)
            source["status"] = "extracted" if paths else "no_xml_observed"
            for path in paths:
                if path.is_symlink() or not path.resolve().is_relative_to(destination.resolve()):
                    raise BuilderError("Unexpected linked XML in extracted evidence")
                raw = path.read_bytes()
                root = ET.fromstring(raw)
                hals = []
                for hal in root.findall("hal"):
                    hals.append({
                        "attributes": dict(hal.attrib),
                        "format": hal.get("format"),
                        "optional": hal.get("optional"),
                        "name": hal.findtext("name"),
                        "versions": [item.text for item in hal.findall("version")],
                        "fqnames": [item.text for item in hal.findall("fqname")],
                        "interfaces": [
                            {"name": interface.findtext("name"),
                             "instances": [item.text for item in interface.findall("instance")],
                             "regex_instances": [item.text for item in interface.findall("regex-instance")]}
                            for interface in hal.findall("interface")
                        ],
                    })
                report["xml_files"].append({
                    "partition": partition, "path": str(path.relative_to(output)),
                    "sha256": sha256_file(path), "root": root.tag,
                    "attributes": dict(root.attrib),
                    "type": root.get("type"), "level": root.get("level"),
                    "target_level": root.get("target-level"), "hals": hals,
                })
        except (BuilderError, OSError, ET.ParseError) as error:
            source["status"] = "incomplete"
            source["error"] = str(error)
        report["sources"].append(source)
        (output / "inventory.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(output / "inventory.json"), "sources": report["sources"],
                      "xml_files": len(report["xml_files"]), "compatibility_verified": False}, indent=2))
    return 0 if all(item["status"] == "extracted" for item in report["sources"]) else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BuilderError, OSError, ValueError, KeyError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
