from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .avb import AvbTool
from .avb_dev import build_development_avb, load_development_avb_profile
from .composition import build_super_budget
from .errors import BuilderError, ToolUnavailableError
from .global_plan import prepare_global_sources
from .lp import inspect_super_image, inspect_super_zip
from .ota import attach_partitions, inspect_ota
from .ownership import build_ownership_plan
from .profile import build_device_profile, load_reference, write_profile
from .product_compose import (
    ErofsExtractor,
    compose_product_from_images,
    load_blueprint,
)
from .reduction import load_reduction_plan, validate_reduction_plan
from .stage import stage_inputs
from .super_plan import (
    build_structural_super_plan,
    load_super_reference,
    run_structural_super_plan,
    verify_structural_super,
)
from .tools import PayloadDumperGo, Toolchain


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_reference() -> Path:
    return project_root() / "builder" / "devices" / "peridot" / "reference.json"


def default_profile_output() -> Path:
    return project_root() / "builder" / "work" / "profiles" / "peridot-profile.json"


def default_reduction_plan() -> Path:
    return (
        project_root()
        / "builder"
        / "devices"
        / "peridot"
        / "composition"
        / "madrid-4.0.11-product-reduction-candidates.json"
    )


def default_composition_blueprint() -> Path:
    return (
        project_root()
        / "builder"
        / "devices"
        / "peridot"
        / "composition"
        / "madrid-4.0.11-clean-v0.json"
    )


def default_development_avb_profile() -> Path:
    return (
        project_root()
        / "builder"
        / "devices"
        / "peridot"
        / "avb"
        / "development-aosp-testkey-v0.json"
    )


def emit(data: object) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def inspect_with_optional_partitions(
    rom: Path,
    toolchain: Toolchain,
    include_partitions: bool,
):
    inspection = inspect_ota(rom)
    if include_partitions:
        executable = toolchain.find("payload-dumper-go")
        if executable:
            partitions = PayloadDumperGo(executable).list_partitions(rom)
            attach_partitions(inspection, partitions)
        else:
            inspection.warnings.append(
                "payload-dumper-go not found; partition inventory was skipped"
            )
    return inspection


def command_preflight(args: argparse.Namespace) -> int:
    root = project_root()
    tools = Toolchain(root)
    statuses = [status.to_dict() for status in tools.status()]
    result: dict[str, object] = {
        "project_root": str(root),
        "tools": statuses,
        "required_for_profile": ["payload-dumper-go"],
        "required_for_extract": ["payload-dumper-go"],
        "required_for_avb_inspect": ["avbtool"],
        "future_repack_tools": [
            "lpdump",
            "lpunpack",
            "lpmake",
            "mkfs.erofs",
            "avbtool",
        ],
    }
    if args.rom:
        result["rom"] = inspect_ota(Path(args.rom)).to_dict()

    emit(result)
    if args.require_profile_tools and not tools.find("payload-dumper-go"):
        return 2
    return 0


def command_inspect(args: argparse.Namespace) -> int:
    tools = Toolchain(project_root())
    inspection = inspect_with_optional_partitions(
        Path(args.rom), tools, args.partitions
    )
    data = inspection.to_dict()
    if args.out:
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    emit(data)
    return 0


def command_profile(args: argparse.Namespace) -> int:
    root = project_root()
    tools = Toolchain(root)
    inspection = inspect_with_optional_partitions(Path(args.stock), tools, True)

    if args.require_tools and not inspection.partitions:
        raise ToolUnavailableError(
            "A full device profile requires payload-dumper-go, but it is unavailable"
        )

    reference_path = (
        Path(args.reference).resolve() if args.reference else default_reference()
    )
    reference = load_reference(reference_path)
    profile = build_device_profile(inspection, reference)

    if args.strict and not profile["verification"]["codename_matches_stock_metadata"]:
        expected = reference["device"]["codename"]
        observed = inspection.device_candidates
        raise BuilderError(
            f"Strict profile rejected OTA: expected {expected}, metadata reports {observed}"
        )

    output = Path(args.out).resolve() if args.out else default_profile_output()
    write_profile(profile, output)
    profile["profile_path"] = str(output)
    emit(profile)
    return 0


def command_extract(args: argparse.Namespace) -> int:
    rom = Path(args.rom).resolve()
    output = Path(args.out).resolve()
    tools = Toolchain(project_root())
    executable = tools.require("payload-dumper-go")
    dumper = PayloadDumperGo(executable)

    partitions: list[str] | None = None
    if args.partitions:
        partitions = [
            item.strip() for item in args.partitions.split(",") if item.strip()
        ]
    elif not args.all:
        raise BuilderError(
            "Refusing an implicit full extraction. Pass --partitions name1,name2 "
            "or explicitly pass --all."
        )

    dumper.extract(rom, output, partitions)
    emit(
        {
            "rom": str(rom),
            "output": str(output),
            "partitions": partitions if partitions is not None else "all",
            "status": "complete",
        }
    )
    return 0


def _inspect_required_partitions(rom: Path, tools: Toolchain):
    executable = tools.require("payload-dumper-go")
    inspection = inspect_ota(rom)
    attach_partitions(
        inspection,
        PayloadDumperGo(executable).list_partitions(rom),
    )
    return inspection


def command_prepare(args: argparse.Namespace) -> int:
    tools = Toolchain(project_root())
    stock = _inspect_required_partitions(Path(args.stock).resolve(), tools)
    donor = _inspect_required_partitions(Path(args.donor).resolve(), tools)
    plan = build_ownership_plan(
        stock,
        donor,
        expected_stock=args.stock_codename,
        expected_donor=args.donor_codename,
    )
    if args.out:
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(plan, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    emit(plan)
    return 0


def command_budget(args: argparse.Namespace) -> int:
    root = project_root()
    tools = Toolchain(root)
    stock = _inspect_required_partitions(Path(args.stock).resolve(), tools)
    donor = _inspect_required_partitions(Path(args.donor).resolve(), tools)
    plan = build_ownership_plan(
        stock,
        donor,
        expected_stock=args.stock_codename,
        expected_donor=args.donor_codename,
    )

    reference_path = (
        Path(args.reference).resolve() if args.reference else default_reference()
    )
    reference = load_reference(reference_path)
    super_size = int(reference["hints"]["super_size_bytes"])
    budget = build_super_budget(stock, donor, plan, super_size)

    if args.out:
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(budget, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    emit(budget)
    return 0


def command_validate_reduction(args: argparse.Namespace) -> int:
    path = Path(args.plan).resolve() if args.plan else default_reduction_plan()
    plan = load_reduction_plan(path)
    summary = validate_reduction_plan(
        plan,
        require_headroom_target=not args.minimum_only,
    )
    summary["plan_path"] = str(path)
    emit(summary)
    return 0


def command_compose_product(args: argparse.Namespace) -> int:
    root = project_root()
    tools = Toolchain(root)
    executable = tools.require("extract.erofs")
    blueprint_path = (
        Path(args.blueprint).resolve()
        if args.blueprint
        else default_composition_blueprint()
    )
    reduction_path = (
        Path(args.plan).resolve() if args.plan else default_reduction_plan()
    )
    blueprint = load_blueprint(blueprint_path)
    reduction_plan = load_reduction_plan(reduction_path)
    result = compose_product_from_images(
        extractor=ErofsExtractor(executable),
        donor_product_image=Path(args.donor_product),
        stock_product_image=Path(args.stock_product),
        output_dir=Path(args.out),
        blueprint=blueprint,
        reduction_plan=reduction_plan,
    )
    result["blueprint_path"] = str(blueprint_path)
    result["reduction_plan_path"] = str(reduction_path)
    emit(result)
    return 0


def command_inspect_avb(args: argparse.Namespace) -> int:
    tools = Toolchain(project_root())
    executable = tools.require("avbtool")
    result = AvbTool(executable).info_image(Path(args.image))

    if args.out:
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    emit(result)
    return 0


def command_build_avb_dev(args: argparse.Namespace) -> int:
    root = project_root()
    tools = Toolchain(root)
    executable = tools.require("avbtool")
    profile_path = (
        Path(args.profile).resolve()
        if args.profile
        else default_development_avb_profile()
    )
    profile = load_development_avb_profile(profile_path)
    result = build_development_avb(
        avbtool=executable,
        project_root=root,
        profile=profile,
        stock_physical_dir=Path(args.stock_physical_dir),
        stock_dynamic_dir=Path(args.stock_dynamic_dir),
        donor_dir=Path(args.donor_dir),
        product_image=Path(args.product),
        output_dir=Path(args.out),
    )
    result["profile_path"] = str(profile_path)
    emit(result)
    return 0


def command_inspect_super(args: argparse.Namespace) -> int:
    if args.image:
        result = inspect_super_image(Path(args.image))
    else:
        result = inspect_super_zip(
            Path(args.zip),
            entry_name=args.entry,
        )
    if args.out:
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    emit(result)
    return 0


def command_plan_super(args: argparse.Namespace) -> int:
    reference = load_super_reference(Path(args.reference).resolve())
    stock_dir = Path(args.stock_dir).resolve()
    donor_dir = Path(args.donor_dir).resolve()
    images = {
        "mi_ext": donor_dir / "mi_ext.img",
        "odm": stock_dir / "odm.img",
        "product": Path(args.product).resolve(),
        "system": donor_dir / "system.img",
        "system_dlkm": stock_dir / "system_dlkm.img",
        "system_ext": donor_dir / "system_ext.img",
        "vendor": stock_dir / "vendor.img",
        "vendor_dlkm": stock_dir / "vendor_dlkm.img",
    }
    result = build_structural_super_plan(
        reference,
        images,
        Path(args.output),
    )
    if not result["fits_raw_layout"]:
        raise BuilderError(
            "Mixed image set does not fit the observed peridot super layout: "
            f"{result['raw_headroom_bytes']} bytes headroom"
        )

    if args.out:
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    emit(result)
    return 0


def command_build_super_structural(args: argparse.Namespace) -> int:
    tools = Toolchain(project_root())
    executable = tools.require("lpmake")
    plan = load_super_reference(Path(args.plan).resolve())
    result = run_structural_super_plan(executable, plan)

    if args.out:
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    emit(result)
    return 0


def command_verify_super_structural(args: argparse.Namespace) -> int:
    plan = load_super_reference(Path(args.plan).resolve())
    result = verify_structural_super(Path(args.image), plan)

    if args.out:
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    emit(result)
    return 0


def command_stage(args: argparse.Namespace) -> int:
    tools = Toolchain(project_root())
    executable = tools.require("payload-dumper-go")
    stock = _inspect_required_partitions(Path(args.stock).resolve(), tools)
    donor = _inspect_required_partitions(Path(args.donor).resolve(), tools)
    plan = build_ownership_plan(
        stock,
        donor,
        expected_stock=args.stock_codename,
        expected_donor=args.donor_codename,
    )
    manifest = stage_inputs(
        PayloadDumperGo(executable),
        stock,
        donor,
        plan,
        Path(args.out),
    )
    emit(manifest)
    return 0


def command_prepare_global(args: argparse.Namespace) -> int:
    profile = (Path(args.source_profile).resolve() if args.source_profile else
               project_root() / "builder/devices/peridot/sources/global-pudding-4.0.0.9-peridot-3.0.303.json")
    result = prepare_global_sources(Path(args.stock).resolve(), Path(args.donor).resolve(), profile)
    if args.out:
        output = Path(args.out).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
    emit(result)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="peridot-builder",
        description=(
            "Evidence-first HyperOS port builder foundation for POCO F6 / peridot"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    global_prepare = sub.add_parser(
        "prepare-global", help="Verify exact Global source locks and plan without ROM-tool dependencies")
    global_prepare.add_argument("--stock", required=True)
    global_prepare.add_argument("--donor", required=True)
    global_prepare.add_argument("--source-profile")
    global_prepare.add_argument("--out")
    global_prepare.set_defaults(func=command_prepare_global)

    preflight = sub.add_parser(
        "preflight", help="Check local tools and optional ROM input"
    )
    preflight.add_argument("--rom")
    preflight.add_argument("--require-profile-tools", action="store_true")
    preflight.set_defaults(func=command_preflight)

    inspect = sub.add_parser("inspect", help="Inspect an OTA without modifying it")
    inspect.add_argument("--rom", required=True)
    inspect.add_argument(
        "--partitions",
        action="store_true",
        help="Also query payload-dumper-go for the partition inventory when available",
    )
    inspect.add_argument("--out")
    inspect.set_defaults(func=command_inspect)

    profile = sub.add_parser(
        "profile", help="Generate a peridot device profile from a stock full OTA"
    )
    profile.add_argument("--stock", required=True)
    profile.add_argument("--reference")
    profile.add_argument("--out")
    profile.add_argument("--strict", action="store_true")
    profile.add_argument("--require-tools", action="store_true")
    profile.set_defaults(func=command_profile)

    extract = sub.add_parser(
        "extract", help="Extract selected partitions using payload-dumper-go"
    )
    extract.add_argument("--rom", required=True)
    extract.add_argument("--out", required=True)
    group = extract.add_mutually_exclusive_group()
    group.add_argument("--partitions")
    group.add_argument("--all", action="store_true")
    extract.set_defaults(func=command_extract)

    prepare = sub.add_parser(
        "prepare",
        help="Validate stock+donor OTAs and emit the partition ownership plan",
    )
    prepare.add_argument("--stock", required=True)
    prepare.add_argument("--donor", required=True)
    prepare.add_argument("--stock-codename", default="peridot")
    prepare.add_argument("--donor-codename")
    prepare.add_argument("--out")
    prepare.set_defaults(func=command_prepare)

    budget = sub.add_parser(
        "budget",
        help="Calculate the clean target-hardware + donor-userspace super budget",
    )
    budget.add_argument("--stock", required=True)
    budget.add_argument("--donor", required=True)
    budget.add_argument("--stock-codename", default="peridot")
    budget.add_argument("--donor-codename")
    budget.add_argument("--reference")
    budget.add_argument("--out")
    budget.set_defaults(func=command_budget)

    reduction = sub.add_parser(
        "validate-reduction",
        help="Validate the reviewed Madrid product trim plan and super headroom",
    )
    reduction.add_argument("--plan")
    reduction.add_argument(
        "--minimum-only",
        action="store_true",
        help="Require only the hard super-fit minimum, not the configured extra-headroom target",
    )
    reduction.set_defaults(func=command_validate_reduction)

    compose_product = sub.add_parser(
        "compose-product",
        help="Extract and compose the reviewed clean-v0 Madrid product tree for peridot",
    )
    compose_product.add_argument("--donor-product", required=True)
    compose_product.add_argument("--stock-product", required=True)
    compose_product.add_argument("--out", required=True)
    compose_product.add_argument("--blueprint")
    compose_product.add_argument("--plan")
    compose_product.set_defaults(func=command_compose_product)

    inspect_avb = sub.add_parser(
        "inspect-avb",
        help="Inspect AVB metadata or a footer-bearing image with pinned avbtool",
    )
    inspect_avb.add_argument("--image", required=True)
    inspect_avb.add_argument("--out")
    inspect_avb.set_defaults(func=command_inspect_avb)

    build_avb_dev = sub.add_parser(
        "build-avb-dev",
        help=(
            "Build and fully verify the explicit AOSP-testkey development AVB "
            "chain without disabling hashtree or verification"
        ),
    )
    build_avb_dev.add_argument("--profile")
    build_avb_dev.add_argument("--stock-physical-dir", required=True)
    build_avb_dev.add_argument("--stock-dynamic-dir", required=True)
    build_avb_dev.add_argument("--donor-dir", required=True)
    build_avb_dev.add_argument("--product", required=True)
    build_avb_dev.add_argument("--out", required=True)
    build_avb_dev.set_defaults(func=command_build_avb_dev)

    inspect_super = sub.add_parser(
        "inspect-super",
        help="Inspect logical-partition metadata from a super image or ZIP entry",
    )
    inspect_super_source = inspect_super.add_mutually_exclusive_group(required=True)
    inspect_super_source.add_argument("--zip")
    inspect_super_source.add_argument("--image")
    inspect_super.add_argument("--entry", default="images/super.img")
    inspect_super.add_argument("--out")
    inspect_super.set_defaults(func=command_inspect_super)

    plan_super = sub.add_parser(
        "plan-super",
        help="Plan a structural-only mixed super image from observed peridot layout",
    )
    plan_super.add_argument("--reference", required=True)
    plan_super.add_argument("--stock-dir", required=True)
    plan_super.add_argument("--donor-dir", required=True)
    plan_super.add_argument("--product", required=True)
    plan_super.add_argument("--output", required=True)
    plan_super.add_argument("--out")
    plan_super.set_defaults(func=command_plan_super)

    build_super_structural = sub.add_parser(
        "build-super-structural",
        help="Execute a reviewed structural-only super plan; output is not boot-ready",
    )
    build_super_structural.add_argument("--plan", required=True)
    build_super_structural.add_argument("--out")
    build_super_structural.set_defaults(func=command_build_super_structural)

    verify_super_structural = sub.add_parser(
        "verify-super-structural",
        help="Verify structural super metadata and each logical partition against its input hash",
    )
    verify_super_structural.add_argument("--plan", required=True)
    verify_super_structural.add_argument("--image", required=True)
    verify_super_structural.add_argument("--out")
    verify_super_structural.set_defaults(func=command_verify_super_structural)

    stage = sub.add_parser(
        "stage",
        help="Extract the clean target hardware and donor userspace partition sets",
    )
    stage.add_argument("--stock", required=True)
    stage.add_argument("--donor", required=True)
    stage.add_argument("--stock-codename", default="peridot")
    stage.add_argument("--donor-codename")
    stage.add_argument("--out", required=True)
    stage.set_defaults(func=command_stage)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except BuilderError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130
