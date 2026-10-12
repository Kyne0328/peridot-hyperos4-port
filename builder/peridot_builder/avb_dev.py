from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .avb import AvbTool
from .errors import BuilderError
from .hashing import sha256_file


_GENERATED_NAMES = (
    "boot.img",
    "recovery.img",
    "product.img",
    "vbmeta_system.img",
    "vbmeta.img",
    "development.avbpubkey",
    "development-avb-manifest.json",
)


def load_development_avb_profile(path: Path) -> dict[str, Any]:
    try:
        profile = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BuilderError(f"Could not load development AVB profile {path}: {error}") from error
    validate_development_avb_profile(profile)
    return profile


def validate_development_avb_profile(profile: dict[str, Any]) -> None:
    if profile.get("mode") != "development_aosp_testkey":
        raise BuilderError("AVB profile must explicitly use development_aosp_testkey mode")
    if profile.get("production_trust") is not False:
        raise BuilderError("Development AVB profile must set production_trust=false")

    security = profile.get("security")
    if not isinstance(security, dict):
        raise BuilderError("Development AVB profile is missing security policy")
    if int(security.get("vbmeta_flags", -1)) != 0:
        raise BuilderError("Development AVB profile must keep top-level vbmeta flags at 0")
    if security.get("hashtree_disabled") is not False:
        raise BuilderError("Development AVB profile must not disable hashtree verification")
    if security.get("verification_disabled") is not False:
        raise BuilderError("Development AVB profile must not disable AVB verification")
    if security.get("fake_locked_properties") is not False:
        raise BuilderError("Development AVB profile must not fake locked/green properties")

    key = profile.get("key")
    if not isinstance(key, dict) or key.get("algorithm") != "SHA256_RSA4096":
        raise BuilderError("Development AVB profile must declare the RSA-4096 test key")

    product = profile.get("product")
    if not isinstance(product, dict):
        raise BuilderError("Development AVB profile is missing product policy")
    if int(product.get("partition_size", 0)) <= 0:
        raise BuilderError("Development AVB product partition size must be positive")
    if product.get("generate_fec") is not False:
        raise BuilderError(
            "This v0 development profile must explicitly record generate_fec=false"
        )

    chains = profile.get("vbmeta", {}).get("chains")
    expected = {
        ("boot", 3),
        ("recovery", 1),
        ("vbmeta_system", 2),
    }
    observed = {
        (str(item.get("partition")), int(item.get("rollback_slot", -1)))
        for item in chains or []
        if isinstance(item, dict)
    }
    if observed != expected:
        raise BuilderError(
            "Development AVB chain must exactly preserve boot:3, recovery:1, "
            "and vbmeta_system:2"
        )


def _props(config: dict[str, Any]) -> list[str]:
    result: list[str] = []
    properties = config.get("properties", {})
    if not isinstance(properties, dict):
        raise BuilderError("AVB properties must be a JSON object")
    for name, value in properties.items():
        result.extend(["--prop", f"{name}:{value}"])
    return result


def _require_image(directory: Path, name: str) -> Path:
    path = (directory / f"{name}.img").resolve()
    if not path.is_file():
        raise BuilderError(f"Required AVB source image is missing: {path}")
    return path


def _signing_environment() -> dict[str, str]:
    env = os.environ.copy()
    if shutil.which("openssl", path=env.get("PATH")):
        return env

    candidates = (
        Path(r"C:\Program Files\Git\usr\bin"),
        Path(r"C:\Program Files\Git\mingw64\bin"),
    )
    for directory in candidates:
        if (directory / "openssl.exe").is_file():
            env["PATH"] = str(directory) + os.pathsep + env.get("PATH", "")
            return env
    raise BuilderError(
        "AVB signing requires openssl. No openssl executable was found on PATH "
        "or in the standard Git for Windows directories."
    )


def _link(source: Path, destination: Path) -> None:
    try:
        os.link(source, destination)
    except OSError as error:
        raise BuilderError(
            "AVB verification needs same-volume hard links for large source images; "
            f"could not link {source} -> {destination}: {error}"
        ) from error


def _generated_record(path: Path) -> dict[str, Any]:
    return {
        "path": str(path.resolve()),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def build_development_avb(
    *,
    avbtool: Path,
    project_root: Path,
    profile: dict[str, Any],
    stock_physical_dir: Path,
    stock_dynamic_dir: Path,
    donor_dir: Path,
    product_image: Path,
    output_dir: Path,
) -> dict[str, Any]:
    validate_development_avb_profile(profile)

    stock_physical_dir = stock_physical_dir.resolve()
    stock_dynamic_dir = stock_dynamic_dir.resolve()
    donor_dir = donor_dir.resolve()
    product_image = product_image.resolve()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    occupied = [name for name in _GENERATED_NAMES if (output_dir / name).exists()]
    if occupied:
        raise BuilderError(
            "Refusing to overwrite existing development AVB outputs: "
            + ", ".join(occupied)
        )

    key_config = profile["key"]
    key_path = (project_root / str(key_config["path"])).resolve()
    if not key_path.is_file():
        raise BuilderError(f"Development AVB key is missing: {key_path}")
    observed_key_hash = sha256_file(key_path)
    if observed_key_hash != str(key_config["sha256"]):
        raise BuilderError(
            "Development AVB key hash mismatch: "
            f"expected {key_config['sha256']}, got {observed_key_hash}"
        )

    stock_physical = {
        name: _require_image(stock_physical_dir, name)
        for name in profile["source_layout"]["stock_physical"]
    }
    stock_dynamic = {
        name: _require_image(stock_dynamic_dir, name)
        for name in profile["source_layout"]["stock_dynamic"]
    }
    donor = {
        name: _require_image(donor_dir, name)
        for name in profile["source_layout"]["donor_userspace"]
    }
    if not product_image.is_file():
        raise BuilderError(f"Rebuilt product image is missing: {product_image}")

    tool = AvbTool(avbtool)
    env = _signing_environment()
    algorithm = str(key_config["algorithm"])
    public_key = output_dir / "development.avbpubkey"
    boot = output_dir / "boot.img"
    recovery = output_dir / "recovery.img"
    product = output_dir / "product.img"
    vbmeta_system = output_dir / "vbmeta_system.img"
    vbmeta = output_dir / "vbmeta.img"

    tool.run(
        "extract_public_key",
        "--key",
        str(key_path),
        "--output",
        str(public_key),
        env=env,
    )

    shutil.copyfile(stock_physical["boot"], boot)
    tool.run("erase_footer", "--image", str(boot))
    boot_config = profile["boot"]
    tool.run(
        "add_hash_footer",
        "--image",
        str(boot),
        "--partition_name",
        "boot",
        "--partition_size",
        str(boot_config["partition_size"]),
        "--hash_algorithm",
        str(boot_config["hash_algorithm"]),
        "--salt",
        str(boot_config["salt"]),
        "--algorithm",
        algorithm,
        "--key",
        str(key_path),
        "--rollback_index",
        str(boot_config["rollback_index"]),
        *_props(boot_config),
        env=env,
    )

    shutil.copyfile(stock_physical["recovery"], recovery)
    tool.run("erase_footer", "--image", str(recovery))
    recovery_config = profile["recovery"]
    tool.run(
        "add_hash_footer",
        "--image",
        str(recovery),
        "--partition_name",
        "recovery",
        "--partition_size",
        str(recovery_config["partition_size"]),
        "--hash_algorithm",
        str(recovery_config["hash_algorithm"]),
        "--salt",
        str(recovery_config["salt"]),
        "--algorithm",
        algorithm,
        "--key",
        str(key_path),
        "--rollback_index",
        str(recovery_config["rollback_index"]),
        *_props(recovery_config),
        env=env,
    )

    shutil.copyfile(product_image, product)
    product_config = profile["product"]
    product_args = [
        "add_hashtree_footer",
        "--image",
        str(product),
        "--partition_name",
        "product",
        "--partition_size",
        str(product_config["partition_size"]),
        "--hash_algorithm",
        str(product_config["hash_algorithm"]),
        "--salt",
        str(product_config["salt"]),
        "--algorithm",
        str(product_config["footer_algorithm"]),
        *_props(product_config),
    ]
    if product_config.get("generate_fec") is False:
        product_args.append("--do_not_generate_fec")
    tool.run(*product_args, env=env)

    vbmeta_system_config = profile["vbmeta_system"]
    tool.run(
        "make_vbmeta_image",
        "--output",
        str(vbmeta_system),
        "--padding_size",
        str(vbmeta_system_config["padding_size"]),
        "--algorithm",
        algorithm,
        "--key",
        str(key_path),
        "--rollback_index",
        str(vbmeta_system_config["rollback_index"]),
        "--flags",
        str(vbmeta_system_config["flags"]),
        "--include_descriptors_from_image",
        str(product),
        "--include_descriptors_from_image",
        str(donor["system"]),
        "--include_descriptors_from_image",
        str(donor["system_ext"]),
        env=env,
    )

    direct_sources = {
        "countrycode": stock_physical["countrycode"],
        "dtbo": stock_physical["dtbo"],
        "init_boot": stock_physical["init_boot"],
        "mi_ext": donor["mi_ext"],
        "odm": stock_dynamic["odm"],
        "system_dlkm": stock_dynamic["system_dlkm"],
        "vendor": stock_dynamic["vendor"],
        "vendor_boot": stock_physical["vendor_boot"],
        "vendor_dlkm": stock_dynamic["vendor_dlkm"],
    }
    vbmeta_config = profile["vbmeta"]
    top_args = [
        "make_vbmeta_image",
        "--output",
        str(vbmeta),
        "--padding_size",
        str(vbmeta_config["padding_size"]),
        "--algorithm",
        algorithm,
        "--key",
        str(key_path),
        "--rollback_index",
        str(vbmeta_config["rollback_index"]),
        "--flags",
        str(vbmeta_config["flags"]),
    ]
    for chain in vbmeta_config["chains"]:
        top_args.extend(
            [
                "--chain_partition",
                f"{chain['partition']}:{chain['rollback_slot']}:development.avbpubkey",
            ]
        )
    for name in vbmeta_config["descriptor_sources"]:
        top_args.extend(
            ["--include_descriptors_from_image", str(direct_sources[name])]
        )
    tool.run(*top_args, cwd=output_dir, env=env)

    verify_sources = {
        "boot": boot,
        "recovery": recovery,
        "product": product,
        "vbmeta_system": vbmeta_system,
        "vbmeta": vbmeta,
        "system": donor["system"],
        "system_ext": donor["system_ext"],
        **direct_sources,
    }
    with tempfile.TemporaryDirectory(
        prefix="peridot-avb-verify-",
        dir=str(output_dir.parent),
    ) as temp:
        verify_dir = Path(temp)
        for name, source in verify_sources.items():
            _link(source, verify_dir / f"{name}.img")
        _link(public_key, verify_dir / "development.avbpubkey")

        expected_chain_args: list[str] = []
        for chain in vbmeta_config["chains"]:
            expected_chain_args.extend(
                [
                    "--expected_chain_partition",
                    f"{chain['partition']}:{chain['rollback_slot']}:development.avbpubkey",
                ]
            )
        verification_output = tool.run(
            "verify_image",
            "--image",
            "vbmeta.img",
            "--key",
            str(key_path),
            *expected_chain_args,
            "--follow_chain_partitions",
            cwd=verify_dir,
            env=env,
        )

    top_info = tool.info_image(vbmeta)
    system_info = tool.info_image(vbmeta_system)
    observed_public_key_sha1 = str(top_info["header"].get("public_key_sha1", ""))
    if observed_public_key_sha1 != str(key_config["expected_public_key_sha1"]):
        raise BuilderError(
            "Generated AVB public-key fingerprint mismatch: "
            f"expected {key_config['expected_public_key_sha1']}, "
            f"got {observed_public_key_sha1}"
        )
    if int(top_info["header"].get("flags", -1)) != 0:
        raise BuilderError("Generated top-level vbmeta unexpectedly has non-zero flags")
    if int(system_info["header"].get("flags", -1)) != 0:
        raise BuilderError("Generated vbmeta_system unexpectedly has non-zero flags")

    generated = {
        name: _generated_record(path)
        for name, path in {
            "boot": boot,
            "recovery": recovery,
            "product": product,
            "vbmeta_system": vbmeta_system,
            "vbmeta": vbmeta,
            "public_key": public_key,
        }.items()
    }
    result = {
        "schema_version": 1,
        "profile_id": profile["id"],
        "mode": profile["mode"],
        "development_boot_candidate": True,
        "production_release": False,
        "device_boot_tested": False,
        "requires_unlocked_bootloader_or_accepted_custom_root": True,
        "avb": {
            "algorithm": algorithm,
            "public_key_sha1": observed_public_key_sha1,
            "top_level_flags": top_info["header"]["flags"],
            "vbmeta_system_flags": system_info["header"]["flags"],
            "hashtree_disabled": False,
            "verification_disabled": False,
            "product_fec_generated": bool(product_config["generate_fec"]),
            "full_chain_verified": True,
        },
        "security": profile["security"],
        "generated": generated,
        "verification_output": verification_output.rstrip(),
    }
    manifest = output_dir / "development-avb-manifest.json"
    manifest.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    result["manifest"] = str(manifest)
    return result
