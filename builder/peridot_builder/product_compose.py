from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .errors import BuilderError, ToolExecutionError
from .reduction import APPROVED_REMOVE, load_reduction_plan, validate_reduction_plan


def load_blueprint(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _logical_to_tree(root: Path, logical_path: str) -> Path:
    if not logical_path.startswith("/"):
        raise BuilderError(f"logical product path must be absolute: {logical_path!r}")
    return root / "product" / logical_path.lstrip("/")


def _remove_path(path: Path) -> bool:
    if path.is_dir():
        shutil.rmtree(path)
        return True
    if path.exists():
        path.unlink()
        return True
    return False


def _metadata_token_to_logical(token: str, kind: str) -> str:
    token = token.strip()
    if kind == "fs_config":
        if token == "product":
            return "/"
        prefix = "product/"
        if token.startswith(prefix):
            return "/" + token[len(prefix):]
        return "/" + token.lstrip("/")
    if kind == "file_contexts":
        token = token.replace(r"\.", ".").replace(r"\-", "-")
        prefix = "/product"
        if token == prefix:
            return "/"
        if token.startswith(prefix + "/"):
            return token[len(prefix):]
        return token
    raise ValueError(kind)


def _line_token(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    return stripped.split(maxsplit=1)[0]


def _is_under(logical: str, root: str) -> bool:
    root = root.rstrip("/") or "/"
    if root == "/":
        return True
    return logical == root or logical.startswith(root + "/")


def _filter_metadata_file(path: Path, removed_roots: list[str], kind: str) -> int:
    if not path.exists():
        return 0
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    kept: list[str] = []
    removed = 0
    for line in lines:
        token = _line_token(line)
        if token is None:
            kept.append(line)
            continue
        logical = _metadata_token_to_logical(token, kind)
        if any(_is_under(logical, root) for root in removed_roots):
            removed += 1
            continue
        kept.append(line)
    path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    return removed


def _collect_metadata_lines(path: Path, logical_paths: list[str], kind: str) -> list[str]:
    if not path.exists():
        return []
    result: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        token = _line_token(line)
        if token is None:
            continue
        logical = _metadata_token_to_logical(token, kind)
        if any(_is_under(logical, requested) or _is_under(requested, logical) for requested in logical_paths):
            result.append(line)
    return result


def _merge_metadata_lines(path: Path, replacement_lines: list[str], logical_paths: list[str], kind: str) -> int:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        existing: list[str] = []
    else:
        existing = path.read_text(encoding="utf-8", errors="replace").splitlines()

    filtered: list[str] = []
    for line in existing:
        token = _line_token(line)
        if token is None:
            filtered.append(line)
            continue
        logical = _metadata_token_to_logical(token, kind)
        if any(_is_under(logical, requested) for requested in logical_paths):
            continue
        filtered.append(line)

    seen = set(filtered)
    inserted = 0
    for line in replacement_lines:
        if line not in seen:
            filtered.append(line)
            seen.add(line)
            inserted += 1

    path.write_text("\n".join(filtered) + ("\n" if filtered else ""), encoding="utf-8")
    return inserted


def _remove_privapp_blocks(path: Path, packages: list[str]) -> list[str]:
    if not path.exists():
        raise BuilderError(f"privileged-permission XML is missing: {path}")
    tree = ET.parse(path)
    root = tree.getroot()
    removed: list[str] = []
    for child in list(root):
        if child.tag != "privapp-permissions":
            continue
        package = child.attrib.get("package")
        if package in packages:
            root.remove(child)
            removed.append(package or "")
    ET.indent(tree, space="    ")
    tree.write(path, encoding="utf-8", xml_declaration=True)
    missing = sorted(set(packages) - set(removed))
    if missing:
        raise BuilderError(
            "requested privileged-permission blocks were not found: " + ", ".join(missing)
        )
    return removed


def _append_unique_lines(source: Path, target: Path) -> int:
    if not source.exists():
        return 0
    target.parent.mkdir(parents=True, exist_ok=True)
    existing = (
        target.read_text(encoding="utf-8", errors="replace").splitlines()
        if target.exists()
        else []
    )
    seen = set(existing)
    inserted = 0
    for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
        if line not in seen:
            existing.append(line)
            seen.add(line)
            inserted += 1
    target.write_text(
        "\n".join(existing) + ("\n" if existing else ""),
        encoding="utf-8",
    )
    return inserted


def _merge_targeted_stock_extract(
    source_root: Path,
    aggregate_root: Path,
    logical_path: str,
) -> None:
    source_file = _logical_to_tree(source_root, logical_path)
    if not source_file.is_file():
        raise BuilderError(
            f"targeted stock extraction did not produce expected file: {logical_path}"
        )
    target_file = _logical_to_tree(aggregate_root, logical_path)
    target_file.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_file, target_file)

    for name in ("product_fs_config", "product_file_contexts"):
        _append_unique_lines(
            source_root / "config" / name,
            aggregate_root / "config" / name,
        )


def _tree_stats(product_root: Path) -> dict[str, int]:
    files = 0
    bytes_total = 0
    for path in product_root.rglob("*"):
        if path.is_file():
            files += 1
            bytes_total += path.stat().st_size
    return {"file_count": files, "logical_file_bytes": bytes_total}


def apply_product_plan(
    *,
    donor_extract_root: Path,
    stock_extract_root: Path,
    blueprint: dict[str, Any],
    reduction_plan: dict[str, Any],
) -> dict[str, Any]:
    validate_reduction_plan(reduction_plan)

    donor_extract_root = donor_extract_root.resolve()
    stock_extract_root = stock_extract_root.resolve()
    product_root = donor_extract_root / "product"
    config_root = donor_extract_root / "config"

    if not product_root.is_dir():
        raise BuilderError(f"donor product tree is missing: {product_root}")
    if not (stock_extract_root / "product").is_dir():
        raise BuilderError(f"stock product overlay tree is missing: {stock_extract_root / 'product'}")

    removed_roots = [
        str(item["root"])
        for item in reduction_plan.get("candidates", [])
        if item.get("decision") == APPROVED_REMOVE
    ]
    removed_paths: list[str] = []
    already_absent: list[str] = []
    for logical in removed_roots:
        if _remove_path(_logical_to_tree(donor_extract_root, logical)):
            removed_paths.append(logical)
        else:
            already_absent.append(logical)

    target_ops = list(blueprint.get("product_target_config", []))
    donor_removals: list[str] = []
    copied_stock: list[dict[str, str]] = []
    copied_logical_paths: list[str] = []

    for operation in target_ops:
        op = operation.get("operation")
        source_partition = operation.get("source_partition")
        source_path = str(operation.get("source_path", ""))
        if source_partition == "donor_product" and op == "remove":
            _remove_path(_logical_to_tree(donor_extract_root, source_path))
            donor_removals.append(source_path)
            continue
        if source_partition == "stock_product" and op in {"copy", "copy_stock_version"}:
            destination = str(operation.get("destination_path") or source_path)
            source = _logical_to_tree(stock_extract_root, source_path)
            target = _logical_to_tree(donor_extract_root, destination)
            if not source.is_file():
                raise BuilderError(f"required stock product file is missing: {source_path}")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            copied_logical_paths.append(destination)
            copied_stock.append(
                {
                    "source_path": source_path,
                    "destination_path": destination,
                    "sha256": _sha256(target),
                }
            )
            continue
        raise BuilderError(f"unsupported product target-config operation: {operation}")

    cleanup_packages = [
        str(item["package"])
        for item in blueprint.get("product_config_cleanup", [])
        if item.get("operation") == "remove_privapp_block"
    ]
    cleanup_paths = {
        str(item["path"])
        for item in blueprint.get("product_config_cleanup", [])
        if item.get("operation") == "remove_privapp_block"
    }
    if len(cleanup_paths) > 1:
        raise BuilderError("multiple privileged-permission cleanup files are not supported yet")
    cleaned_packages: list[str] = []
    if cleanup_packages:
        cleanup_path = next(iter(cleanup_paths))
        cleaned_packages = _remove_privapp_blocks(
            _logical_to_tree(donor_extract_root, cleanup_path),
            cleanup_packages,
        )

    metadata_removed_roots = sorted(set(removed_roots + donor_removals))
    fs_config = config_root / "product_fs_config"
    file_contexts = config_root / "product_file_contexts"
    removed_fs_config = _filter_metadata_file(fs_config, metadata_removed_roots, "fs_config")
    removed_file_contexts = _filter_metadata_file(
        file_contexts, metadata_removed_roots, "file_contexts"
    )

    stock_config = stock_extract_root / "config"
    stock_fs_lines = _collect_metadata_lines(
        stock_config / "product_fs_config", copied_logical_paths, "fs_config"
    )
    stock_ctx_lines = _collect_metadata_lines(
        stock_config / "product_file_contexts", copied_logical_paths, "file_contexts"
    )
    inserted_fs_config = _merge_metadata_lines(
        fs_config, stock_fs_lines, copied_logical_paths, "fs_config"
    )
    inserted_file_contexts = _merge_metadata_lines(
        file_contexts, stock_ctx_lines, copied_logical_paths, "file_contexts"
    )

    retained_imes = [
        str(item["root"])
        for item in reduction_plan.get("candidates", [])
        if item.get("decision") == "retain_required_input_method"
    ]
    missing_retained = [
        path for path in retained_imes if not _logical_to_tree(donor_extract_root, path).exists()
    ]
    if missing_retained:
        raise BuilderError(
            "required retained input method is missing after composition: "
            + ", ".join(missing_retained)
        )

    stale_madrid_paths = [
        path
        for path in donor_removals
        if _logical_to_tree(donor_extract_root, path).exists()
    ]
    if stale_madrid_paths:
        raise BuilderError(
            "donor target-specific files remain after composition: "
            + ", ".join(stale_madrid_paths)
        )

    for copied in copied_stock:
        stock_source = _logical_to_tree(stock_extract_root, copied["source_path"])
        donor_target = _logical_to_tree(donor_extract_root, copied["destination_path"])
        if _sha256(stock_source) != _sha256(donor_target):
            raise BuilderError(
                f"stock transplant hash mismatch: {copied['destination_path']}"
            )

    stats = _tree_stats(product_root)
    return {
        "schema_version": 1,
        "status": "composed",
        "removed_approved_roots": removed_paths,
        "already_absent_approved_roots": already_absent,
        "removed_target_specific_donor_paths": donor_removals,
        "copied_stock_files": copied_stock,
        "cleaned_privapp_packages": cleaned_packages,
        "metadata": {
            "removed_fs_config_lines": removed_fs_config,
            "removed_file_context_lines": removed_file_contexts,
            "inserted_stock_fs_config_lines": inserted_fs_config,
            "inserted_stock_file_context_lines": inserted_file_contexts,
        },
        "retained_input_method_roots": retained_imes,
        "tree_stats": stats,
    }


class ErofsExtractor:
    def __init__(self, executable: Path):
        self.executable = executable.resolve()

    def _run(self, args: list[str]) -> None:
        process = subprocess.run(
            [str(self.executable), *args],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        if process.returncode != 0:
            detail = process.stderr.strip() or process.stdout.strip()
            raise ToolExecutionError(
                f"extract.erofs failed with exit code {process.returncode}: {detail}"
            )

    def extract_all(self, image: Path, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        self._run(["-i", str(image.resolve()), "-x", "-o", str(output_dir.resolve()), "-s"])

    def extract_path(self, image: Path, logical_path: str, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        self._run(
            [
                "-i",
                str(image.resolve()),
                "-X",
                logical_path,
                "-o",
                str(output_dir.resolve()),
                "-s",
            ]
        )


def compose_product_from_images(
    *,
    extractor: ErofsExtractor,
    donor_product_image: Path,
    stock_product_image: Path,
    output_dir: Path,
    blueprint: dict[str, Any],
    reduction_plan: dict[str, Any],
) -> dict[str, Any]:
    output_dir = output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise BuilderError(f"product composition output is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    extractor.extract_all(donor_product_image, output_dir)

    stock_paths = [
        str(item.get("source_path"))
        for item in blueprint.get("product_target_config", [])
        if item.get("source_partition") == "stock_product"
        and item.get("operation") in {"copy", "copy_stock_version"}
    ]
    with tempfile.TemporaryDirectory(prefix="peridot-stock-product-") as temp:
        temp_root = Path(temp)
        stock_root = temp_root / "aggregate"
        for index, logical_path in enumerate(stock_paths):
            part_root = temp_root / f"part-{index:02d}"
            extractor.extract_path(stock_product_image, logical_path, part_root)
            _merge_targeted_stock_extract(part_root, stock_root, logical_path)
        result = apply_product_plan(
            donor_extract_root=output_dir,
            stock_extract_root=stock_root,
            blueprint=blueprint,
            reduction_plan=reduction_plan,
        )

    manifest_path = output_dir / "composition-manifest.json"
    manifest_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    result["manifest_path"] = str(manifest_path)
    return result
