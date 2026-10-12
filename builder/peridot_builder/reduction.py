from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import BuilderError

APPROVED_REMOVE = "approved_remove"
RETAIN_REQUIRED_INPUT_METHOD = "retain_required_input_method"
ALLOWED_DECISIONS = {APPROVED_REMOVE, RETAIN_REQUIRED_INPUT_METHOD, "hold"}


def load_reduction_plan(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def summarize_reduction_plan(plan: dict[str, Any]) -> dict[str, Any]:
    candidates = list(plan.get("candidates", []))
    approved = [item for item in candidates if item.get("decision") == APPROVED_REMOVE]
    retained_imes = [
        item
        for item in candidates
        if item.get("is_input_method")
        and item.get("decision") == RETAIN_REQUIRED_INPUT_METHOD
    ]
    approved_bytes = sum(int(item.get("on_disk_bytes", 0)) for item in approved)
    minimum = int(plan.get("minimum_reduction_bytes", 0))
    target = int(plan.get("target_reduction_bytes", minimum))
    headroom = approved_bytes - minimum

    return {
        "schema_version": 1,
        "approved_removal_count": len(approved),
        "approved_reduction_bytes": approved_bytes,
        "minimum_reduction_bytes": minimum,
        "target_reduction_bytes": target,
        "projected_headroom_bytes": headroom,
        "meets_minimum": approved_bytes >= minimum,
        "meets_headroom_target": approved_bytes >= target,
        "dependencies_reviewed": all(
            bool(item.get("dependencies_reviewed")) for item in approved
        ),
        "retained_input_methods": [
            {
                "root": item.get("root"),
                "package": item.get("package"),
            }
            for item in retained_imes
        ],
        "approved_roots": [item.get("root") for item in approved],
        "config_cleanup": plan.get("safety", {}).get("config_cleanup", []),
    }


def validate_reduction_plan(
    plan: dict[str, Any],
    *,
    require_headroom_target: bool = True,
) -> dict[str, Any]:
    errors: list[str] = []
    candidates = list(plan.get("candidates", []))

    if not candidates:
        errors.append("reduction plan contains no candidates")

    seen_roots: set[str] = set()
    for item in candidates:
        root = str(item.get("root", ""))
        if not root.startswith("/"):
            errors.append(f"candidate root is not absolute: {root!r}")
        if root in seen_roots:
            errors.append(f"duplicate candidate root: {root}")
        seen_roots.add(root)

        decision = item.get("decision")
        if decision not in ALLOWED_DECISIONS:
            errors.append(f"{root}: unsupported decision {decision!r}")

        if decision == APPROVED_REMOVE:
            if int(item.get("on_disk_bytes", 0)) <= 0:
                errors.append(f"{root}: approved removal has no measured size")
            if not item.get("dependencies_reviewed"):
                errors.append(f"{root}: dependency review is incomplete")
            if not item.get("regression_tests"):
                errors.append(f"{root}: no regression tests are recorded")

    summary = summarize_reduction_plan(plan)

    safety = plan.get("safety", {})
    expected_ime = safety.get("retained_input_method_package")
    retained_packages = {
        item.get("package")
        for item in candidates
        if item.get("decision") == RETAIN_REQUIRED_INPUT_METHOD
    }
    if not expected_ime:
        errors.append("safety.retained_input_method_package is missing")
    elif expected_ime not in retained_packages:
        errors.append(
            f"required input method {expected_ime!r} is not explicitly retained"
        )

    if not summary["meets_minimum"]:
        errors.append(
            "approved removals do not recover the minimum super deficit"
        )
    if require_headroom_target and not summary["meets_headroom_target"]:
        errors.append(
            "approved removals do not meet the configured extra-headroom target"
        )
    if not summary["dependencies_reviewed"]:
        errors.append("one or more approved removals lack dependency review")

    declared = plan.get("approved_reduction_bytes")
    if declared is not None and int(declared) != summary["approved_reduction_bytes"]:
        errors.append(
            "declared approved_reduction_bytes does not match candidate sum"
        )

    declared_headroom = plan.get("projected_headroom_after_fit_bytes")
    if declared_headroom is not None and int(declared_headroom) != summary["projected_headroom_bytes"]:
        errors.append(
            "declared projected_headroom_after_fit_bytes does not match candidate sum"
        )

    if errors:
        raise BuilderError("Invalid product reduction plan: " + "; ".join(errors))

    return summary
