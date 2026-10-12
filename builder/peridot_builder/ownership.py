from __future__ import annotations

from typing import Any

from .errors import BuilderError
from .models import OtaInspection


DONOR_USERSPACE_ORDER = ("system", "system_ext", "product", "mi_ext")
TARGET_BOOT_STACK_ORDER = (
    "boot",
    "init_boot",
    "vendor_boot",
    "dtbo",
    "recovery",
)
TARGET_DYNAMIC_HARDWARE_ORDER = (
    "vendor",
    "odm",
    "vendor_dlkm",
    "system_dlkm",
)
TARGET_FIRMWARE_ORDER = (
    "abl",
    "aop",
    "aop_config",
    "bluetooth",
    "countrycode",
    "cpucp",
    "cpucp_dtb",
    "devcfg",
    "dsp",
    "featenabler",
    "hyp",
    "imagefv",
    "keymaster",
    "modem",
    "modemfirmware",
    "multiimgqti",
    "qupfw",
    "shrm",
    "tz",
    "uefi",
    "uefisecapp",
    "xbl",
    "xbl_config",
    "xbl_ramdump",
)
TARGET_HARDWARE_ORDER = (
    TARGET_BOOT_STACK_ORDER
    + TARGET_DYNAMIC_HARDWARE_ORDER
    + TARGET_FIRMWARE_ORDER
)
AVB_METADATA = ("vbmeta", "vbmeta_system", "vbmeta_vendor")


def _present(order: tuple[str, ...], names: set[str]) -> list[str]:
    return [name for name in order if name in names]


def _validate_codename(
    inspection: OtaInspection, expected: str | None, label: str
) -> None:
    if not expected or not inspection.device_candidates:
        return
    if expected not in inspection.device_candidates:
        raise BuilderError(
            f"{label} OTA codename mismatch: expected {expected}, "
            f"metadata reports {inspection.device_candidates}"
        )


def build_ownership_plan(
    stock: OtaInspection,
    donor: OtaInspection,
    expected_stock: str = "peridot",
    expected_donor: str | None = None,
) -> dict[str, Any]:
    _validate_codename(stock, expected_stock, "stock")
    _validate_codename(donor, expected_donor, "donor")

    stock_names = {item.name for item in stock.partitions}
    donor_names = {item.name for item in donor.partitions}
    if not stock_names or not donor_names:
        raise BuilderError(
            "Ownership planning requires payload partition inventories for both OTAs"
        )

    target_boot_stack = _present(TARGET_BOOT_STACK_ORDER, stock_names)
    target_dynamic_hardware = _present(
        TARGET_DYNAMIC_HARDWARE_ORDER, stock_names
    )
    target_firmware = _present(TARGET_FIRMWARE_ORDER, stock_names)
    target_hardware = _present(TARGET_HARDWARE_ORDER, stock_names)
    donor_userspace = _present(DONOR_USERSPACE_ORDER, donor_names)
    stock_avb = _present(AVB_METADATA, stock_names)

    required_stock = {"boot", "vendor", "odm"}
    required_donor = {"system", "product"}
    missing_stock = sorted(required_stock - stock_names)
    missing_donor = sorted(required_donor - donor_names)
    if missing_stock:
        raise BuilderError(
            f"Stock OTA is missing required target partitions: {missing_stock}"
        )
    if missing_donor:
        raise BuilderError(
            f"Donor OTA is missing required userspace partitions: {missing_donor}"
        )

    donor_excluded = sorted(donor_names - set(donor_userspace))
    stock_unstaged = sorted(
        stock_names - set(target_hardware) - set(stock_avb)
    )

    warnings: list[str] = []
    if "mi_ext" not in donor_names:
        warnings.append("Donor has no mi_ext partition; this may be normal for this build")
    if not stock.device_candidates:
        warnings.append("Stock OTA metadata did not advertise pre-device; codename was not verified")
    if expected_donor and not donor.device_candidates:
        warnings.append("Donor OTA metadata did not advertise pre-device; donor codename was not verified")

    return {
        "schema_version": 1,
        "policy": "peridot_hardware_plus_donor_userspace",
        "stock": {
            "path": stock.path,
            "sha256": stock.sha256,
            "device_candidates": stock.device_candidates,
            "take_boot_stack": target_boot_stack,
            "take_dynamic_hardware": target_dynamic_hardware,
            "take_firmware": target_firmware,
            "preserve": target_hardware,
            "avb_metadata_deferred": stock_avb,
            "not_staged_yet": stock_unstaged,
        },
        "donor": {
            "path": donor.path,
            "sha256": donor.sha256,
            "device_candidates": donor.device_candidates,
            "take_userspace": donor_userspace,
            "explicitly_do_not_take": donor_excluded,
        },
        "invariants": [
            "all available target boot, dynamic-hardware, and firmware partitions come from the selected peridot stock OTA",
            "donor firmware is never staged",
            "donor vendor/odm/boot stack is never staged",
            "AVB metadata is deferred until rebuilt images and topology are verified",
            "no compatibility patch is implied by this ownership plan",
        ],
        "warnings": warnings,
    }
