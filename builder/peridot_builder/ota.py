from __future__ import annotations

import zipfile
from pathlib import Path

from .errors import RomValidationError
from .hashing import sha256_file
from .models import OtaInspection, PartitionInfo


ANDROID_METADATA = "META-INF/com/android/metadata"
PAYLOAD_PROPERTIES = "payload_properties.txt"


def parse_key_value_text(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _find_entry(names: list[str], expected: str) -> str | None:
    if expected in names:
        return expected
    suffix = "/" + expected
    for name in names:
        if name.endswith(suffix):
            return name
    return None


def inspect_ota(path: Path) -> OtaInspection:
    path = path.expanduser().resolve()
    if not path.is_file():
        raise RomValidationError(f"ROM file does not exist: {path}")

    file_hash = sha256_file(path)
    file_size = path.stat().st_size

    if not zipfile.is_zipfile(path):
        raise RomValidationError(
            f"Only full recovery OTA ZIP inputs are supported in builder v0: {path.name}"
        )

    metadata: dict[str, str] = {}
    payload_properties: dict[str, str] = {}
    warnings: list[str] = []

    with zipfile.ZipFile(path, "r") as archive:
        names = archive.namelist()
        payload_entry = _find_entry(names, "payload.bin")
        metadata_entry = _find_entry(names, ANDROID_METADATA)
        properties_entry = _find_entry(names, PAYLOAD_PROPERTIES)

        payload_size = None
        if payload_entry:
            payload_size = archive.getinfo(payload_entry).file_size
        else:
            warnings.append(
                "payload.bin is missing; this does not look like a full A/B recovery OTA"
            )

        if metadata_entry:
            raw = archive.read(metadata_entry).decode("utf-8", errors="replace")
            metadata = parse_key_value_text(raw)
        else:
            warnings.append("Android OTA metadata file is missing")

        if properties_entry:
            raw = archive.read(properties_entry).decode("utf-8", errors="replace")
            payload_properties = parse_key_value_text(raw)
        else:
            warnings.append("payload_properties.txt is missing")

    devices = [
        item.strip()
        for item in metadata.get("pre-device", "").split(",")
        if item.strip()
    ]

    return OtaInspection(
        path=str(path),
        size_bytes=file_size,
        sha256=file_hash,
        is_zip=True,
        has_payload=payload_entry is not None,
        payload_entry=payload_entry,
        payload_size_bytes=payload_size,
        metadata=metadata,
        payload_properties=payload_properties,
        device_candidates=devices,
        warnings=warnings,
    )


def attach_partitions(
    inspection: OtaInspection, partitions: list[PartitionInfo]
) -> OtaInspection:
    inspection.partitions = partitions
    return inspection
