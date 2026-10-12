"""Bounded, read-only projection of a full OTA payload manifest.

Schema: AOSP platform/system/update_engine/update_metadata.proto
blob 6d16da40e53720078b2e4f3689dbb296eb325bee. Unknown fields are skipped.
The manifest describes update groups, not physical liblp geometry.
"""
from __future__ import annotations

import hashlib
import re
import struct
import zipfile
from pathlib import Path
from typing import Any

from .errors import BuilderError

MAX_MANIFEST = 64 * 1024 * 1024


def _varint(data: bytes, position: int) -> tuple[int, int]:
    value = 0
    for index in range(10):
        if position >= len(data):
            raise BuilderError("Truncated payload protobuf varint")
        byte = data[position]
        position += 1
        if index == 9 and byte > 1:
            raise BuilderError("Payload protobuf integer exceeds uint64")
        value |= (byte & 127) << (7 * index)
        if byte < 128:
            if index and byte == 0:
                raise BuilderError("Noncanonical payload protobuf varint")
            return value, position
    raise BuilderError("Unterminated payload protobuf varint")


def _fields(data: bytes) -> list[tuple[int, int, Any]]:
    result = []
    position = 0
    while position < len(data):
        key, position = _varint(data, position)
        number, wire = key >> 3, key & 7
        if not 1 <= number <= 536870911:
            raise BuilderError("Invalid payload protobuf field number")
        if wire == 0:
            value, position = _varint(data, position)
        elif wire in (1, 2, 5):
            if wire == 2:
                length, position = _varint(data, position)
            else:
                length = 8 if wire == 1 else 4
            if length > len(data) - position:
                raise BuilderError("Truncated payload protobuf field")
            value = data[position:position + length]
            position += length
        else:
            raise BuilderError("Unsupported payload protobuf wire type")
        result.append((number, wire, value))
    return result


def _one(fields: list[tuple[int, int, Any]], number: int, wire: int,
         default: Any = None, required: bool = True) -> Any:
    matches = [(w, value) for n, w, value in fields if n == number]
    if not matches and not required:
        return default
    if len(matches) != 1 or matches[0][0] != wire:
        raise BuilderError(f"Missing, duplicate or mistyped payload field {number}")
    return matches[0][1]


def _name(value: bytes) -> str:
    try:
        result = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise BuilderError("Invalid payload name encoding") from exc
    if not re.fullmatch(r"[A-Za-z0-9_-]+", result):
        raise BuilderError(f"Invalid payload partition/group name: {result!r}")
    return result


def parse_manifest(manifest: bytes) -> dict[str, Any]:
    if not 0 < len(manifest) <= MAX_MANIFEST:
        raise BuilderError("Payload manifest exceeds allowed size")
    fields = _fields(manifest)
    block_size = _one(fields, 3, 0, 4096, False)
    if block_size != 4096:
        raise BuilderError("Only 4096-byte payload blocks are supported")
    if _one(fields, 12, 0, 0, False) != 0:
        raise BuilderError("A full payload is required; delta payload rejected")
    if _one(fields, 16, 0, 0, False):
        raise BuilderError("Partial-update payload rejected")
    partitions = []
    names: set[str] = set()
    for number, wire, value in fields:
        if number != 13:
            continue
        if wire != 2:
            raise BuilderError("Mistyped partition payload field")
        part = _fields(value)
        name = _name(_one(part, 1, 2))
        if name in names:
            raise BuilderError(f"Duplicate payload partition: {name}")
        names.add(name)
        if any(n == 6 for n, _, _ in part):
            raise BuilderError("Full payload must not depend on an old partition")
        info = _fields(_one(part, 7, 2))
        size = _one(info, 1, 0)
        digest = _one(info, 2, 2)
        if size <= 0 or size % block_size or len(digest) != 32:
            raise BuilderError(f"Invalid size or SHA-256 for {name}")
        partitions.append({"partition": name, "size_bytes": size,
                           "sha256": digest.hex()})
    if not partitions:
        raise BuilderError("Payload manifest contains no partitions")

    dynamic = _fields(_one(fields, 15, 2))
    groups = []
    group_names: set[str] = set()
    assigned: set[str] = set()
    for number, wire, value in dynamic:
        if number != 1:
            continue
        if wire != 2:
            raise BuilderError("Mistyped dynamic partition group")
        group = _fields(value)
        name = _name(_one(group, 1, 2))
        maximum = _one(group, 2, 0)
        members = []
        for n, w, member in group:
            if n == 3:
                if w != 2:
                    raise BuilderError("Mistyped group partition name")
                members.append(_name(member))
        if name in group_names or maximum <= 0 or maximum % block_size:
            raise BuilderError("Duplicate group or invalid group maximum size")
        if not members or len(members) != len(set(members)) or assigned.intersection(members):
            raise BuilderError("Empty group or duplicate dynamic partition membership")
        group_names.add(name)
        assigned.update(members)
        groups.append({"name": name, "maximum_size_bytes": maximum,
                       "partitions": members})
    if not groups:
        raise BuilderError("Payload has no dynamic partition groups")
    return {"schema_version": 1, "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            "block_size": block_size, "full_payload": True, "partitions": partitions,
            "dynamic_groups": groups,
            "snapshot_enabled": bool(_one(dynamic, 2, 0, 0, False)),
            "physical_super_geometry_verified": False,
            "scope": "Payload partition identities and update-group limits; no OEM signature or physical geometry verification"}


def inspect_payload_manifest(ota: Path) -> dict[str, Any]:
    with zipfile.ZipFile(ota, "r") as archive:
        entries = [entry for entry in archive.infolist() if entry.filename == "payload.bin"]
        if len(entries) != 1:
            raise BuilderError("OTA requires one root payload.bin")
        entry = entries[0]
        if entry.flag_bits & 1:
            raise BuilderError("Encrypted payload ZIP entry rejected")
        with archive.open(entry) as payload:
            header = payload.read(24)
            if len(header) != 24:
                raise BuilderError("Truncated payload header")
            magic, version, length, signature_size = struct.unpack(">4sQQI", header)
            if magic != b"CrAU" or version != 2:
                raise BuilderError("Requires CrAU major version 2")
            if not 0 < length <= MAX_MANIFEST or 24 + length + signature_size > entry.file_size:
                raise BuilderError("Payload metadata length is outside archive bounds")
            manifest = payload.read(length)
            if len(manifest) != length:
                raise BuilderError("Truncated payload manifest")
    result = parse_manifest(manifest)
    result["payload_metadata_size_bytes"] = 24 + length
    return result
