from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class PartitionInfo:
    name: str
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class OtaInspection:
    path: str
    size_bytes: int
    sha256: str
    is_zip: bool
    has_payload: bool
    payload_entry: str | None
    payload_size_bytes: int | None
    metadata: dict[str, str] = field(default_factory=dict)
    payload_properties: dict[str, str] = field(default_factory=dict)
    device_candidates: list[str] = field(default_factory=list)
    partitions: list[PartitionInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["partitions"] = [item.to_dict() for item in self.partitions]
        return data
