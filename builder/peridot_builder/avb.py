from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from .errors import ToolExecutionError
from .hashing import sha256_file


_DESCRIPTOR_TYPES = {
    "Chain Partition descriptor:": "chain_partition",
    "Hash descriptor:": "hash",
    "Hashtree descriptor:": "hashtree",
}


def _key(name: str) -> str:
    value = name.strip().lower()
    value = value.replace("(sha1)", "sha1")
    value = value.replace("dm-verity", "dm_verity")
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return value.strip("_")


def _value(value: str) -> str | int:
    value = value.strip()
    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return value[1:-1]
    match = re.fullmatch(r"(\d+) bytes", value)
    if match:
        return int(match.group(1))
    if re.fullmatch(r"\d+", value):
        return int(value)
    return value


def parse_avb_info(output: str) -> dict[str, Any]:
    header: dict[str, Any] = {}
    descriptors: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_descriptors = False

    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped == "Descriptors:":
            in_descriptors = True
            current = None
            continue

        descriptor_type = _DESCRIPTOR_TYPES.get(stripped)
        if descriptor_type:
            current = {"type": descriptor_type}
            descriptors.append(current)
            continue

        if in_descriptors and stripped.startswith("Prop: "):
            payload = stripped[len("Prop: ") :]
            if " -> " not in payload:
                continue
            name, value = payload.split(" -> ", 1)
            descriptors.append(
                {
                    "type": "property",
                    "name": name.strip(),
                    "value": _value(value),
                }
            )
            current = None
            continue

        if ":" not in stripped:
            continue
        name, value = stripped.split(":", 1)
        target = current if in_descriptors and current is not None else header
        target[_key(name)] = _value(value)

    return {
        "header": header,
        "descriptors": descriptors,
    }


class AvbTool:
    def __init__(self, executable: Path):
        self.executable = executable.resolve()

    def _command(self, *args: str) -> list[str]:
        if self.executable.suffix.lower() == ".py":
            return [sys.executable, str(self.executable), *args]
        return [str(self.executable), *args]

    def run(
        self,
        *args: str,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> str:
        process = subprocess.run(
            self._command(*args),
            cwd=str(cwd.resolve()) if cwd else None,
            env=env,
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        if process.returncode != 0:
            detail = process.stderr.strip() or process.stdout.strip()
            operation = args[0] if args else "command"
            raise ToolExecutionError(
                f"avbtool {operation} failed with exit code "
                f"{process.returncode}: {detail}"
            )
        return process.stdout

    def info_image(self, image: Path) -> dict[str, Any]:
        image = image.resolve()
        output = self.run("info_image", "--image", str(image))

        parsed = parse_avb_info(output)
        parsed.update(
            {
                "path": str(image),
                "size_bytes": image.stat().st_size,
                "sha256": sha256_file(image),
                "raw_info": output.rstrip(),
            }
        )
        return parsed
