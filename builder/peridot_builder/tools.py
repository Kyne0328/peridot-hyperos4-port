from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .errors import ToolExecutionError, ToolUnavailableError
from .models import PartitionInfo


@dataclass(frozen=True)
class ToolStatus:
    name: str
    path: str | None
    available: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "path": self.path,
            "available": self.available,
        }


def _candidate_names(name: str) -> list[str]:
    lower = name.lower()
    if lower.endswith((".exe", ".py")):
        return [name]
    if os.name == "nt":
        return [name + ".exe", name + ".py", name]
    return [name, name + ".py"]


class Toolchain:
    def __init__(self, project_root: Path):
        self.project_root = project_root.resolve()
        platform = "windows" if os.name == "nt" else "linux"
        self.search_dirs = [
            self.project_root / "builder" / "tools" / "bin" / platform,
            self.project_root / "tools",
            self.project_root
            / "references"
            / "hyperos4-port-windows-python"
            / "bin"
            / platform,
        ]

    def find(self, name: str) -> Path | None:
        for candidate_name in _candidate_names(name):
            resolved = shutil.which(candidate_name)
            if resolved:
                return Path(resolved).resolve()
            for directory in self.search_dirs:
                candidate = directory / candidate_name
                if candidate.is_file():
                    return candidate.resolve()
        return None

    def status(self) -> list[ToolStatus]:
        names = [
            "payload-dumper-go",
            "lpdump",
            "lpunpack",
            "lpmake",
            "simg2img",
            "mkfs.erofs",
            "extract.erofs",
            "avbtool",
        ]
        result: list[ToolStatus] = []
        for name in names:
            path = self.find(name)
            result.append(
                ToolStatus(
                    name=name,
                    path=str(path) if path else None,
                    available=path is not None,
                )
            )
        return result

    def require(self, name: str) -> Path:
        path = self.find(name)
        if path is None:
            raise ToolUnavailableError(
                f"Required tool '{name}' was not found. "
                f"Install it or place it under {self.search_dirs[0]}."
            )
        return path


_PARTITION_LINE = re.compile(r"^([^:\s]+):(\d+)$")


def parse_payload_dumper_list(output: str) -> list[PartitionInfo]:
    partitions: list[PartitionInfo] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        match = _PARTITION_LINE.match(line)
        if not match:
            continue
        name, kib = match.groups()
        partitions.append(PartitionInfo(name=name, size_bytes=int(kib) * 1024))
    return partitions


class PayloadDumperGo:
    def __init__(self, executable: Path):
        self.executable = executable

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str]:
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
                f"payload-dumper-go failed with exit code {process.returncode}: {detail}"
            )
        return process

    def list_partitions(self, rom: Path) -> list[PartitionInfo]:
        process = self._run(["-l", "-m", str(rom)])
        partitions = parse_payload_dumper_list(process.stdout)
        if not partitions:
            raise ToolExecutionError(
                "payload-dumper-go returned no machine-readable partition inventory"
            )
        return partitions

    def extract(
        self,
        rom: Path,
        output_dir: Path,
        partitions: list[str] | None,
    ) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        args = ["-o", str(output_dir)]
        if partitions:
            args.extend(["-p", ",".join(partitions)])
        args.append(str(rom))
        self._run(args)
