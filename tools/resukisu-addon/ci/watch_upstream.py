#!/usr/bin/env python3
"""Detect upstream BakaSU main revisions and previously successful peridot CI artifacts."""
from __future__ import annotations
import base64
import json
import os
import re
from pathlib import Path
from urllib.request import Request, urlopen

UPSTREAM = "Baka-SU/BakaSU"
PREFIX = "bakasu-peridot-"
NAME = re.compile(r"^bakasu-peridot-([0-9a-f]{40})-([0-9a-f]{64})$")
HEX_SHA = re.compile(r"^[0-9a-f]{40}$")


def choose(commit: str, artifacts: list[dict], *, force: bool = False) -> dict:
    if not HEX_SHA.fullmatch(commit):
        raise ValueError("BakaSU upstream SHA must be 40 lowercase hexadecimal digits")
    previous = []
    for entry in artifacts:
        match = NAME.fullmatch(entry.get("name", ""))
        if not match or entry.get("expired") or entry.get("size_in_bytes", 0) <= 0:
            continue
        previous.append((entry.get("created_at", ""), match.group(1), match.group(2)))
    previous.sort(reverse=True)
    already_built = any(rev == commit for _, rev, _ in previous)
    last_image = next((digest for _, rev, digest in previous if rev != commit), "")
    return {
        "upstream_sha": commit,
        "changed": force or not already_built,
        "already_built": already_built,
        "force": force,
        "previous_image_sha": last_image,
        "repository": UPSTREAM,
    }


def api_json(url: str, token: str) -> dict:
    request = Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "peridot-bakasu-autobuilder",
        "X-GitHub-Api-Version": "2022-11-28",
        **({"Authorization": "Bearer " + token} if token else {}),
    })
    with urlopen(request, timeout=25) as response:
        return json.load(response)


def susfs_inline_gate(source: str) -> tuple[bool, str]:
    """Conservatively reject upstream Makefile fatal stops in SUSFS integration.

    This is a preflight gate, NOT proof that the remaining hooks are compatible.
    Never remove/patch the upstream guard merely to compile a kernel.
    """
    if re.search(r"(?m)^[ \t]*\$\(\s*error\b", source):
        return (False, "upstream_susfs_inline_build_suspended")
    if not source.strip() or "susfs" not in source.lower():
        return (False, "unknown_susfs_compatibility_contract")
    return (True, "no_explicit_susfs_build_stop_detected")


def read_susfs_contract(sha: str) -> str:
    if not HEX_SHA.fullmatch(sha):
        raise ValueError("Invalid commit hash for BakaSU SUSFS compatibility preflight")
    url = f"https://api.github.com/repos/{UPSTREAM}/contents/kernel/tools/susfs_compat.mk?ref={sha}"
    entry = api_json(url, "")
    if entry.get("encoding") != "base64" or not isinstance(entry.get("content"), str):
        raise ValueError("Unexpected upstream SUSFS compatibility contract format")
    return base64.b64decode(entry["content"], validate=False).decode("utf-8", "strict")


def inspect_remote(repo: str, token: str, force: bool) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("Invalid GitHub repository name")
    sha = api_json(f"https://api.github.com/repos/{UPSTREAM}/git/ref/heads/main", "")["object"]["sha"]
    artifacts = []
    for page in range(1, 6):
        batch = api_json(f"https://api.github.com/repos/{repo}/actions/artifacts?per_page=100&page={page}", token).get("artifacts", [])
        artifacts.extend(batch)
        if len(batch) < 100:
            break
    result = choose(sha, artifacts, force=force)
    # Always check the exact selected upstream SHA, not mutable main.
    supported, reason = susfs_inline_gate(read_susfs_contract(sha))
    result.update({
        "susfs_inline_supported": supported,
        "susfs_status": reason,
        "build_required": bool(result["changed"] and supported),
    })
    return result


def main() -> None:
    repo = os.environ["GITHUB_REPOSITORY"]
    token = os.environ.get("GITHUB_TOKEN", "")
    force = os.environ.get("BAKASU_FORCE_BUILD", "false").lower() == "true"
    result = inspect_remote(repo, token, force)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a", encoding="utf-8") as handle:
            for key in ("upstream_sha", "previous_image_sha", "changed", "already_built", "build_required", "susfs_inline_supported", "susfs_status"):
                value = result[key]
                handle.write(f"{key}={str(value).lower() if isinstance(value, bool) else value}\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as handle:
            handle.write(
                "### POCO F6 BakaSU upstream check\n\n"
                f"Upstream: https://github.com/{UPSTREAM}\n\n"
                f"Commit: {result['upstream_sha']}\n\n"
                f"Upstream changed/unbuilt: **{result['changed']}**\n\n"
                f"SUSFS inline integration: **{result['susfs_status']}**\n\n"
                f"Start kernel compilation: **{result['build_required']}**\n\n"
                "Gate checks the exact BakaSU commit for an upstream SUSFS build stop. "
                "A passing gate is NOT proof that the kernel will compile or boot.\n\n"
            )
    if not result["susfs_inline_supported"]:
        print(
            "::warning::BakaSU upstream currently suspends SUSFS inline builds. "
            "Preserving the full SUSFS/WildKernels configuration; "
            "kernel compilation skipped until upstream restores compatibility. "
            "See https://github.com/Baka-SU/BakaSU/commit/48fa4bb7ec8bddb8ea932a8c9be0877f89a1fa73"
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
