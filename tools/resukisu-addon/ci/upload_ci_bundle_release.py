#!/usr/bin/env python3
"""Owner-authorized local upload of the POCO F6 CI input archive to a GitHub Release.

GitHub auth comes from local Git Credential Manager, only in volatile memory.
Does not publish a flashable kernel or commit a >100 MiB binary to Git history.
"""
from __future__ import annotations
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit, urlencode
from urllib.request import Request, urlopen

REPO = "Kyne0328/peridot-bakasu-kernel"
TAG = "ci-stock-inputs-20261014"
LOCAL = Path("D:/peridot-bakasu-stock-inputs.tar.gz")
EXPECTED_SHA = "fa9ca6f9f8332e284605347422e235684396e74a14b7001b568d73e174bd26fe"
EXPECTED_BYTES = 688792632
API = f"https://api.github.com/repos/{REPO}"
USER_AGENT = "KyneOS-owner-poco-f6-ci-asset-upload"
HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": USER_AGENT,
    "X-GitHub-Api-Version": "2022-11-28",
}


def authorize() -> dict[str, str]:
    p = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=github.com\n\n",
        text=True,
        capture_output=True,
        timeout=20,
        check=True,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    credentials = dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)
    if not credentials.get("password"):
        raise ValueError("No authenticated GitHub credentials in local Git Credential Manager")
    return {**HEADERS, "Authorization": "Bearer " + credentials["password"]}


def github(url: str, headers: dict[str, str], method: str = "GET", payload=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        url, data=data, method=method,
        headers={**headers, **({"Content-Type": "application/json"} if data is not None else {})},
    )
    with urlopen(request, timeout=65) as response:
        raw = response.read()
        return json.loads(raw) if raw else {}


def release_for_tag(headers):
    try:
        return github(f"{API}/releases/tags/{TAG}", headers)
    except HTTPError as e:
        if e.code == 404:
            return None
        raise


def create_draft(headers):
    existing = release_for_tag(headers)
    if existing:
        print("EXISTING_RELEASE", existing["id"], "DRAFT", existing.get("draft"), flush=True)
        return existing
    return github(
        f"{API}/releases", headers, "POST",
        {
            "tag_name": TAG,
            "target_commitish": "main",
            "name": "CI inputs for POCO F6 BakaSU (NOT FLASHABLE)",
            "body": (
                "Build input bundle only; NOT A FLASHABLE KERNEL OR ROM.\n\n"
                "Contains the owner's preserved Android GKI 6.1.138 source worktree,"
                " exact input kernel config, public module trust certificate,"
                " and selected stock image/vendor module compatibility references.\n"
                "Proprietary Xiaomi stock module files may be present;"
                " uploaded at the explicit request of the project owner.\n\n"
                f"SHA-256: {EXPECTED_SHA}\n"
                f"Expected bytes: {EXPECTED_BYTES}\n"
                "Do not flash or install this archive on a device."
                " Reproducible build inputs only; no device testing implied.\n"
            ),
            "draft": True,
            "prerelease": True,
            "make_latest": "false",
        },
    )


def upload(headers, release):
    assets = github(f"{API}/releases/{release['id']}/assets?per_page=100", headers)
    for a in assets:
        if a["name"] == LOCAL.name:
            if a["size"] != EXPECTED_BYTES:
                raise RuntimeError("Existing same-named asset has different length; refusing overwrite")
            if a.get("digest") and a["digest"] != "sha256:" + EXPECTED_SHA:
                raise RuntimeError("Existing asset digest differs; refusing overwrite")
            print("EXISTING_ASSET", a["id"], a.get("state"), a.get("digest"), flush=True)
            return a
    upload_url = release["upload_url"].split("{", 1)[0]
    uri = urlsplit(upload_url)
    assert uri.scheme == "https" and uri.hostname == "uploads.github.com"
    req_path = uri.path + "?" + urlencode({"name": LOCAL.name})
    conn = http.client.HTTPSConnection(uri.hostname, timeout=300)
    conn.putrequest("POST", req_path)
    for key, value in headers.items():
        conn.putheader(key, value)
    conn.putheader("Content-Type", "application/gzip")
    conn.putheader("Content-Length", str(EXPECTED_BYTES))
    conn.endheaders()
    total = 0
    last = time.monotonic()
    with LOCAL.open("rb") as src:
        while True:
            chunk = src.read(4 * 1024 * 1024)
            if not chunk:
                break
            conn.send(chunk)
            total += len(chunk)
            now = time.monotonic()
            if now - last > 10:
                print("UPLOAD_PROGRESS", total, "/", EXPECTED_BYTES, flush=True)
                last = now
    assert total == EXPECTED_BYTES
    result = conn.getresponse()
    raw = result.read()
    print("UPLOAD_HTTP", result.status, flush=True)
    if result.status != 201:
        raise RuntimeError(f"Asset upload failed with HTTP {result.status}: {raw[:1300].decode('utf-8', 'replace')}")
    return json.loads(raw)


def publish(headers, release_id):
    return github(f"{API}/releases/{release_id}", headers, "PATCH",
                  {"draft": False, "prerelease": True, "make_latest": "false"})


def configure_variable(headers, name: str, value: str):
    endpoint = f"{API}/actions/variables"
    try:
        github(f"{endpoint}/{name}", headers)
    except HTTPError as e:
        if e.code != 404:
            raise
        github(endpoint, headers, "POST", {"name": name, "value": value})
        return "created"
    github(f"{endpoint}/{name}", headers, "PATCH", {"name": name, "value": value})
    return "updated"


def main():
    if not LOCAL.is_file() or LOCAL.stat().st_size != EXPECTED_BYTES:
        raise RuntimeError("Owner's pinned bundle missing or wrong size")
    with LOCAL.open("rb") as f:
        actual = hashlib.file_digest(f, "sha256").hexdigest()
    if actual != EXPECTED_SHA:
        raise RuntimeError("Owner's pinned bundle digest changed")
    print("INPUT_VERIFIED_BYTES", EXPECTED_BYTES, "SHA256", actual, flush=True)

    headers = authorize()
    repo = github(API, headers)
    if repo.get("full_name") != REPO or not repo.get("permissions", {}).get("push"):
        raise RuntimeError("Credentials cannot publish to expected user-owned repository")
    print("REPO_VERIFIED", REPO, "VISIBILITY", repo.get("visibility"), flush=True)
    release = create_draft(headers)
    print("DRAFT_ID", release["id"], flush=True)
    asset = upload(headers, release)
    if asset.get("size") != EXPECTED_BYTES:
        raise RuntimeError("GitHub asset reported unexpected byte count")
    if asset.get("digest") and asset.get("digest") != "sha256:" + EXPECTED_SHA:
        raise RuntimeError("GitHub asset digest verification failed")
    print("UPLOAD_ASSET_VERIFIED", asset.get("id"), asset.get("size"), asset.get("digest"), flush=True)
    published = publish(headers, release["id"])
    # A draft uses a temporary untagged-* URL. Fetch the canonical tag URL
    # after publication, otherwise Actions gets a stale 404 download link.
    refreshed = github(f"{API}/releases/{release['id']}/assets", headers)
    verified = next((row for row in refreshed if row['id'] == asset['id']), None)
    if not verified or verified.get('digest') != 'sha256:' + EXPECTED_SHA:
        raise RuntimeError('Post-publish asset identity/digest drift')
    url = verified.get('browser_download_url')
    if f'/releases/download/{TAG}/' not in (url or ''):
        raise RuntimeError('GitHub did not return canonical published release asset URL')
    print("RELEASE_PUBLISHED", published.get("html_url"), flush=True)
    print("ASSET_URL", url, flush=True)
    print("SHA256", EXPECTED_SHA, flush=True)
    for name, value in (
        ("BAKASU_INPUT_BUNDLE_URL", url),
        ("BAKASU_INPUT_BUNDLE_SHA256", EXPECTED_SHA),
    ):
        try:
            status = configure_variable(headers, name, value)
            print("ACTIONS_VARIABLE", name, status, flush=True)
        except HTTPError as e:
            print("ACTIONS_VARIABLE_FAILED", name, e.code, flush=True)
    print("COMPLETE", flush=True)


if __name__ == "__main__":
    main()
