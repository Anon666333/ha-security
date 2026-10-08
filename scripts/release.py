"""Validate release metadata and publish tested main commits without retagging."""
import argparse
import json
import os
from pathlib import Path
import re
import struct
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")


def version_tuple(version):
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        raise ValueError("Release versions must be stable MAJOR.MINOR.PATCH numbers")
    return tuple(map(int, version.split(".")))


def validate(root=ROOT):
    manifest = json.loads((root / "custom_components/ha_security/manifest.json").read_text(encoding="utf-8"))
    version = manifest["version"]
    version_tuple(version)
    if manifest["domain"] != "ha_security":
        raise ValueError("Unexpected integration domain")
    hacs = json.loads((root / "hacs.json").read_text(encoding="utf-8"))
    if "version" in hacs or "icon" in hacs:
        raise ValueError("HACS uses GitHub releases for versions and local brand assets for icons")
    for filename in ("README.md", "dashboards/security.yaml"):
        text = (root / filename).read_text(encoding="utf-8")
        if f"/ha_security/ha-security-card.js?v={version}" not in text:
            raise ValueError(f"Dashboard resource version is missing from {filename}")
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(rf"^## \[{re.escape(version)}\]\s*\n(.*?)(?=^## |\Z)", changelog, re.M | re.S)
    if not match or not match[1].strip():
        raise ValueError("Add release notes for the manifest version to CHANGELOG.md")
    brand = root / "custom_components/ha_security/brand"
    for name, size in (("icon.png", 256), ("dark_icon.png", 256), ("icon@2x.png", 512), ("dark_icon@2x.png", 512)):
        data = (brand / name).read_bytes()
        if data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR" or struct.unpack(">II", data[16:24]) != (size, size) or data[25] != 6:
            raise ValueError(f"{name} must be a {size}px RGBA PNG")
    return version, match[1].strip()


def github_api(repository, token, path, payload=None):
    request = Request(f"https://api.github.com/repos/{repository}/{path}",
                      data=json.dumps(payload).encode() if payload is not None else None,
                      headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                               "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"},
                      method="POST" if payload is not None else "GET")
    try:
        with urlopen(request, timeout=30) as response:
            return json.load(response)
    except HTTPError as error:
        if error.code == 404 and payload is None:
            return None
        raise RuntimeError(f"GitHub API request failed with HTTP {error.code}") from None


def publish(version, notes, repository, sha, api):
    """Idempotent after success; retry a partial tag creation without moving tags."""
    tag = f"v{version}"
    current = version_tuple(version)
    existing = api(f"releases/tags/{quote(tag)}")
    if existing:
        if existing.get("draft") or existing.get("prerelease"):
            raise ValueError("An existing draft or prerelease needs maintainer review")
        return "Release already published; unchanged versions do not create updates"
    latest = api("releases/latest")
    if latest:
        previous = latest["tag_name"].removeprefix("v")
        if current <= version_tuple(previous):
            raise ValueError("New release version must exceed the latest published stable release")
    reference = api(f"git/ref/tags/{quote(tag)}")
    if reference:
        obj = reference["object"]
        for _ in range(5):
            if obj["type"] != "tag":
                break
            obj = api(f"git/tags/{obj['sha']}")["object"]
        if obj["type"] != "commit" or obj["sha"] != sha:
            raise ValueError("Existing tag points elsewhere; tags are never moved")
    else:
        api("git/refs", {"ref": f"refs/tags/{tag}", "sha": sha})
    api("releases", {"tag_name": tag, "target_commitish": sha, "name": f"HA Security {tag}",
                     "body": notes, "draft": False, "prerelease": False, "make_latest": "true"})
    return f"Published https://github.com/{repository}/releases/tag/{tag}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    version, notes = validate()
    if not args.publish:
        print(f"Release metadata valid: v{version}")
        return
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ValueError("Publishing is restricted to the tested main-branch workflow")
    repository, sha, token = (os.environ.get(key, "") for key in ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_TOKEN"))
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(r"[0-9a-f]{40}", sha) or not token:
        raise ValueError("Missing or invalid GitHub workflow context")
    print(publish(version, notes, repository, sha, lambda path, payload=None: github_api(repository, token, path, payload)))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError) as error:
        raise SystemExit(str(error)) from None
