"""Prepare a GitHub draft without publishing or replacing existing release data."""
import hashlib
import json
import re
import subprocess

from release_packages import ReleaseError, TARGETS, digest, source_sha, version, verify_package

REPOSITORY = "zaks-io/redact"


def gh(args, data=None):
    result = subprocess.run(["gh", *args], input=data, capture_output=True,
                            check=False, timeout=120)
    if result.returncode:
        raise ReleaseError("GitHub operation failed; check access and retry draft preparation")
    return result.stdout


def api(path, data=None):
    args = ["api", path]
    if data is not None:
        args.extend(["--method", "POST", "--input", "-"])
    return json.loads(gh(args, None if data is None else json.dumps(data).encode()))


def releases_for_tag(tag):
    pages = json.loads(gh(["api", "--paginate", "--slurp", f"repos/{REPOSITORY}/releases?per_page=100"]))
    return [release for page in pages for release in page if release["tag_name"] == tag]


def verify_tag(tag, sha):
    refs = api(f"repos/{REPOSITORY}/git/matching-refs/tags/{tag}")
    matching = [ref for ref in refs if ref["ref"] == f"refs/tags/{tag}"]
    if not matching:
        return
    obj = matching[0]["object"]
    for _ in range(8):
        if obj["type"] == "commit":
            if obj["sha"] != sha:
                raise ReleaseError("release tag points to another commit; choose a new version")
            return
        if obj["type"] != "tag":
            break
        obj = api(f"repos/{REPOSITORY}/git/tags/{source_sha(obj['sha'])}")["object"]
    raise ReleaseError("release tag cannot be resolved to a commit")


def notes_match(actual, expected):
    return (isinstance(actual, str)
            and actual.replace("\r\n", "\n").rstrip() == expected.replace("\r\n", "\n").rstrip())


def local_assets(directory, release_version, sha, run_id):
    manifest_path = directory / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if (manifest["schema_version"] != 1 or manifest["version"] != release_version
            or manifest["source_sha"] != sha or manifest["run_id"] != int(run_id)
            or len(manifest["packages"]) != len(TARGETS)
            or {item["target"] for item in manifest["packages"]} != set(TARGETS)):
        raise ReleaseError("release manifest does not match the requested draft")
    for package in manifest["packages"]:
        verify_package(directory, package, release_version, sha, run_id, package["attempt"])
    checksums = "".join(f"{item['sha256']}  {item['archive']}\n" for item in manifest["packages"])
    if (directory / "SHA256SUMS").read_text() != checksums:
        raise ReleaseError("release checksum file does not match its manifest")
    names = {item["archive"] for item in manifest["packages"]} | {"SHA256SUMS", "release-manifest.json"}
    if {item.name for item in directory.iterdir()} != names | {"RELEASE_NOTES.md"}:
        raise ReleaseError("unexpected release assets")
    if any((directory / name).is_symlink() for name in names | {"RELEASE_NOTES.md"}):
        raise ReleaseError("release assets must be ordinary files")
    return {name: digest((directory / name).read_bytes()) for name in sorted(names)}


def draft(directory, release_version, sha, run_id):
    release_version = version(release_version)
    sha = source_sha(sha)
    tag = f"v{release_version}"
    assets = local_assets(directory, release_version, sha, run_id)
    verify_tag(tag, sha)
    matching = releases_for_tag(tag)
    if len(matching) > 1:
        raise ReleaseError("multiple releases use this version; resolve duplicates in GitHub")
    if matching:
        release = matching[0]
        if not release["draft"]:
            raise ReleaseError("this version is already published; choose a new version")
        if release["target_commitish"] != sha:
            raise ReleaseError("existing draft targets another commit; review the draft in GitHub")
        if (not notes_match(release["body"], (directory / "RELEASE_NOTES.md").read_text())
                or release["name"] != tag or release["prerelease"] != ("-" in release_version)):
            raise ReleaseError("existing draft belongs to another run; review it in GitHub")
    else:
        release = api(f"repos/{REPOSITORY}/releases", {
            "tag_name": tag, "target_commitish": sha, "name": tag, "draft": True,
            "prerelease": "-" in release_version,
            "body": (directory / "RELEASE_NOTES.md").read_text(),
        })
    release_id = int(release["id"])
    pages = json.loads(gh(["api", "--paginate", "--slurp",
                          f"repos/{REPOSITORY}/releases/{release_id}/assets?per_page=100"]))
    existing = [asset for page in pages for asset in page]
    if len({asset["name"] for asset in existing}) != len(existing):
        raise ReleaseError("draft has duplicate assets; review the draft in GitHub")
    for asset in existing:
        if asset["state"] != "uploaded":
            raise ReleaseError("draft has an incomplete upload; review the asset in GitHub before retrying")
        if asset["name"] not in assets or not 0 <= asset["size"] <= 100 * 1024 * 1024:
            raise ReleaseError("draft has unexpected assets; review the draft in GitHub")
        content = gh(["api", f"repos/{REPOSITORY}/releases/assets/{int(asset['id'])}",
                      "-H", "Accept: application/octet-stream"])
        if hashlib.sha256(content).hexdigest() != assets[asset["name"]]:
            raise ReleaseError("draft asset differs from tested bytes; no assets were replaced")
    names_present = {asset["name"] for asset in existing}
    for name in assets.keys() - names_present:
        # Upload by numeric release ID to avoid ambiguous tag-based draft lookups.
        gh(["api", "--method", "POST", "-H", "Content-Type: application/octet-stream",
            f"https://uploads.github.com/repos/{REPOSITORY}/releases/{release_id}/assets?name={name}",
            "--input", str(directory / name)])
    complete = api(f"repos/{REPOSITORY}/releases/{release_id}")
    if (not complete["draft"] or complete["tag_name"] != tag or complete["target_commitish"] != sha
            or not notes_match(complete["body"], (directory / "RELEASE_NOTES.md").read_text())
            or complete["name"] != tag or complete["prerelease"] != ("-" in release_version)
            or len(complete["assets"]) != len(assets)
            or {asset["name"] for asset in complete["assets"]} != set(assets)):
        raise ReleaseError("draft changed during preparation; review it in GitHub")
    for asset in complete["assets"]:
        if asset["state"] != "uploaded":
            raise ReleaseError("draft upload is incomplete; review the asset in GitHub before retrying")
        content = gh(["api", f"repos/{REPOSITORY}/releases/assets/{int(asset['id'])}",
                      "-H", "Accept: application/octet-stream"])
        if digest(content) != assets[asset["name"]]:
            raise ReleaseError("uploaded draft asset failed checksum verification")
    verify_tag(tag, sha)
    url = complete["html_url"]
    if not isinstance(url, str) or not re.fullmatch(
            rf"https://github\.com/{REPOSITORY}/releases/(?:tag|edit)/[A-Za-z0-9._-]+", url):
        raise ReleaseError("draft has an unexpected review URL; open repository releases in GitHub")
    return url
