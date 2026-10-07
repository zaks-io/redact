"""Create and verify the binary packages shipped by the release workflow."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

from release_licenses import write_notices

TARGETS = ("x86_64-unknown-linux-gnu", "aarch64-apple-darwin")
BINARIES = ("rprintenv", "rstr")
ROOT = Path(__file__).resolve().parent.parent
MAX_BYTES = 100 * 1024 * 1024


class ReleaseError(Exception):
    """A fixed, safe release diagnostic."""


def command(args):
    result = subprocess.run(args, capture_output=True, check=False, timeout=120)
    if result.returncode:
        raise ReleaseError("required release command failed; check tooling and retry")
    return result.stdout.decode("utf-8")


def version(value):
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?", value):
        raise ReleaseError("invalid release version; use the Cargo package version")
    return value


def source_sha(value):
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ReleaseError("invalid source revision; use a full commit SHA")
    return value


def positive(value):
    if not re.fullmatch(r"[1-9][0-9]*", str(value)):
        raise ReleaseError("invalid workflow run or attempt number")
    return int(value)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def runtime(target, bin_dir):
    if target == TARGETS[0]:
        versions = []
        for name in BINARIES:
            output = command(["readelf", "--version-info", str(bin_dir / name)])
            versions.extend(re.findall(r"\bGLIBC_([0-9]+(?:\.[0-9]+)+)\b", output))
        if not versions:
            raise ReleaseError("cannot determine the Linux runtime requirement")
        return {"glibc_required": max(versions, key=lambda item: tuple(map(int, item.split("."))))}
    minimums = []
    for name in BINARIES:
        output = command(["otool", "-l", str(bin_dir / name)])
        minimums.extend(re.findall(r"\bminos ([0-9]+(?:\.[0-9]+)+)", output))
    if len(minimums) != 2:
        raise ReleaseError("cannot determine the macOS deployment target")
    return {"macos_deployment_target": max(minimums, key=lambda item: tuple(map(int, item.split("."))))}


def package(bin_dir, output_dir, target, run_id, attempt):
    if target not in TARGETS:
        raise ReleaseError("unsupported release target")
    rust = command(["rustc", "-vV"])
    if f"host: {target}\n" not in rust:
        raise ReleaseError("release target does not match the build host")
    if os.environ.get("RUSTFLAGS") or os.environ.get("CARGO_ENCODED_RUSTFLAGS"):
        raise ReleaseError("distributed builds require the repository compiler settings")
    metadata = json.loads(command(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"]))
    cargo = next(item for item in metadata["packages"] if item["name"] == "redact")
    release_version = version(cargo["version"])
    sha = source_sha(command(["git", "rev-parse", "HEAD"]).strip())
    epoch = int(command(["git", "show", "-s", "--format=%ct", sha]).strip())
    for name in BINARIES:
        if not (bin_dir / name).is_file() or (bin_dir / name).is_symlink():
            raise ReleaseError("release binary is missing or is a symbolic link")
        result = subprocess.run([str((bin_dir / name).resolve()), "--version"],
                                env={}, capture_output=True, check=False, timeout=10)
        if result.returncode or result.stderr or result.stdout != f"{name} {release_version}\n".encode():
            raise ReleaseError("binary version does not match Cargo metadata")
    requirements = runtime(target, bin_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    prefix = f"redact-v{release_version}-{target}"
    archive = output_dir / f"{prefix}.tar.gz"
    files = {}
    with tempfile.TemporaryDirectory(prefix="redact-package-") as temporary:
        stage = Path(temporary)
        for name in BINARIES:
            shutil.copyfile(bin_dir / name, stage / name)
        shutil.copyfile(ROOT / "LICENSE", stage / "LICENSE")
        shutil.copyfile(ROOT / "docs/releases.md", stage / "INSTALL.md")
        write_notices(stage, target)
        with archive.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=epoch) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as tar:
                for path in sorted(stage.rglob("*")):
                    if path.is_symlink():
                        raise ReleaseError("license staging contains a symbolic link")
                    if not path.is_file():
                        continue
                    relative = path.relative_to(stage).as_posix()
                    data = path.read_bytes()
                    files[relative] = digest(data)
                    entry = tarfile.TarInfo(f"{prefix}/{relative}")
                    entry.size = len(data)
                    entry.mtime = epoch
                    entry.mode = 0o755 if relative in BINARIES else 0o644
                    tar.addfile(entry, io.BytesIO(data))
    manifest = {"schema_version": 1, "version": release_version, "source_sha": sha,
                "run_id": positive(run_id), "attempt": positive(attempt), "target": target,
                "rust_version": rust.splitlines()[0], "runtime": requirements,
                "archive": archive.name, "sha256": digest(archive.read_bytes()), "files": files}
    write_json(output_dir / f"{target}.json", manifest)
    return manifest


def validate_manifest(manifest):
    expected = {"schema_version", "version", "source_sha", "run_id", "attempt", "target",
                "rust_version", "runtime", "archive", "sha256", "files"}
    if (not isinstance(manifest, dict) or set(manifest) != expected
            or any(type(manifest[key]) is not int for key in ("schema_version", "run_id", "attempt"))
            or any(not isinstance(manifest[key], str) for key in
                   ("version", "source_sha", "target", "rust_version", "archive", "sha256"))
            or not isinstance(manifest["files"], dict) or not isinstance(manifest["runtime"], dict)):
        raise ReleaseError("invalid platform manifest schema")
    for name, checksum in manifest["files"].items():
        if (not isinstance(name, str) or not isinstance(checksum, str)
                or not re.fullmatch(r"[0-9a-f]{64}", checksum)):
            raise ReleaseError("invalid platform manifest file checksum")
    if not re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"]):
        raise ReleaseError("invalid platform manifest archive checksum")
    if not re.fullmatch(r"rustc [0-9]+\.[0-9]+\.[0-9]+(?: \([0-9a-f]{7,40} [0-9]{4}-[0-9]{2}-[0-9]{2}\))?",
                        manifest["rust_version"]):
        raise ReleaseError("invalid platform compiler metadata")
    requirements = manifest["runtime"]
    field = "glibc_required" if manifest["target"] == TARGETS[0] else "macos_deployment_target"
    if (set(requirements) != {field} or not isinstance(requirements[field], str)
            or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", requirements[field])):
        raise ReleaseError("invalid platform runtime requirements")


def verify_package(directory, manifest, release_version, sha, run_id, attempt, extract_to=None):
    validate_manifest(manifest)
    if (manifest["schema_version"] != 1 or manifest["version"] != version(release_version)
            or manifest["source_sha"] != source_sha(sha) or manifest["run_id"] != positive(run_id)
            or not 1 <= manifest["attempt"] <= positive(attempt) or manifest["target"] not in TARGETS):
        raise ReleaseError("package provenance does not match this release run")
    prefix = f"redact-v{release_version}-{manifest['target']}"
    if manifest["archive"] != f"{prefix}.tar.gz":
        raise ReleaseError("unexpected archive name")
    archive = directory / manifest["archive"]
    if archive.is_symlink() or archive.stat().st_size > MAX_BYTES:
        raise ReleaseError("invalid release archive")
    if digest(archive.read_bytes()) != manifest["sha256"]:
        raise ReleaseError("archive checksum mismatch; run CI again")
    seen = set()
    total = 0
    with tarfile.open(archive, "r:gz") as tar:
        for entry in tar:
            parts = PurePosixPath(entry.name).parts
            if (len(parts) < 2 or parts[0] != prefix or ".." in parts or not entry.isfile()
                    or entry.name.startswith("/") or entry.size < 0):
                raise ReleaseError("unsafe archive entry")
            relative = PurePosixPath(*parts[1:]).as_posix()
            if relative in seen or (relative not in (*BINARIES, "LICENSE", "INSTALL.md")
                                   and not relative.startswith("licenses/")):
                raise ReleaseError("unexpected or duplicate archive entry")
            total += entry.size
            if total > MAX_BYTES:
                raise ReleaseError("archive exceeds the release size limit")
            expected_mode = 0o755 if relative in BINARIES else 0o644
            if entry.mode != expected_mode:
                raise ReleaseError("incorrect packaged file permissions")
            stream = tar.extractfile(entry)
            if stream is None:
                raise ReleaseError("unreadable archive entry")
            data = stream.read()
            if digest(data) != manifest["files"].get(relative):
                raise ReleaseError("packaged file checksum mismatch")
            seen.add(relative)
            if extract_to is not None:
                destination = extract_to / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                destination.chmod(expected_mode)
    if (seen != set(manifest["files"]) or not set((*BINARIES, "LICENSE", "INSTALL.md")).issubset(seen)
            or not any(name.startswith("licenses/") for name in seen)):
        raise ReleaseError("incomplete release package")


def prepare(input_dir, output_dir, release_version, sha, run_id, attempt):
    version(release_version)
    source_sha(sha)
    candidates = {target: [] for target in TARGETS}
    for directory in sorted(input_dir.iterdir()):
        if not directory.is_dir() or directory.is_symlink():
            raise ReleaseError("unexpected downloaded artifact")
        manifests = list(directory.glob("*.json"))
        if len(manifests) != 1:
            raise ReleaseError("artifact must contain one platform manifest")
        manifest = json.loads(manifests[0].read_text())
        validate_manifest(manifest)
        target = manifest["target"]
        if target not in TARGETS or directory.name != f"release-{target}-{manifest['attempt']}":
            raise ReleaseError("artifact name does not match its manifest")
        if {item.name for item in directory.iterdir()} != {f"{target}.json", manifest["archive"]}:
            raise ReleaseError("unexpected artifact contents")
        verify_package(directory, manifest, release_version, sha, run_id, attempt)
        candidates[target].append((manifest, directory))
    selected = []
    for entries in candidates.values():
        if not entries:
            raise ReleaseError("a required platform artifact is missing")
        if len({item[0]["attempt"] for item in entries}) != len(entries):
            raise ReleaseError("duplicate platform artifacts")
        selected.append(max(entries, key=lambda item: item[0]["attempt"]))
    output_dir.mkdir(parents=True, exist_ok=False)
    for manifest, directory in selected:
        shutil.copyfile(directory / manifest["archive"], output_dir / manifest["archive"])
    write_json(output_dir / "release-manifest.json", {
        "schema_version": 1, "version": release_version, "source_sha": sha,
        "run_id": positive(run_id), "packages": [item[0] for item in selected]})
    (output_dir / "SHA256SUMS").write_text("".join(
        f"{manifest['sha256']}  {manifest['archive']}\n" for manifest, _ in selected))
    (output_dir / "RELEASE_NOTES.md").write_text(
        f"Both rprintenv and rstr, version {release_version}.\n\n"
        "Download the archive for your platform, verify its SHA-256 checksum, and follow INSTALL.md.\n"
        "Tested on Blacksmith Ubuntu 24.04 x86-64 and macOS 26 Apple Silicon.\n"
        "Older systems are not certified. The macOS binaries are not Developer ID signed or notarized.\n"
        "Public downloads do not require a GitHub account. Source code is MIT licensed.\n"
        "rstr filters recognizable secrets; arbitrary passwords may pass through.\n\n"
        + "".join(f"- {manifest['target']}: {json.dumps(manifest['runtime'], sort_keys=True)}\n"
                  for manifest, _ in selected)
        + f"\nSource commit: {sha}\nCI: https://github.com/zaks-io/redact/actions/runs/{run_id}\n")
