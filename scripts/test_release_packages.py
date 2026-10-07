"""Synthetic acceptance tests for release archive provenance and safety."""
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

from release_packages import BINARIES, ReleaseError, TARGETS, digest, prepare, verify_package

VERSION = "0.1.0"
SHA = "a" * 40
RUN_ID = 123
CANARY = "SYNTHETIC_SECRET_CANARY_RELEASE_FAILURE"
SCRIPT = Path(__file__).with_name("release.py")


def fixture(directory, target=TARGETS[0], attempt=1, entries=None):
    directory.mkdir(parents=True, exist_ok=True)
    prefix = f"redact-v{VERSION}-{target}"
    if entries is None:
        entries = [(name, f"synthetic {name}\n".encode(),
                    0o755 if name in BINARIES else 0o644, tarfile.REGTYPE)
                   for name in (*BINARIES, "LICENSE", "INSTALL.md", "licenses/synthetic.txt")]
    archive = directory / f"{prefix}.tar.gz"
    files = {}
    with tarfile.open(archive, "w:gz") as tar:
        for name, data, mode, kind in entries:
            member = tarfile.TarInfo(f"{prefix}/{name}")
            member.mode = mode
            member.type = kind
            member.size = len(data) if kind == tarfile.REGTYPE else 0
            member.linkname = "../../outside" if kind != tarfile.REGTYPE else ""
            tar.addfile(member, io.BytesIO(data) if member.size else None)
            files[name] = digest(data)
    manifest = {"schema_version": 1, "version": VERSION, "source_sha": SHA,
                "run_id": RUN_ID, "attempt": attempt, "target": target,
                "rust_version": "rustc 1.99.0 (aaaaaaaaa 2026-09-28)",
                "runtime": {"glibc_required": "2.39"} if target == TARGETS[0]
                else {"macos_deployment_target": "26.0"},
                "archive": archive.name, "sha256": digest(archive.read_bytes()), "files": files}
    (directory / f"{target}.json").write_text(json.dumps(manifest))
    return manifest


def artifact(root, target, attempt):
    directory = root / f"release-{target}-{attempt}"
    return directory, fixture(directory, target, attempt)


def prepared(root):
    inputs = root / "inputs"
    for target in TARGETS:
        artifact(inputs, target, 1)
    output = root / "assets"
    prepare(inputs, output, VERSION, SHA, RUN_ID, 1)
    return output


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / "package"
        self.manifest = fixture(self.directory)

    def verify(self, manifest=None, **kwargs):
        verify_package(self.directory, manifest or self.manifest,
                       kwargs.get("version", VERSION), kwargs.get("sha", SHA),
                       kwargs.get("run_id", RUN_ID), kwargs.get("attempt", 1),
                       kwargs.get("extract_to"))

    def test_documented_download_checksum_gates_extraction(self):
        commands = self.root / "commands"
        commands.mkdir()
        archive = f"redact-v{VERSION}-{TARGETS[0]}.tar.gz"
        gh = commands / "gh"
        tar = commands / "tar"
        tar.write_text("#!/bin/sh\ntouch extraction-was-run\nexit 73\n")
        tar.chmod(0o755)
        docs = SCRIPT.parent.parent / "docs/releases.md"
        block = docs.read_text().split("```sh", 1)[1].split("```", 1)[0]
        for valid in (False, True):
            with self.subTest(valid=valid):
                checksum = digest(b"synthetic archive") if valid else "0" * 64
                gh.write_text("#!/bin/sh\n"
                              f"printf 'synthetic archive' > '{archive}'\n"
                              f"printf '%s  %s\\n' '{checksum}' '{archive}' > SHA256SUMS\n")
                gh.chmod(0o755)
                result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", block],
                                        cwd=self.root, env={"PATH": f"{commands}:/usr/bin:/bin"},
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 73 if valid else 1)
                self.assertEqual((self.root / "extraction-was-run").exists(), valid)

    def test_extracts_verified_files_with_executable_permissions(self):
        destination = self.root / "extracted"
        self.verify(extract_to=destination)
        self.assertEqual(set(self.manifest["files"]),
                         {path.relative_to(destination).as_posix()
                          for path in destination.rglob("*") if path.is_file()})
        for name, checksum in self.manifest["files"].items():
            path = destination / name
            self.assertEqual(digest(path.read_bytes()), checksum)
            self.assertEqual(path.stat().st_mode & 0o777, 0o755 if name in BINARIES else 0o644)

    def test_rejects_wrong_provenance_and_future_attempts(self):
        for field, value in (("version", "1.2.3"), ("source_sha", "b" * 40),
                             ("run_id", RUN_ID + 1), ("attempt", 2),
                             ("target", "unsupported")):
            with self.subTest(field=field):
                manifest = copy.deepcopy(self.manifest)
                manifest[field] = value
                with self.assertRaises(ReleaseError):
                    self.verify(manifest)

    def test_rejects_malformed_manifest_types_and_truncated_hashes(self):
        for field, value in (("files", [CANARY]), ("runtime", {}), ("attempt", True),
                             ("run_id", 1.5), ("schema_version", False),
                             ("sha256", "a" * 16), ("files", {"rstr": "a" * 16})):
            with self.subTest(field=field, value_type=type(value).__name__):
                manifest = copy.deepcopy(self.manifest)
                manifest[field] = value
                with self.assertRaises(ReleaseError) as caught:
                    self.verify(manifest)
                self.assertNotIn(CANARY, str(caught.exception))

    def test_rejects_archive_and_file_checksum_mismatches(self):
        for field in ("sha256", "files"):
            with self.subTest(field=field):
                manifest = copy.deepcopy(self.manifest)
                if field == "files":
                    manifest[field]["rstr"] = "0" * 64
                else:
                    manifest[field] = "0" * 64
                with self.assertRaises(ReleaseError):
                    self.verify(manifest)

    def test_rejects_unsafe_or_incomplete_archives(self):
        base = [(name, b"synthetic\n", 0o755 if name in BINARIES else 0o644, tarfile.REGTYPE)
                for name in (*BINARIES, "LICENSE", "INSTALL.md", "licenses/synthetic.txt")]
        cases = {"traversal": base + [("../outside", b"synthetic", 0o644, tarfile.REGTYPE)],
                 "symlink": base + [("licenses/link", b"", 0o644, tarfile.SYMTYPE)],
                 "hardlink": base + [("licenses/link", b"", 0o644, tarfile.LNKTYPE)],
                 "duplicate": base + [base[0]],
                 "permissions": [("rstr", b"synthetic", 0o644, tarfile.REGTYPE)] + base[2:],
                 "unexpected": base + [("other", b"synthetic", 0o644, tarfile.REGTYPE)],
                 "missing_binary": base[1:], "missing_notices": base[:-1]}
        for label, entries in cases.items():
            with self.subTest(label=label):
                manifest = fixture(self.directory, entries=entries)
                with self.assertRaises(ReleaseError):
                    self.verify(manifest)
        self.assertFalse((self.root / "outside").exists())

    def test_rejects_symlink_archive(self):
        archive = self.directory / self.manifest["archive"]
        moved = self.root / "archive.tar.gz"
        archive.rename(moved)
        archive.symlink_to(moved)
        with self.assertRaises(ReleaseError):
            self.verify()

    def test_prepares_latest_platforms_from_failed_only_rerun(self):
        inputs = self.root / "inputs"
        artifact(inputs, TARGETS[0], 1)
        _, linux = artifact(inputs, TARGETS[0], 3)
        _, macos = artifact(inputs, TARGETS[1], 1)
        output = self.root / "assets"
        prepare(inputs, output, VERSION, SHA, RUN_ID, 3)
        manifest = json.loads((output / "release-manifest.json").read_text())
        self.assertEqual(manifest["packages"], [linux, macos])
        sums = (output / "SHA256SUMS").read_text()
        self.assertEqual(sums, "".join(f"{item['sha256']}  {item['archive']}\n"
                                      for item in (linux, macos)))
        for item in (linux, macos):
            self.assertEqual(digest((output / item["archive"]).read_bytes()), item["sha256"])

    def test_missing_platform_and_future_artifact_prevent_preparation(self):
        for label in ("missing", "future", "wrong_source", "wrong_run"):
            with self.subTest(label=label):
                inputs = self.root / label
                artifact(inputs, TARGETS[0], 1)
                if label != "missing":
                    directory, manifest = artifact(inputs, TARGETS[1], 2 if label == "future" else 1)
                    if label.startswith("wrong"):
                        manifest["source_sha" if label == "wrong_source" else "run_id"] = (
                            "b" * 40 if label == "wrong_source" else RUN_ID + 1)
                        (directory / f"{TARGETS[1]}.json").write_text(json.dumps(manifest))
                output = self.root / f"{label}-output"
                with self.assertRaises(ReleaseError):
                    prepare(inputs, output, VERSION, SHA, RUN_ID, 1)
                self.assertFalse(output.exists())

    def test_cli_failures_do_not_echo_input_or_tracebacks(self):
        bad_json = self.root / "bad-json"
        bad_json.mkdir()
        (bad_json / f"{TARGETS[0]}.json").write_text(CANARY)
        invalid_tar = self.root / "bad-tar"
        manifest = fixture(invalid_tar)
        archive = invalid_tar / manifest["archive"]
        archive.write_bytes(CANARY.encode())
        manifest["sha256"] = digest(archive.read_bytes())
        (invalid_tar / f"{TARGETS[0]}.json").write_text(json.dumps(manifest))
        malformed_manifest = self.root / "malformed-manifest"
        malformed = fixture(malformed_manifest)
        malformed["files"] = [CANARY]
        (malformed_manifest / f"{TARGETS[0]}.json").write_text(json.dumps(malformed))
        common = ["--target", TARGETS[0], "--output-dir", str(self.root / "out"),
                  "--run-id", str(RUN_ID), "--attempt", "1", "--version", VERSION,
                  "--source-sha", SHA]
        cases = [[CANARY], ["extract", "--input-dir", str(bad_json), *common],
                 ["extract", "--input-dir", str(invalid_tar), *common],
                 ["extract", "--input-dir", str(malformed_manifest), *common]]
        for index, arguments in enumerate(cases):
            with self.subTest(index=index):
                arguments = list(arguments)
                if "--output-dir" in arguments:
                    arguments[arguments.index("--output-dir") + 1] = str(self.root / f"out-{index}")
                result = subprocess.run([sys.executable, str(SCRIPT), *arguments],
                                        env={}, capture_output=True, check=False, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"release:", result.stderr)
                self.assertNotIn(CANARY.encode(), result.stdout + result.stderr)
                self.assertNotIn(b"Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
