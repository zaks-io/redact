#!/usr/bin/env python3
"""Verify complete notices and safe failures with synthetic local sources."""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import release_licenses

MIT = b"Synthetic MIT License\nCopyright synthetic author\nPermission is hereby granted\n"
UNICODE = b"UNICODE LICENSE V3\nCopyright synthetic Unicode contributor\n"
CANARY = "SYNTHETIC_LICENSE_DIAGNOSTIC_SECRET"


class LicenseNoticesTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.output = self.root / "staging"
        self.doc = self.root / "sysroot/share/doc/rust"
        self.doc.mkdir(parents=True)
        (self.doc / "COPYRIGHT-library.html").write_text(
            '<html><body>Synthetic Rust copyright and full license text'
            '<a href="licenses/MIT.txt#notice">License</a>'
            '<a href="https://example.test/notice">Upstream</a>'
            '<a href="#top">Top</a></body></html>'
        )
        (self.doc / "licenses").mkdir()
        (self.doc / "licenses/MIT.txt").write_bytes(MIT)
        self.project = self.package("redact", "MIT", source=None)
        self.dependency = self.package("synthetic-runtime", "MIT OR Apache-2.0")
        self.build = self.package("synthetic-macro", "(MIT OR Apache-2.0) AND Unicode-3.0")
        self.dev = self.package("synthetic-dev-only", "unsupported-dev-license")
        (pathlib.Path(self.build["manifest_path"]).parent / "LICENSE-UNICODE").write_bytes(UNICODE)
        self.metadata = {
            "packages": [self.project, self.dependency, self.build, self.dev],
            "resolve": {"root": "redact", "nodes": [
                {"id": "redact", "deps": [self.edge("synthetic-runtime", None),
                                            self.edge("synthetic-dev-only", "dev")]},
                {"id": "synthetic-runtime", "deps": [self.edge("synthetic-macro", "build")]},
                {"id": "synthetic-macro", "deps": []},
                {"id": "synthetic-dev-only", "deps": []},
            ]},
        }

    def package(self, name, expression, source="registry+synthetic"):
        directory = self.root / name
        directory.mkdir()
        (directory / "LICENSE-MIT").write_bytes(MIT)
        return {"id": name, "name": name, "version": "1.0.0", "license": expression,
                "source": source, "manifest_path": str(directory / "Cargo.toml"),
                "license_file": None}

    @staticmethod
    def edge(name, kind):
        return {"pkg": name, "dep_kinds": [{"kind": kind}]}

    def write(self):
        with patch.object(release_licenses, "_command", side_effect=[
            json.dumps(self.metadata), str(self.root / "sysroot"),
        ]) as command:
            release_licenses.write_notices(self.output, "synthetic-target")
        return command

    def test_copies_runtime_build_and_rust_notices(self):
        directory = pathlib.Path(self.dependency["manifest_path"]).parent
        (directory / "src/unicode_tables").mkdir(parents=True)
        (directory / "src/unicode_tables/LICENSE-UNICODE").write_bytes(UNICODE)
        (directory / "NOTICE").write_text("Synthetic attribution")
        command = self.write()
        notices = self.output / "licenses"
        entries = json.loads((notices / "dependencies.json").read_text())
        self.assertEqual([entry["name"] for entry in entries],
                         ["redact", "synthetic-macro", "synthetic-runtime"])
        self.assertEqual(entries[1]["selected_license"], "MIT AND Unicode-3.0")
        self.assertEqual((notices / "crates/synthetic-runtime-1.0.0/LICENSE-MIT").read_bytes(), MIT)
        self.assertEqual((notices / "crates/synthetic-runtime-1.0.0/NOTICE").read_text(), "Synthetic attribution")
        self.assertEqual((notices / "crates/synthetic-runtime-1.0.0/src/unicode_tables/LICENSE-UNICODE").read_bytes(), UNICODE)
        self.assertEqual((notices / "rust/licenses/MIT.txt").read_bytes(), MIT)
        self.assertEqual((notices / "rust/COPYRIGHT-library.html").read_bytes(),
                         (self.doc / "COPYRIGHT-library.html").read_bytes())
        self.assertIn("--locked", command.call_args_list[0].args[0])
        self.assertIn("--offline", command.call_args_list[0].args[0])
        self.assertEqual(command.call_args_list[0].args[0][-1], "synthetic-target")

    def test_workspace_does_not_copy_fixture_licenses(self):
        directory = pathlib.Path(self.project["manifest_path"]).parent
        (directory / "fixtures").mkdir()
        (directory / "fixtures/LICENSE").write_text(CANARY)
        self.write()
        self.assertFalse((self.output / "licenses/crates/redact-1.0.0/fixtures").exists())

    def test_missing_mit_license_fails_before_writing(self):
        (pathlib.Path(self.dependency["manifest_path"]).parent / "LICENSE-MIT").unlink()
        with self.assertRaisesRegex(RuntimeError, "MIT license text is missing"):
            self.write()
        self.assertFalse(self.output.exists())

    def test_nested_test_license_cannot_replace_dependency_license(self):
        directory = pathlib.Path(self.dependency["manifest_path"]).parent
        (directory / "LICENSE-MIT").unlink()
        (directory / "tests").mkdir()
        (directory / "tests/LICENSE").write_bytes(MIT)
        with self.assertRaisesRegex(RuntimeError, "MIT license text is missing"):
            self.write()
        self.assertFalse(self.output.exists())

    def test_empty_license_fails(self):
        (pathlib.Path(self.dependency["manifest_path"]).parent / "LICENSE-MIT").write_bytes(b"")
        with self.assertRaisesRegex(RuntimeError, "license source is empty"):
            self.write()

    def test_missing_unicode_license_fails(self):
        (pathlib.Path(self.build["manifest_path"]).parent / "LICENSE-UNICODE").unlink()
        with self.assertRaisesRegex(RuntimeError, "Unicode license text is missing"):
            self.write()

    def test_unknown_license_expression_fails_safely(self):
        self.dependency["license"] = CANARY
        with self.assertRaises(RuntimeError) as error:
            self.write()
        self.assertNotIn(CANARY, str(error.exception))

    def test_missing_explicit_license_fails(self):
        self.dependency["license_file"] = "custom-license.txt"
        with self.assertRaisesRegex(RuntimeError, "license source is missing"):
            self.write()

    def test_license_symlink_does_not_copy_data_outside_dependency(self):
        directory = pathlib.Path(self.dependency["manifest_path"]).parent
        outside = self.root / "outside.txt"
        outside.write_text(CANARY)
        license_path = directory / "LICENSE-MIT"
        license_path.unlink()
        license_path.symlink_to(outside)
        with self.assertRaises(RuntimeError) as error:
            self.write()
        self.assertNotIn(CANARY, str(error.exception))
        self.assertFalse(self.output.exists())

    def test_explicit_license_parent_symlink_does_not_escape_dependency(self):
        directory = pathlib.Path(self.dependency["manifest_path"]).parent
        outside = self.root / "external-licenses"
        outside.mkdir()
        (outside / "text.txt").write_text(CANARY)
        (directory / "legal").symlink_to(outside, target_is_directory=True)
        self.dependency["license_file"] = "legal/text.txt"
        with self.assertRaises(RuntimeError) as error:
            self.write()
        self.assertNotIn(CANARY, str(error.exception))
        self.assertFalse(self.output.exists())

    def test_missing_standard_library_notice_fails(self):
        (self.doc / "COPYRIGHT-library.html").unlink()
        with self.assertRaisesRegex(RuntimeError, "license source is missing"):
            self.write()
        self.assertFalse(self.output.exists())

    def test_missing_linked_rust_license_fails(self):
        (self.doc / "licenses/MIT.txt").unlink()
        with self.assertRaisesRegex(RuntimeError, "license source is missing"):
            self.write()

    def test_rust_link_outside_doc_directory_fails(self):
        (self.doc / "COPYRIGHT-library.html").write_text('<a href="../outside-license">License</a>')
        with self.assertRaisesRegex(RuntimeError, "escapes its documentation directory"):
            self.write()

    def test_incomplete_metadata_fails_safely(self):
        self.metadata["resolve"]["root"] = CANARY
        with self.assertRaises(RuntimeError) as error:
            self.write()
        self.assertNotIn(CANARY, str(error.exception))

    def test_output_failure_fails_safely(self):
        self.output.write_text(CANARY)
        with self.assertRaises(RuntimeError) as error:
            self.write()
        self.assertIn("writable clean staging directory", str(error.exception))
        self.assertNotIn(CANARY, str(error.exception))

    def test_real_subprocess_command_failure_does_not_disclose_diagnostics(self):
        commands = self.root / "bin"
        commands.mkdir()
        cargo = commands / "cargo"
        cargo.write_text(f"#!{sys.executable}\nimport sys\n"
                         f"print({CANARY!r})\nprint({CANARY!r}, file=sys.stderr)\n"
                         "raise SystemExit(7)\n")
        cargo.chmod(0o755)
        script_directory = pathlib.Path(__file__).resolve().parent
        code = (
            f"import sys; sys.path.insert(0, {str(script_directory)!r}); "
            "import pathlib, release_licenses\n"
            f"release_licenses.ROOT = pathlib.Path({str(self.root)!r})\n"
            "try:\n"
            f" release_licenses.write_notices(pathlib.Path({str(self.output)!r}), 'synthetic-target')\n"
            "except RuntimeError as error:\n"
            " print(str(error), file=sys.stderr)\n"
            " raise SystemExit(1)\n"
        )
        result = subprocess.run([sys.executable, "-c", code], capture_output=True,
                                text=True, env={"PATH": str(commands)}, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("license source command failed", result.stderr)
        self.assertNotIn(CANARY, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
