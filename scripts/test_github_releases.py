"""Draft release tests use synthetic assets and an in-memory GitHub transport."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import github_releases as releases
from release_packages import ReleaseError
from test_release_packages import CANARY, RUN_ID, SHA, VERSION, prepared


class Github:
    def __init__(self, directory):
        self.directory = directory
        self.calls = []
        self.release = {"id": 42, "draft": True, "tag_name": f"v{VERSION}",
                        "target_commitish": SHA, "assets": [],
                        "name": f"v{VERSION}", "prerelease": False,
                        "body": (directory / "RELEASE_NOTES.md").read_text(),
                        "html_url": "https://github.com/zaks-io/redact/releases/tag/untagged-synthetic"}
        self.matching = []
        self.refs = []
        self.tag_objects = {}
        self.content = {}
        self.next_asset = 100
        self.mutate_after_upload = None

    def asset(self, name, content=None):
        content = (self.directory / name).read_bytes() if content is None else content
        asset = {"id": self.next_asset, "name": name, "size": len(content), "state": "uploaded"}
        self.next_asset += 1
        self.release["assets"].append(asset)
        self.content[asset["id"]] = content
        return asset

    def gh(self, arguments, data=None):
        self.calls.append((arguments, data))
        path = next(arg for arg in arguments if arg.startswith(("repos/", "https://")))
        method = arguments[arguments.index("--method") + 1] if "--method" in arguments else "GET"
        if "matching-refs" in path:
            result = self.refs
        elif "/git/tags/" in path:
            result = {"object": self.tag_objects[path.rsplit("/", 1)[-1]]}
        elif path.endswith("releases?per_page=100"):
            result = [self.matching]
        elif path.endswith("/assets?per_page=100"):
            result = [self.release["assets"]]
        elif "/releases/assets/" in path:
            return self.content[int(path.rsplit("/", 1)[-1])]
        elif path.startswith("https://uploads.github.com/"):
            if method != "POST":
                raise AssertionError("upload must use POST")
            name = path.split("?name=", 1)[1]
            content = Path(arguments[arguments.index("--input") + 1]).read_bytes()
            result = self.asset(name, content)
            if self.mutate_after_upload is not None:
                self.mutate_after_upload(self)
        elif path.endswith("/releases") and method == "POST":
            request = json.loads(data)
            if request["draft"] is not True:
                raise AssertionError("release creation must remain a draft")
            self.release.update(request)
            self.matching = [self.release]
            result = self.release
        elif path.endswith("/releases/42"):
            result = self.release
        else:
            raise AssertionError(f"unexpected test operation: {method} {path}")
        return json.dumps(result).encode()

    @property
    def uploads(self):
        return [arguments for arguments, _ in self.calls
                if any(arg.startswith("https://uploads.github.com/") for arg in arguments)]

    @property
    def mutations(self):
        return [arguments for arguments, _ in self.calls if "--method" in arguments]


class DraftTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = prepared(self.root)
        self.github = Github(self.directory)
        self.mock = patch.object(releases, "gh", side_effect=self.github.gh)
        self.mock.start()
        self.addCleanup(self.mock.stop)
        self.names = {path.name for path in self.directory.iterdir()} - {"RELEASE_NOTES.md"}

    def draft(self):
        return releases.draft(self.directory, VERSION, SHA, RUN_ID)

    def assert_read_only(self):
        self.assertEqual(self.github.mutations, [])

    def test_new_release_stays_draft_and_uploaded_bytes_are_download_verified(self):
        self.assertEqual(self.draft(), self.github.release["html_url"])
        self.assertTrue(self.github.release["draft"])
        self.assertEqual(self.github.release["target_commitish"], SHA)
        self.assertEqual(self.github.release["body"], (self.directory / "RELEASE_NOTES.md").read_text())
        self.assertEqual(len(self.github.uploads), len(self.names))
        for asset in self.github.release["assets"]:
            self.assertEqual(self.github.content[asset["id"]],
                             (self.directory / asset["name"]).read_bytes())
            downloads = [args for args, _ in self.github.calls
                         if f"repos/zaks-io/redact/releases/assets/{asset['id']}" in args]
            self.assertEqual(len(downloads), 1)
        methods = [args[args.index("--method") + 1] for args in self.github.mutations]
        self.assertTrue(all(method == "POST" for method in methods))

    def test_partial_draft_resumes_without_replacing_existing_assets(self):
        self.github.matching = [self.github.release]
        present = self.github.asset("SHA256SUMS")
        self.draft()
        self.assertEqual(len(self.github.uploads), len(self.names) - 1)
        self.assertEqual(self.github.release["assets"][0], present)
        self.github.calls.clear()
        self.draft()
        self.assert_read_only()

    def test_draft_from_another_run_or_edited_metadata_blocks_all_uploads(self):
        for field, value in (("body", "CI: synthetic earlier run"),
                             ("name", "synthetic different name"), ("prerelease", True)):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.github.release)
                candidate[field] = value
                self.github.matching = [candidate]
                self.github.calls.clear()
                with self.assertRaisesRegex(ReleaseError, "belongs to another run"):
                    self.draft()
                self.assert_read_only()

    def test_release_notes_allow_only_line_ending_and_trailing_whitespace_changes(self):
        self.github.release["body"] = self.github.release["body"].replace("\n", "\r\n") + "\r\n "
        self.github.matching = [self.github.release]
        self.draft()
        self.assertTrue(self.github.release["draft"])

    def test_incomplete_remote_upload_has_actionable_recovery_without_mutation(self):
        self.github.matching = [self.github.release]
        asset = self.github.asset("SHA256SUMS")
        asset["state"] = "starter"
        with self.assertRaisesRegex(ReleaseError, "incomplete upload"):
            self.draft()
        self.assert_read_only()

    def test_duplicate_drafts_published_release_and_wrong_commit_block_mutation(self):
        for label in ("duplicates", "published", "wrong_commit"):
            with self.subTest(label=label):
                candidate = copy.deepcopy(self.github.release)
                if label == "published":
                    candidate["draft"] = False
                if label == "wrong_commit":
                    candidate["target_commitish"] = "b" * 40
                self.github.matching = [candidate, candidate] if label == "duplicates" else [candidate]
                self.github.calls.clear()
                with self.assertRaises(ReleaseError):
                    self.draft()
                self.assert_read_only()

    def test_annotated_tags_resolve_and_wrong_commit_blocks_mutation(self):
        tag_sha = "c" * 40
        self.github.refs = [{"ref": f"refs/tags/v{VERSION}",
                             "object": {"type": "tag", "sha": tag_sha}}]
        self.github.tag_objects[tag_sha] = {"type": "commit", "sha": "b" * 40}
        with self.assertRaises(ReleaseError):
            self.draft()
        self.assert_read_only()
        self.github.tag_objects[tag_sha] = {"type": "commit", "sha": SHA}
        self.draft()
        self.assertTrue(self.github.release["draft"])

    def test_conflicting_asset_prevents_all_uploads(self):
        self.github.matching = [self.github.release]
        self.github.asset("SHA256SUMS", CANARY.encode())
        with self.assertRaisesRegex(ReleaseError, "differs from tested bytes"):
            self.draft()
        self.assert_read_only()
        self.assertEqual(len(self.github.release["assets"]), 1)

    def test_duplicate_or_unexpected_assets_block_mutation(self):
        for label in ("duplicate", "unexpected"):
            with self.subTest(label=label):
                self.github.release["assets"] = []
                self.github.matching = [self.github.release]
                if label == "duplicate":
                    self.github.asset("SHA256SUMS")
                    self.github.asset("SHA256SUMS")
                else:
                    self.github.asset("unexpected.txt", b"synthetic")
                self.github.calls.clear()
                with self.assertRaises(ReleaseError):
                    self.draft()
                self.assert_read_only()

    def test_corrupt_local_checksums_block_all_github_calls(self):
        (self.directory / "SHA256SUMS").write_text(CANARY)
        with self.assertRaises(ReleaseError):
            self.draft()
        self.assertEqual(self.github.calls, [])

    def test_missing_platform_blocks_all_github_calls(self):
        path = self.directory / "release-manifest.json"
        manifest = json.loads(path.read_text())
        manifest["packages"] = manifest["packages"][:1]
        path.write_text(json.dumps(manifest))
        with self.assertRaises(ReleaseError):
            self.draft()
        self.assertEqual(self.github.calls, [])

    def test_upload_corruption_or_concurrent_publish_is_detected_without_rollback(self):
        for label in ("corrupt", "published"):
            with self.subTest(label=label):
                self.github.release["assets"] = []
                self.github.matching = [self.github.release]
                self.github.release["draft"] = True
                def mutate(github):
                    if label == "published":
                        github.release["draft"] = False
                    else:
                        github.content[github.release["assets"][-1]["id"]] = b"synthetic corruption"
                self.github.mutate_after_upload = mutate
                self.github.calls.clear()
                with self.assertRaises(ReleaseError):
                    self.draft()
                self.assertTrue(self.github.release["assets"])
                self.assertTrue(all(args[args.index("--method") + 1] == "POST"
                                    for args in self.github.mutations))

    def test_concurrent_identity_change_or_duplicate_asset_is_detected(self):
        for label in ("target", "tag", "duplicate"):
            with self.subTest(label=label):
                self.github.release["assets"] = []
                self.github.release["target_commitish"] = SHA
                self.github.release["tag_name"] = f"v{VERSION}"
                self.github.matching = [self.github.release]
                def mutate(github):
                    if label == "target":
                        github.release["target_commitish"] = "b" * 40
                    elif label == "tag":
                        github.release["tag_name"] = "v9.9.9"
                    else:
                        asset = github.release["assets"][-1]
                        github.asset(asset["name"], github.content[asset["id"]])
                self.github.mutate_after_upload = mutate
                self.github.calls.clear()
                with self.assertRaisesRegex(ReleaseError, "draft changed"):
                    self.draft()
                self.assertTrue(self.github.release["assets"])
                self.assertTrue(all(args[args.index("--method") + 1] == "POST"
                                    for args in self.github.mutations))

    def test_cli_github_failure_hides_raw_command_output(self):
        tool_dir = self.root / "tools"
        tool_dir.mkdir()
        tool = tool_dir / "gh"
        tool.write_text(f"#!/bin/sh\nprintf '%s\\n' '{CANARY}' >&2\nexit 1\n")
        tool.chmod(0o755)
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("release.py")), "draft",
             "--asset-dir", str(self.directory), "--version", VERSION,
             "--source-sha", SHA, "--run-id", str(RUN_ID)],
            env={"PATH": str(tool_dir)}, capture_output=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"GitHub operation failed", result.stderr)
        self.assertNotIn(CANARY.encode(), result.stdout + result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)

    def test_gh_failure_discards_raw_output(self):
        self.mock.stop()
        failure = subprocess.CompletedProcess(["gh"], 1, CANARY.encode(), CANARY.encode())
        with patch.object(releases.subprocess, "run", return_value=failure):
            with self.assertRaises(ReleaseError) as caught:
                releases.gh(["api", "synthetic"])
        self.assertNotIn(CANARY, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
