#!/usr/bin/env python3
"""Package tested executables and prepare a draft GitHub release."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import zlib

from github_releases import draft
from release_licenses import LicenseError
from release_packages import ReleaseError, TARGETS, package, prepare, verify_package


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "release: invalid arguments; use --help for the supported command\n")


def main():
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True, parser_class=Parser)
    build = commands.add_parser("package", help="package standalone release binaries")
    build.add_argument("--bin-dir", type=Path, default=Path("target/release"))
    build.add_argument("--target", required=True)
    build.add_argument("--output-dir", type=Path, required=True)
    extract = commands.add_parser("extract", help="verify and extract a package for acceptance")
    extract.add_argument("--input-dir", type=Path, required=True)
    extract.add_argument("--target", required=True)
    extract.add_argument("--output-dir", type=Path, required=True)
    promote = commands.add_parser("prepare", help="verify artifacts from this workflow run")
    promote.add_argument("--input-dir", type=Path, required=True)
    promote.add_argument("--output-dir", type=Path, required=True)
    publish = commands.add_parser("draft", help="attach tested assets to an unpublished draft")
    publish.add_argument("--asset-dir", type=Path, required=True)
    for command_parser in (build, extract, promote, publish):
        command_parser.add_argument("--run-id", required=True)
        if command_parser is not publish:
            command_parser.add_argument("--attempt", required=True)
        if command_parser is not build:
            command_parser.add_argument("--version", required=True)
            command_parser.add_argument("--source-sha", required=True)
    options = parser.parse_args()
    try:
        if options.operation == "package":
            result = package(options.bin_dir, options.output_dir, options.target,
                             options.run_id, options.attempt)
            print(f"packaged {result['target']}, version {result['version']}")
        elif options.operation == "extract":
            if options.target not in TARGETS:
                raise ReleaseError("unsupported release target")
            manifest = json.loads((options.input_dir / f"{options.target}.json").read_text())
            options.output_dir.mkdir(parents=True, exist_ok=False)
            verify_package(options.input_dir, manifest, options.version, options.source_sha,
                           options.run_id, options.attempt, options.output_dir)
            print("package checksums and permissions verified")
        elif options.operation == "prepare":
            prepare(options.input_dir, options.output_dir, options.version, options.source_sha,
                    options.run_id, options.attempt)
            print("both platform packages verified for draft preparation")
        else:
            print(draft(options.asset_dir, options.version, options.source_sha, options.run_id))
    except (ReleaseError, LicenseError) as error:
        print(f"release: {error}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError, StopIteration, EOFError,
            subprocess.SubprocessError, tarfile.TarError, zlib.error):
        # Parser and operating-system diagnostics may contain caller-controlled data.
        print("release: invalid or unavailable release data; rerun checks before preparing a draft",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
