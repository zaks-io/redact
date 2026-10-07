#!/usr/bin/env python3
"""Collect local license texts for the release dependency graph and Rust library."""

import json
import pathlib
import re
import subprocess
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

ROOT = pathlib.Path(__file__).resolve().parent.parent
LICENSE_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT")
MIT_EXPRESSIONS = {
    "MIT", "MIT OR Apache-2.0", "Apache-2.0 OR MIT", "MIT/Apache-2.0",
    "Apache-2.0/MIT", "MIT / Apache-2.0", "Apache-2.0 / MIT", "Unlicense OR MIT",
}
UNICODE_EXPRESSION = "(MIT OR Apache-2.0) AND Unicode-3.0"


class LicenseError(RuntimeError):
    """A fixed, approved license diagnostic."""


def _command(arguments):
    try:
        result = subprocess.run(
            arguments, cwd=ROOT, capture_output=True, text=True,
            check=False, timeout=120,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise LicenseError("license source command failed; verify the pinned Rust installation") from None
    if result.returncode:
        raise LicenseError("license source command failed; fetch locked dependencies and install rust-docs")
    return result.stdout


def _read(path):
    try:
        if path.is_symlink():
            raise LicenseError("license sources must not be symbolic links; restore packaged sources")
        content = path.read_bytes()
    except OSError:
        raise LicenseError("required license source is missing or unreadable; restore dependencies and rust-docs") from None
    if not content.strip():
        raise LicenseError("required license source is empty; restore dependencies and rust-docs")
    return content


def _release_packages(metadata):
    """Include build dependencies because proc macros may emit code in the executables."""
    try:
        resolve = metadata["resolve"]
        nodes = {node["id"]: node for node in resolve["nodes"]}
        pending = [resolve["root"]]
        selected = set()
        while pending:
            package_id = pending.pop()
            if package_id in selected:
                continue
            selected.add(package_id)
            pending.extend(
                dependency["pkg"] for dependency in nodes[package_id]["deps"]
                if any(kind["kind"] != "dev" for kind in dependency["dep_kinds"])
            )
        packages = [package for package in metadata["packages"] if package["id"] in selected]
        if len(packages) != len(selected):
            raise ValueError
        return sorted(packages, key=lambda package: (package["name"], package["version"]))
    except (KeyError, TypeError, ValueError):
        raise LicenseError("Cargo dependency metadata is incomplete; regenerate locked metadata") from None


def _package_notice(package):
    try:
        name, version = package["name"], package["version"]
        expression = package["license"]
        if not all(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.+-]+", value)
                   for value in (name, version)):
            raise ValueError
        if expression not in MIT_EXPRESSIONS | {UNICODE_EXPRESSION}:
            raise LicenseError("dependency license expression needs review before release packaging")
        directory = pathlib.Path(package["manifest_path"]).parent
        # The workspace contains unrelated fixtures and generated output.
        candidates = directory.iterdir() if package["source"] is None else directory.rglob("*")
        sources = {
            path.relative_to(directory): path for path in candidates
            if path.is_file() and path.name.upper().startswith(LICENSE_PREFIXES)
        }
        if package.get("license_file"):
            explicit = pathlib.Path(package["license_file"])
            if explicit.is_absolute() or ".." in explicit.parts:
                raise ValueError
            sources[explicit] = directory / explicit
        for path in sources.values():
            path.resolve().relative_to(directory.resolve())
        texts = {relative: _read(path) for relative, path in sorted(sources.items())}
        mit_sources = [content for relative, content in texts.items()
                       if len(relative.parts) == 1
                       and relative.name.upper() in {"LICENSE", "LICENSE-MIT", "LICENCE", "LICENCE-MIT"}]
        if not any(b"Permission is hereby granted" in content for content in mit_sources):
            raise LicenseError("dependency MIT license text is missing; restore its packaged sources")
        if expression == UNICODE_EXPRESSION and not any(
            "UNICODE" in relative.name.upper() and b"UNICODE LICENSE" in content
            for relative, content in texts.items()
        ):
            raise LicenseError("dependency Unicode license text is missing; restore its packaged sources")
        prefix = pathlib.Path("crates") / f"{name}-{version}"
        files = {prefix / relative: content for relative, content in texts.items()}
        return {"name": name, "version": version, "declared_license": expression,
                "selected_license": "MIT AND Unicode-3.0" if expression == UNICODE_EXPRESSION else "MIT",
                "files": [str(path) for path in files]}, files
    except (KeyError, TypeError, ValueError, OSError):
        raise LicenseError("dependency license metadata is incomplete; restore its packaged sources") from None


class _LocalLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = []

    def handle_starttag(self, tag, attributes):
        for name, value in attributes:
            if name not in {"href", "src"} or not value:
                continue
            url = urlsplit(value)
            if url.scheme in {"http", "https"} or (not url.path and not url.netloc):
                continue
            if url.scheme or url.netloc:
                raise LicenseError("Rust license notice has an unsupported reference; inspect pinned rust-docs")
            self.paths.append(pathlib.Path(unquote(url.path)))


def _rust_notices():
    sysroot = pathlib.Path(_command(["rustc", "--print", "sysroot"]).strip())
    source = sysroot / "share/doc/rust"
    pending = [pathlib.Path("COPYRIGHT-library.html")]
    files = {}
    while pending:
        relative = pending.pop()
        path = (source / relative).resolve()
        try:
            relative = path.relative_to(source.resolve())
        except ValueError:
            raise LicenseError("Rust license reference escapes its documentation directory") from None
        output = pathlib.Path("rust") / relative
        if output in files:
            continue
        content = _read(path)
        files[output] = content
        if path.suffix.lower() == ".html":
            links = _LocalLinks()
            try:
                links.feed(content.decode("utf-8"))
            except (UnicodeError, ValueError):
                raise LicenseError("Rust license notice is invalid; restore pinned rust-docs") from None
            pending.extend(relative.parent / link for link in links.paths)
    return files


def write_notices(destination: pathlib.Path, target: str):
    """Write destination/licenses without downloading license texts or exposing diagnostics."""
    try:
        metadata = json.loads(_command([
            "cargo", "metadata", "--locked", "--offline", "--format-version", "1",
            "--filter-platform", target,
        ]))
    except (json.JSONDecodeError, TypeError):
        raise LicenseError("Cargo dependency metadata is invalid; regenerate locked metadata") from None
    entries, files = [], {}
    for package in _release_packages(metadata):
        entry, package_files = _package_notice(package)
        entries.append(entry)
        files.update(package_files)
    files.update(_rust_notices())
    files[pathlib.Path("dependencies.json")] = (json.dumps(entries, indent=2) + "\n").encode()
    files[pathlib.Path("README.txt")] = (
        "Dependency copyright notices and full license texts are under crates/.\n"
        "dependencies.json identifies the locked runtime and build dependency versions.\n"
        "MIT is selected where crates offer a choice; additional bundled notices are retained.\n"
        "Rust standard library notices and texts are in rust/COPYRIGHT-library.html.\n"
    ).encode()
    try:
        output = destination / "licenses"
        output.mkdir(parents=True, exist_ok=False)
        for relative, content in sorted(files.items()):
            path = output / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    except OSError:
        raise LicenseError("cannot write release license notices; use a writable clean staging directory") from None
