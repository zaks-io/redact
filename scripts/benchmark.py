#!/usr/bin/env python3
"""Compare local CLI builds using only synthetic inputs and verified outputs."""
import argparse
import hashlib
import json
import pathlib
import platform
import statistics
import subprocess
import time


def marker(value):
    digest = hashlib.sha256(value).hexdigest()[:16]
    return f"[REDACTED sha256={digest}]".encode()


def scenarios():
    secret = b"synthetic-benchmark-canary"
    line = b'{"password":"' + secret + b'","status":401}\n'
    redacted = b'{"password":"' + marker(secret) + b'","status":401}\n'
    count = 4 * 1024 * 1024 // len(line)
    ordinary = b"ordinary diagnostic status=200\n"
    limit = (ordinary * (16 * 1024 * 1024 // len(ordinary) + 1))[:16 * 1024 * 1024]
    rejected = b"xsk-a/" * (4 * 1024 * 1024 // 6)
    return [
        ("presence", "rprintenv", ["--exists", "BENCHMARK_SECRET"], b"", b""),
        ("small_filter", "rstr", [], line, redacted),
        ("mixed_4mib", "rstr", [], line * count, redacted * count),
        ("ordinary_16mib", "rstr", [], limit, limit),
        ("rejected_prefixes_4mib", "rstr", [], rejected, rejected),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bin_dirs", nargs="+", type=pathlib.Path)
    parser.add_argument("--repeats", type=int, default=7)
    options = parser.parse_args()
    if options.repeats < 1:
        parser.error("repeats must be positive")
    builds = [directory.resolve(strict=True) for directory in options.bin_dirs]
    if len(set(builds)) != len(builds):
        parser.error("build directories must be distinct")
    results = {}
    for directory in builds:
        results[str(directory)] = {
            "bytes": {name: (directory / name).stat().st_size for name in ("rprintenv", "rstr")},
            "cases": {},
        }
    for name, binary, args, input_bytes, expected in scenarios():
        samples = {directory: [] for directory in builds}
        # Alternate builds so sustained shared-host load does not favor one build.
        for iteration in range(options.repeats + 1):
            order = builds[iteration % len(builds):] + builds[:iteration % len(builds)]
            for directory in order:
                started = time.perf_counter()
                output = subprocess.run(
                    [str(directory / binary), *args], input=input_bytes,
                    env={"BENCHMARK_SECRET": "synthetic-benchmark-canary"},
                    cwd=directory, capture_output=True, check=False, timeout=30,
                )
                elapsed = (time.perf_counter() - started) * 1000
                if output.returncode != 0 or output.stderr or output.stdout != expected:
                    raise RuntimeError(f"synthetic benchmark failed: {name}, {str(directory)!r}")
                if iteration:
                    samples[directory].append(elapsed)
        for directory in builds:
            results[str(directory)]["cases"][name] = {
                "input_bytes": len(input_bytes),
                "median_ms": round(statistics.median(samples[directory]), 3),
                "min_ms": round(min(samples[directory]), 3),
                "max_ms": round(max(samples[directory]), 3),
            }
    print(json.dumps({"platform": platform.platform(), "repeats": options.repeats,
                      "builds": results}, indent=2))


if __name__ == "__main__":
    main()
