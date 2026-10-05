#!/usr/bin/env python3
"""Exercise the checked-in synthetic agent workflows with release executables."""
import argparse
import json
import pathlib
import platform
import statistics
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", default="target/release")
    parser.add_argument("--repeats", type=int, default=3)
    options = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent.parent
    binary_dir = (root / options.bin_dir).resolve()
    measurements = []
    count = 0
    for fixture in ("rprintenv-workflows.json", "rstr-workflows.json", "context-workflows.json"):
        cases = json.loads((root / "tests/fixtures" / fixture).read_text())["cases"]
        for case in cases:
            for _ in range(options.repeats):
                with tempfile.TemporaryDirectory(prefix="redact-acceptance-") as directory:
                    for name, value in case["files"].items():
                        path = pathlib.Path(directory) / name
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text(value)
                    started = time.perf_counter()
                    output = subprocess.run(
                        [str(binary_dir / case["binary"]), *case["args"]],
                        input=case.get("stdin_utf8", "").encode(),
                        env=case["environment"], cwd=directory,
                        capture_output=True, check=False, timeout=10,
                    )
                    measurements.append((time.perf_counter() - started) * 1000)
                    expected = case["expect"]
                    assert output.returncode == expected["exit_code"], case["id"]
                    stdout = output.stdout.decode()
                    stderr = output.stderr.decode()
                    if "stdout_utf8" in expected:
                        assert stdout == expected["stdout_utf8"], case["id"]
                    if "stdout_json" in expected:
                        assert json.loads(stdout) == expected["stdout_json"], case["id"]
                    if "stderr_utf8" in expected:
                        assert stderr == expected["stderr_utf8"], case["id"]
                    for text in expected.get("stderr_contains", []):
                        assert text in stderr, case["id"]
                    for canary in case["hidden_canaries"]:
                        assert canary not in stdout + stderr, case["id"]
            count += 1
    print(json.dumps({"platform": platform.platform(), "cases": count,
                      "commands_per_case": 1, "repeats": options.repeats,
                      "median_ms": round(statistics.median(measurements), 3),
                      "maximum_ms": round(max(measurements), 3)}))


if __name__ == "__main__":
    main()
