# Binary releases

Each version ships both `rprintenv` and `rstr`. Downloading and running them does
not require Rust. The initial packages are Linux x86-64 and Apple Silicon macOS.
Linux ARM, Intel macOS, and Windows packages are not provided.

## Download and install

Download assets from [Releases](https://github.com/zaks-io/redact/releases)
without a GitHub account. GitHub's automatic source-code archives do not contain
executables. The source code is available under the
[MIT license](https://github.com/zaks-io/redact/blob/main/LICENSE).

For Linux x86-64, run the following in a new directory. Substitute the published
version. For Apple Silicon, change the target to `aarch64-apple-darwin`.

```sh
(
set -euo pipefail
version=0.2.0
target=x86_64-unknown-linux-gnu
archive="redact-v${version}-${target}.tar.gz"
release_url="https://github.com/zaks-io/redact/releases/download/v${version}"
for asset in "$archive" SHA256SUMS release-manifest.json; do
  curl --fail --show-error --silent --location \
    "$release_url/$asset" --output "$asset"
done
grep -F "  $archive" SHA256SUMS | shasum -a 256 -c -
tar -xzf "$archive"
mkdir -p "$HOME/.local/bin"
install -m 755 "redact-v${version}-${target}/rprintenv" \
  "redact-v${version}-${target}/rstr" "$HOME/.local/bin/"
"$HOME/.local/bin/rprintenv" --version
"$HOME/.local/bin/rstr" --version
)
```

Continue to extraction only if checksum verification reports `OK`. The check
uses `shasum`, available on macOS and the supported Ubuntu systems. Add
`$HOME/.local/bin` to your shell's `PATH` if it is not already there. Installing
replaces prior copies at these two paths. Keep the archive's license directory
with the downloaded package.

Full SHA-256 checksums detect changed archive bytes. They do not authenticate a
publisher. The tools' 16-character secret fingerprints serve a different purpose.

## Compatibility and contents

Packages contain the two executable files, `LICENSE`, `INSTALL.md`, dependency
license texts and attribution, and Rust standard-library notices. Archive paths
and executable permissions are verified before shipment.

CI executes both packages on Blacksmith Ubuntu 24.04 x86-64 and macOS 26 Apple
Silicon. The release manifest records the Linux binary's actual required glibc
version or the macOS deployment target, the Rust compiler version, executable
and archive hashes, the source commit, and the workflow run/attempt that built
each platform. A linker deployment target or glibc requirement alone does not
certify an older operating system. Older systems remain unverified.

The macOS binaries are not Developer ID signed or notarized. Browser downloads
may trigger macOS security prompts. The browser download and macOS security
approval path needs verification on the user's Mac; CI downloads do not exercise
quarantine behavior.

`rstr` recognizes supported patterns and contextual secret fields. Arbitrary
standalone passwords may remain. Exit `0` does not certify safe output. Use the
[agent guide](agent-usage.md) for input sources and safe recovery, and pipe the
original producer's complete diagnostic context into `rstr`.

## Prepare a release

Merge the release implementation first so GitHub offers the manual `Release`
workflow. Set the intended package version in `Cargo.toml` and update its root
entry in `Cargo.lock` through Cargo. Merge that change to `main` before preparing
a new version. Both commands use the same package version.

Start the workflow from GitHub Actions with branch `main` and the exact Cargo
version without a `v` prefix, or run:

```sh
gh workflow run release.yml --repo zaks-io/redact --ref main -f version=0.2.0
```

The selected `main` revision is fixed for the entire run. The workflow:

1. Validates the requested version against that revision's Cargo package.
2. Runs reusable CI with all required checks on both Blacksmith platforms.
3. Packages standalone release binaries before test dependencies can enable
   additional runtime features, then tests extracted archive contents.
4. Downloads this run's successful platform artifacts, verifies their provenance,
   checksums, safe paths, and permissions, and combines release metadata.
5. Creates or resumes an unpublished draft, uploads missing assets, and downloads
   every asset again to verify the uploaded bytes.

Only the final draft job has `contents: write`. It does not build or execute the
application binaries. No automatic trigger publishes a release. Ordinary PR and
`main` CI upload native packages and exercise the same cross-platform artifact
download and verification as Release. Only Release prepares the transfer artifact
for draft upload. Use packages from a successful complete run; an acceptance job
can upload its platform package while another required job is still running.

The draft uses the exact source SHA as its target. An existing tag must resolve
to that commit. When no tag exists, the draft defers tag creation to publication.
The release job never replaces existing assets, publishes, or deletes releases
or tags. Every new action is pinned to an immutable revision.

Before publishing, review the draft assets, source SHA, CI link, hashes, and
compatibility notes. `main` currently has no branch protection or rulesets.
Workflow checks are validation, and a writer who changes workflow code can change
those checks. The final publication decision belongs to Isaac. Branch protection,
GitHub environments, immutable-release settings, and public hosting changes are
separate decisions.

After explicit publication, repeat download, checksum verification, installation,
and synthetic CLI acceptance against the published assets. The local binaries
and their hashes must match those from the tested archives.

## Retries and failures

Platform artifacts have distinct target/attempt names and are retained for 30
days, or seven days on PR runs. Failed-job-only reruns can retain an earlier
successful platform package from this same run and source commit. Preparation selects the highest available
successful attempt for each target; future attempts, different source commits,
wrong versions, missing platforms, and checksum mismatches are errors.

The intermediate `prepared-release` transfer artifact is regenerated on a
preparation rerun. It is replaced only within this workflow run. Published assets
and platform build artifacts are never overwritten.

Retry a failed draft job in the same run while artifacts remain available. An
existing single draft is resumed only when its target, notes, title, prerelease
status, and existing asset hashes match. A different CI run's notes are a
conflict even if the archive bytes match. Duplicate drafts, a published version,
conflicting tags, or differing assets stop preparation without changing existing assets. Resolve those cases
explicitly in GitHub; deleting a draft or tag requires Isaac's approval.

If artifacts expire, start a fresh Release workflow from the intended current
`main` version. It rebuilds and revalidates everything; it does not depend on an
old CI run. A fresh run has new provenance and cannot silently replace an
existing draft's manifest. Review an abandoned draft before deciding to remove it
or use a new version. Correct a bad published release with a new version.

## Local validation

Use the pinned Rust toolchain. Install its `rust-docs` component, which supplies
the complete standard-library notices. No real environment values or secrets
belong in package fixtures, command output, or release notes.

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
cargo build --locked --release --bins --jobs 2
python3 scripts/acceptance.py
rustup component add rust-docs
python3 scripts/release.py package --target x86_64-unknown-linux-gnu \
  --output-dir dist/local-packages --run-id 1 --attempt 1
python3 scripts/release.py extract --target x86_64-unknown-linux-gnu \
  --input-dir dist/local-packages --output-dir dist/local-acceptance \
  --version 0.2.0 --source-sha "$(git rev-parse HEAD)" --run-id 1 --attempt 1
python3 scripts/acceptance.py --bin-dir dist/local-acceptance
```

Use clean output directories. Run the Apple Silicon equivalent on that platform.
Local run number `1` is a fixture identifier, not evidence of hosted validation.

See the official [artifact upload](https://github.com/actions/upload-artifact#readme)
and [download](https://github.com/actions/download-artifact#readme) documentation
for retention, permission preservation, and digest verification, and the
[GitHub CLI release source](https://github.com/cli/cli/tree/trunk/pkg/cmd/release)
for draft lookup and creation behavior.
