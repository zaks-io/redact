# Binary release plan

Status: implemented for local and CI validation. Hosted results and release
publication must be verified separately. See [release operations](releases.md).

## Existing foundation

Both commands already use the pinned Rust toolchain, `Cargo.lock`, and the
canonical optimized profile. The previous main CI run passed on Blacksmith
Linux x86-64 and Apple Silicon macOS. It had no downloadable binary artifacts.
The repository is public under the MIT license. Cargo registry publishing is
disabled.

## Reviewed approach

Opus 5.5 reviewed the original proposal to promote packages from a selected
historical CI run. That design left expired-artifact recovery, workflow attempts,
and draft retries underspecified. The implementation runs reusable CI inside a
manual Release workflow, so testing and draft preparation share one source
revision and workflow run. It does not retrieve packages from unrelated CI runs.

The supported package targets are `x86_64-unknown-linux-gnu` and
`aarch64-apple-darwin`. Both commands share a version and ship together. Packages
retain executable permissions and include license texts and usage instructions.
The release contains both archives, `SHA256SUMS`, and `release-manifest.json`.
Users download executables without installing Rust.

## Implementation

- `scripts/release_packages.py` packages standalone binaries, records runtime
  requirements and hashes, verifies safe archive contents, and combines this
  run's successful platform artifacts.
- `scripts/release_licenses.py` collects locked dependency attribution and full
  bundled license texts, including Unicode and Rust standard-library notices.
  Missing required notices fail packaging.
- `scripts/github_releases.py` validates existing tags and drafts, uploads only
  missing matching assets by release ID, and verifies downloaded upload bytes.
  It has no publication or deletion operation.
- `scripts/release.py` exposes the packaging, extraction, preparation, and draft
  operations with concise safe failure diagnostics.
- `.github/workflows/ci.yml` keeps existing required checks, uploads and verifies
  native packages together on PRs and main, and can be called by Release to upload
  the combined draft-transfer artifact.
- `.github/workflows/release.yml` validates the selected main revision, invokes
  reusable CI, prepares assets after all checks pass, and writes a draft with
  `contents: write` limited to the final job.

Platform artifacts use target/attempt names. Preparation chooses the highest
successful attempt per target within the same source revision and workflow run.
A failed-job-only rerun may reuse the earlier successful platform. Fresh release
runs rebuild instead of depending on old artifact retention. Draft lookup lists
releases including drafts; duplicate or conflicting releases fail without
replacement. Versions are checked on each native build platform and against the
selected source package; Linux never executes the macOS binary.

## Scope and limits

CI establishes Ubuntu 24.04 x86-64 and macOS 26 Apple Silicon coverage. Runtime
metadata does not prove that older operating systems work. Linux ARM, Intel
macOS, Windows, Homebrew, crates.io, automatic installers, and Apple Developer ID
signing/notarization are outside this first release.

Public release downloads do not require GitHub authentication.
Unsigned browser downloads need a separate macOS quarantine-flow check on
Isaac's Mac. Review the draft's source SHA, CI link, and hashes before publishing;
workflow validation alone is not an access-control boundary for repository
writers. Production publication remains an explicit user action.

## Done

- All existing required checks and new Python release tests pass. Failure tests
  cover malformed metadata, unsafe archives, missing platforms, bad provenance,
  differing checksums, conflicting drafts/tags/assets, and safe diagnostics.
- Both Blacksmith platforms execute acceptance against extracted production
  packages before their artifacts can reach draft preparation.
- The manually prepared draft contains exactly two binary archives, the checksum
  file, and the manifest. Downloaded upload bytes match the tested packages.
- Clean-directory download, checksum verification, installation, and synthetic
  CLI acceptance succeed on Linux and Apple Silicon. Browser quarantine behavior
  is checked on the user's Mac before claiming that download path works.
- Isaac reviews and explicitly publishes. Published-download acceptance follows
  that authorization. Implementation does not silently complete publication.
