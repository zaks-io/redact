# Future entropy detection options

Status: research options recorded on 2026-10-05. The synthetic evaluation is
implemented; production entropy detection and real chat-history evaluation are
deferred. No production policy, threshold, length bound, CLI flag, or acceptable
false-positive rate has been selected.

The [experiment contract](entropy-evaluation.md),
[initial findings](entropy-evaluation-results.md), and
[complete sweep](entropy-evaluation-report.md) are the current evidence. This
document records choices to revisit, not additional shipped coverage.

## Potential value

Entropy could catch opaque random secrets that have no recognized provider
prefix or sensitive field name. That would supplement the existing detectors
when formats are unfamiliar or change. It measures character diversity, not
credential validity, secrecy, or the randomness of the generating process.

Lengths such as 32, 64, and 128 characters are useful evaluation buckets, not a
universal secret grammar. Include intervening lengths and values outside the
bounds. A 32-character hex string and a 32-character Base64 string have different
entropy ceilings. Short or weak passwords remain secrets, and long private keys
usually have structural evidence that already supports detection.

For an agent-facing filter, some harmless-value removal may be worth the extra
secret coverage. Losing request IDs, hashes, paths, or diagnostic fields can
also prevent useful debugging. The product decision concerns both disclosure
risk and whether the remaining output supports the task.

## What the initial evaluation establishes

The corpus contains 1,892 synthetic cases and tests 72 additive policies. A
16-to-128-character bound with a 3.5-bit threshold catches 188 of 192 opaque
secrets at lengths 32, 64, and 128. It also removes their 188 identical public
controls. This demonstrates detection of random-looking strings and the lack
of evidence about their role.

A stricter 32-to-128-character, 4.5-bit policy still affects 79 of the 152 other
harmless examples. It catches no opaque hex secrets, whose entropy cannot
exceed 4 bits per character. Relative entropy changes which harmless examples
survive but does not separate identical public and secret strings.

The baseline catches all 166 structured/contextual secret fixtures. Existing
coverage remains intact under every tested policy. Candidate boundaries can
produce partial misses or remove ordinary prefixes and suffixes.

These are deliberately constructed stress cases, not production prevalence or
accuracy estimates. The paired controls and reused values are not independent
observations. There is no held-out corpus or ground truth for real chat logs.

## Strategies to compare

| Strategy | Potential benefit | Cost or unresolved issue | Current evidence |
| --- | --- | --- | --- |
| Retain current format/context detection | Preserves ordinary unmatched text under the current contract | Unrecognized standalone opaque secrets can pass through | Implemented baseline |
| Apply length-bounded entropy to every candidate | Broadest chance of catching unfamiliar opaque secrets | Also removes public IDs, hashes, encoded text, and public key material | Tested in the synthetic sweep |
| Apply entropy in selected contexts | May reduce harmless removal by narrowing where candidates occur | Misses bare secrets; context selection needs independent evidence | Proposed, not implemented |
| Preserve recognized public structures during entropy matching | May retain public PEM blocks, SSH keys, or diagnostic identifiers | A permissive exemption can hide a secret embedded in a public-looking container | Proposed, not implemented |
| Keep entropy as evaluation-only observation | Measures candidate frequency and overlap before changing output | Provides no extra production protection | Current experiment status |

Selected contexts could include unfamiliar assignment values or
authentication-related output that existing rules do not cover. Known sensitive
names and recognized authentication headers already require redaction regardless
of entropy. Their detection must not become conditional on the new score.

Any candidate-selection or public-structure policy must preserve every existing
secret match. A public-looking wrapper cannot veto a provider, assignment,
header, URL, private-key, or JWT match within it.

## Scoring and boundaries

Compare absolute bits per character with alphabet-relative scores. Absolute
thresholds exclude alphabets with lower ceilings; relative scores depend on
alphabet inference and short-sample bias. Ordered sequences and repeated
alphabets can score highly. Test proposed repetition or sequence checks against
secret examples as well as harmless ones before treating them as exclusions.

Length bounds limit candidates rather than certify them. The current experiment
scores maximal ASCII tokens and rejects oversized tokens whole. Sliding windows
could find candidates inside long runs, but introduce overlapping matches and
can leave secret prefixes or suffixes visible. They have not been evaluated.
Punctuation, padding, Unicode, escaping, wrapping, and attached prefixes need
explicit whole-span fixtures for any alternate tokenizer. Decoding or joining
fragments would be a separate detection change, not an incidental optimization.

All proposed production detection remains local to `rstr` stdin. Preserve the
separate `rprintenv` input model and disclosure policy. Do not add environment
lookups, known-secret dictionaries, provider calls, runtime rule downloads, or
new modes/configuration layers as a shortcut for evaluating entropy.

## Evidence needed for a decision

Keep the paired stress corpus, and add a separate representative corpus of
messages, command output, structured logs, code, documentation, and diagnostic
errors. Include public identifiers at plausible frequencies and synthetic
secrets with independently specified full spans. Record where sampling is
representative and where it is deliberately adversarial.

Compare every strategy against the same baseline. Report additional full-secret
coverage, partial misses, harmless cases affected, useful-byte loss, and results
by length, alphabet, context, and source type. Separate gains in unknown opaque
secrets from already-covered formats and separate paired controls from other
harmless examples. Measure whether an agent can still follow a request ID,
identify a failing endpoint, compare outputs, or diagnose an error after removal.

Split policy-development examples from held-out evaluation, keeping duplicates
and near-duplicates in one split. Record prevalence and labeling uncertainty.
Threshold selection on a corpus is not validation on that same corpus. Set
acceptable additional coverage and context-loss limits before selecting a
production default; the limits remain open product decisions.

## Possible chat-history evaluation

Applying the experiment to the user's chat-history logs was considered and
deferred. No real logs were evaluated. The existing harness accepts only its
synthetic corpus; it is not an arbitrary-log reader.

A future run requires a specified source and scope, such as a particular export,
project's sessions, or thread. Do not discover or scan unrelated projects based
on shared filesystem or connector access. Process authorized text locally,
keeping raw messages and tool output out of tool results, model context,
screenshots, fixtures, commits, and reports. A failed detector must produce a
sanitized error, never a raw sample for diagnosis.

Parse the export envelope separately from message content. Analyze conversation
text and tool output while retaining their original structured context. Report
transport metadata, session IDs, and other envelope identifiers separately so
they do not distort the estimated cost of filtering actual content. Decide how
to handle repeated messages, generated synthetic credentials, redaction markers,
code blocks, and copied documents before interpreting counts.

An aggregate-only report can measure candidate frequency, overlap with existing
rules, and additional removed bytes without exposing candidate values. A
baseline-redacted snippet is insufficient as a disclosure boundary: unmatched
text can still contain an unknown secret. Keep reports to approved metadata and
counts unless a separate disclosure-safe review method has been established.

Unlabeled history cannot establish precision, recall, or false-positive rate.
An entropy-only match is an unclassified candidate, not a confirmed secret or
confirmed false positive. Credible accuracy estimates require independently
assigned labels through a review method that does not expose raw input to the
agent. Record label uncertainty and selection bias; preserve the original logs.
Any persistent report or regression fixture must exclude real secret material.

## Open decisions

- How much harmless-value removal is acceptable for routine agent tasks?
- Should unfamiliar standalone tokens be removed, or should entropy require
  additional context?
- Which contexts add coverage beyond existing sensitive-name and format rules?
- Can public structures be preserved without introducing disclosure gaps?
- Which length bounds, alphabets, and scores are justified by held-out evidence?
- How should candidate boundaries handle embedded or punctuated secrets?
- What representative data and safe labeling method can support accuracy claims?
- What sampling scope and metadata separation would make a chat-log experiment
  useful without treating transcript machinery as ordinary content?

## Done for this research record

The implemented baseline, evaluated policies, unimplemented options, evidence
limits, real-log evaluation requirements, and open product decisions are
documented and linked from the detection spec. Future adoption requires a
separate production decision with updated detection/CLI contracts and executable
acceptance coverage. Until then, entropy remains an experiment.
