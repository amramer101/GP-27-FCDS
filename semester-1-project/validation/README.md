# Validation — current evidence and proposed ground truth

## Current status

This folder records the existing integration suite and proposes the next detector-validation step. **A five-detector ground-truth benchmark has not yet been implemented or executed in this repository.** No precision, recall, F1 or “100% accurate” claim is made here.

| Evidence | Available now | What it establishes |
| --- | --- | --- |
| Six integration tests | [Source](../code/tests/test_cli.py), [run log](current-tests.txt), [metadata](current-tests-metadata.json) | The asserted CLI, orchestration, local CSV and report behaviors passed for the recorded files/environment. |
| Source-level regression tests | Embedded in the scanner files | Inspectable rules/examples. Existence alone is not an execution record. |
| Initial extraction checks | Four suites previously executed: 19 secrets, 18 cookies, 10 headers, 11 CORS tests | Historical development checks; their raw run logs are not archived here, so they are not the current reproducibility artifact. |
| Independent detector benchmark | Proposed below | Not yet available. |
| External-tool agreement | Not imported | Not a substitute for reviewed ground truth. |

The metadata fingerprints code and data, records the base commit, exact command, runtime/dependency versions and timestamp. A passing run only supports its assertions and the fingerprinted implementation.

## What to reuse from the larger project's validation design

Read-only review found a synthetic HTTP fixture application, a case manifest, a runner, runner tests and saved external-tool comparisons. Reuse the **design** of explicit positive/negative cases for secrets, libraries, cookies, headers and CORS. A Docker wrapper can later make the fixture environment easier to reproduce; Docker is packaging, not ground truth.

Do not copy the old runner or historical headline numbers unchanged:

- Its case-level prediction uses whether an `expected_present` title matched. On a negative case that list is empty, so `predicted_positive` stays false even if forbidden findings occur. It records `absent_hits` separately but does not feed them into the false-positive count. This can inflate the reported negative-case success.
- One matching title can count as a positive hit despite other expected findings being missing. Use per-rule assertions, not an “any expected title” shortcut.
- Its broader suite includes checks outside this project and optional mocked paths. Keep only the five current checks and label every mock explicitly.
- Saved external-tool comparisons exclude incomplete scans and depend on verdict mappings. They are agreement evidence for that saved sample, not independent accuracy evidence for this code revision.

No private historical website outputs or larger-project datasets have been copied here. The current local test fixture and metadata provide a small, shareable starting point.

## Proposed ground-truth protocol

Ground truth means an expected outcome justified independently of the scanner output. Write and review expected labels before running the detector. Store the controlled HTTP response, rule rationale and reference alongside each label. Use synthetic credentials only; never validate fixture keys against real provider accounts.

| Check | Positive fixture | Negative/boundary fixture |
| --- | --- | --- |
| Secrets | Synthetic supported key shape in credential context; external/inline JS variants | Placeholders, low-entropy values, unrelated strings; expected redaction |
| Frontend libraries | Known library/version inside a reviewed affected range | Fixed version, below-range version, unknown version, mismatched fingerprint |
| Cookies | Sensitive cookie missing a required attribute under the relevant transport | Correct attributes, tracking vs session classification, prefix rules, no cookies |
| Headers | Specific missing/unsafe policy under applicable page/transport context | Correct policy, API/static-page applicability, malformed/empty directives |
| CORS | Defined reflected/wildcard origin policy with explicit credential behavior | Rejected probe origin, allowlist, absent headers, probe failure/inconclusive |

HTTP-only fixtures cannot validate every HTTPS-specific behavior: use controlled HTTPS for transport-dependent end-to-end cases, or clearly label unit tests that supply HTTPS context without a real TLS exchange. A cookie-free page or a failed CORS probe must not silently become a confirmed safe policy.

Proposed case record:

```text
case_id, module, rule_id, fixture_path, transport,
expected_outcome (positive/negative/inconclusive/not-applicable),
required_findings, forbidden_findings, expected_evidence,
rationale, reference, reviewer, fixture_sha256
```

Require all expected assertions and reject any forbidden finding. Include timeout, blocked-page and unsupported-input cases. Match module/rule/evidence rather than relying only on broad title substrings. A second teammate should review labels against the fixture and cited rule before execution.

## Measurement rules

For each independently labeled applicable rule-case pair, record TP, FP, FN or TN. Count a negative case with an emitted prohibited detection as FP. A missing expected detection is FN. Report incomplete/inconclusive/not-applicable outcomes separately with explicit coverage denominators; do not silently remove them or relabel them TN.

- Precision = TP / (TP + FP).
- Recall = TP / (TP + FN).
- F1 = 2 × precision × recall / (precision + recall).
- Undefined denominators are `N/A`, not automatic 100%.

Publish per-module counts and case inventory before aggregate metrics. Show a confusion matrix, the number of excluded/non-conclusive cases and why. Synthetic performance describes the fixture set; it does not generalize automatically to arbitrary websites. External-tool comparison is a separate experiment with its own mapping and coverage notes.

## Minimal implementation proposal — not implemented yet

```text
validation/
  fixtures/app.py          # controlled positive/negative HTTP(S) responses
  fixtures/cases.json      # reviewed expected labels and rationales
  runner.py                # real five-module execution and per-rule assertions
  test_runner.py           # verifies FP/FN accounting and incomplete handling
  runs/<run-id>/           # manifest, logs, per-case results and metrics
  Dockerfile              # optional reproducible fixture environment
```

Implement the case manifest and runner accounting tests first, then the fixture app and actual runs. Preserve code commit, dirty-file status, code/data/fixture hashes, environment, arguments, timestamps, mode and observed outputs for each published run. Keep report styling tests separate from detector-validity measurements.

## Defensible presentation statement

“The five-check pipeline has passed the recorded local integration tests for execution, output handling and selected assertions. A detector-level benchmark with independently reviewed positive and negative cases is the next validation step. These tests do not establish universal detection accuracy.”

After that benchmark is actually executed, replace the future claim with its exact case counts, coverage, metrics, run identifier and limitations.
