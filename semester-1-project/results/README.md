# Results — JSON contract and interpretation

The CLI saves JSON here by default. `--html` also saves a same-basename HTML file here. `report/` contains rendering code, not generated reports. A custom `--output` can choose another directory. Website outputs are ignored by Git; this README and `.gitkeep` are tracked.

## Top-level JSON fields

| Field | Meaning |
| --- | --- |
| `scanId` | UUID generated for the CLI run; identifies this execution, not a website. |
| `url` | Normalized requested URL; not guaranteed to be the final redirected URL. |
| `start_time`, `end_time` | ISO-format local timestamps from the executing machine; no explicit timezone offset is stored. |
| `duration_seconds` | Scan duration; excludes subsequent file writing and HTML rendering. |
| `tests_run` | Number of successfully completed scanner routines, from 0 to 5. |
| `tests` | Per-module raw results plus completion status and timing. |
| `findings` | Combined normalized and deduplicated findings; use this list for aggregate analysis. |
| `total_findings` | Length of the combined `findings` list. |
| `summary` | Combined finding counts for `critical`, `high`, `medium`, `low`, `info`. |
| `deduplicated_count` | Number removed from collected findings during deduplication. |
| `errors`, `errors_count` | Orchestrator-level module failure messages and their count; not a count of every uncertainty inside findings. |
| `waf` | Detected WAF/challenge indicator, or `null`; absence is not proof no WAF exists. |
| `page_is_representative` | Whether the fetched response was suitable for analysis under the current gate. |
| `score`, `raw_score`, `grade` | Rule-based prioritization values, explained below. |
| `grade_reliable`, `coverage_note` | Coverage gate and explanation; reliability here means execution coverage, not measured detector accuracy. |
| `metrics` | Internal request/cache/module counters; diagnostic instrumentation rather than packet-level accounting. |

A target blocked by address-safety checks adds `status: "blocked_ssrf"` and `ssrf_block_reason`, has an empty `tests` mapping and null scores. Ordinary completed results do not have an overall `status` field: use per-module status and coverage fields.

## Per-module results: `tests`

Keys are the five module filenames without `.py`. Successful entries include `status: "complete"`, `duration_seconds`, and the scanner's own fields such as `findings` or `details`. Failed entries include `status: "incomplete"`, `fatal_error` and timing. Timeout is an incomplete result. An absent module on the early blocked-target path means it did not run.

Raw module findings have module-specific schemas. The HTML displays those raw `tests[module].findings`; its per-section counts can differ from the combined deduplicated total. A complete entry with no findings means no finding was emitted by that routine for the observed response, not a guarantee that the site has no vulnerability.

## Combined finding fields

| Field | Meaning |
| --- | --- |
| `id` | First 12 hexadecimal characters of SHA-256 over sorted JSON containing module, original title, CWE, OWASP and location. A grouping identifier, not a file-integrity checksum. |
| `module`, `title` | Producing check and finding description. |
| `severity` | `critical`, `high`, `medium`, `low` or `info`. |
| `confidence` | Implementation label: `verified-live`, `verified-static`, `plausible-unconfirmed` or `informational`. It is not a calibrated probability. |
| `cwe`, `owasp` | Classification labels when available; may be empty. |
| `location` | Observed resource/header/location. |
| `evidence` | Supporting observation, possibly masked or truncated. |
| `poc` | Suggested verification text; reporting does not execute it. |
| `remediation` | Suggested corrective action. |
| `detection_method` | Method/source description. |
| `tier` | Optional classification; `hardening` uses the capped secondary score deduction. |

Normalization limits text lengths (title 200, location 500, evidence 1000, PoC/remediation 500 characters). Numeric confidence inputs are mapped into labels by the normalizer; a label alone is not proof that a live credential check occurred. Read the evidence and detector behavior.

Deduplication groups by module, title, CWE, OWASP and stripped/lowercased location. Within a group it keeps the higher-confidence finding, breaking confidence ties by severity. It does not merge identical-looking findings across different modules. Location case normalization is an implementation choice, not a claim that URL paths are universally case-insensitive.

## Score

Start at 100. Deduct 30/15/5/2/0 for critical/high/medium/low/info findings. Hardening-tier deductions are capped at 10 in total; other deductions are uncapped. `raw_score` can be negative; visible `score` is floored at zero. Grades: A ≥85, B ≥75, C ≥65, D ≥55, otherwise F.

The calculation uses severity/tier, not a measured exploit probability. `grade_reliable` becomes false when the page is unrepresentative or fewer modules complete. Always show coverage with scores. These five-check scores should not be compared as equivalent to the original larger scanner's scores.

## Metrics and review order

`http_requests`, `base_url_gets`, `cache_hits`, `cache_reads`, `modules_executed` and `errors` are implementation counters. For example, `base_url_gets` is incremented once before the preflight retry loop, so it is not an exact number of all network attempts. `metrics.errors` is separate from top-level `errors`.

Review in this order: coverage → errors → finding evidence → severity/remediation → summary/score. For experiments, retain the JSON with the code commit, CSV hash, configuration and runtime versions; the current JSON does not embed all that provenance automatically.
