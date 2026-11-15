# Semester 1 — Local Website Security Scanner

A reproducible, command-line project that examines a website through five security checks, combines their evidence into JSON, and optionally generates a readable HTML report. The goal is to help a team inspect observable website configuration and exposed frontend content without deploying cloud infrastructure.

## What the project checks

| Check | Main evidence | Interpretation |
| --- | --- | --- |
| Secrets | HTML, JavaScript, referenced configuration content | Credential-like values and context; detection does not establish that a credential is active. |
| Frontend Libraries | Library fingerprints, versions, bundled CVE ranges | Matches observed components against a local vulnerability snapshot. |
| Cookies | `Set-Cookie` headers and cookie attributes | Flags issues using cookie purpose, transport and attribute rules. |
| Security Headers | Response headers and page context | Evaluates policies including CSP, HSTS, framing and other hardening headers. |
| CORS | Responses to cross-origin probes | Reports observable origin/credential policy behavior. |

This is a focused five-check scanner, not a complete application penetration test. It does not cover authentication workflows, backend source code, every route, or all vulnerability classes. It fetches HTTP content; it does not execute the application in a browser.

## How a scan works

1. Validate the URL and fetch the main page through the shared HTTP session.
2. Cache HTML, headers and cookie headers; assess whether the response represents the target rather than an error/challenge page.
3. Run the five explicitly selected scanners concurrently, sharing cached JavaScript where applicable.
4. Normalize findings, remove matching duplicates and calculate the five-check score.
5. Save JSON. If `--html` is present, render that same in-memory result into HTML beside the JSON.

The scanner files and CVE CSV were preserved from the extracted implementation. Integration changes belong to the local orchestrator and report layer. No Azure deployment, API gateway or database service is needed. Network access is still needed to inspect the target and its assets.

## Repository guide

| Folder | Start here | Purpose |
| --- | --- | --- |
| `code/` | [Code guide](code/README.md) | Installation, CLI, modules, tests and contribution workflow |
| `code/data/` | [Dataset guide](code/data/README.md) | Local frontend CVE snapshot and its limitations |
| `code/tests/` | [Test guide](code/tests/README.md) | Existing integration assertions |
| `report/` | [Report guide](report/README.md) | Optional HTML functions, inputs and hashing |
| `results/` | [Result schema](results/README.md) | JSON fields, statuses, findings and score interpretation |
| `validation/` | [Validation plan and evidence](validation/README.md) | Executed checks versus proposed detector validation |

## Quick start

From the repository root, using Python 3.10 or newer:

```bash
cd semester-1-project
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r code/requirements.txt
python code/main_scanner.py --url "https://example.com"
python code/main_scanner.py --url "https://example.com" --html
```

Windows activation: `.venv\Scripts\activate` in Command Prompt, or `.venv\Scripts\Activate.ps1` in PowerShell.

Results go to this project's `results/` directory. JSON is always the normal output; HTML is optional. Use `--output results/example.json` to choose a filename. The complete CLI and error behavior are documented in the code guide.

## What has actually been verified

The current six integration tests exercise all five modules together against a controlled local fixture, local CVE matching, JSON-only output, optional HTML, blocked-page handling, output locations, report failure handling and HTML escaping. The [recorded run](validation/current-tests.txt) and [file fingerprints](validation/current-tests-metadata.json) identify the tested implementation.

These assertions verify specific behavior. They do **not** estimate real-world precision/recall or prove that every detector is correct. The next validation step is a balanced, independently reviewed positive/negative fixture set for each check, described in the validation plan. Historical results from the larger project are not presented as results of this five-check version.

## Reading results responsibly

Check `tests_run`, per-test `status`, `errors`, `page_is_representative` and `grade_reliable` before interpreting the score. A high score from an incomplete scan is not evidence of a secure website. The score is a rule-based prioritization aid, not a probability of compromise or an accuracy metric. A completed check means its routine returned successfully; it does not establish exhaustive coverage.

The CVE file is a static snapshot. A missing CVE match can reflect incomplete fingerprints, missing versions or missing dataset coverage. Keep the dataset version with validation evidence.

## Team workflow

Run the integration suite before submitting changes. Preserve reproducible fixture inputs and expected outcomes when changing detection rules. Review JSON evidence before drawing conclusions from a report. Generated website results remain local and are ignored by Git; documentation and small validation records are tracked. See each folder's README for its contract.
