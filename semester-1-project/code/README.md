# Code — setup, execution and development

All commands below assume the working directory is `semester-1-project/` unless stated otherwise.

## Files and responsibilities

| File | Responsibility | Per-module timeout |
| --- | --- | --- |
| `main_scanner.py` | CLI, shared context/cache, five-module selection, normalization, deduplication, score and JSON persistence | Main-page requests default to 15 seconds; transient preflight failures can retry |
| `test_01_secrets.py` | Secret detection and redacted evidence | 60 s |
| `test_02_frontend_libs.py` | Frontend identification and CVE correlation | 45 s |
| `test_03_cookies.py` | Cookie attributes and sensitivity | 15 s |
| `test_05_security_headers.py` | Header policies and contextual hardening | 20 s |
| `test_08_cors.py` | CORS probes and interpretation | 15 s |
| `data/cve_database_v2.csv` | Bundled vulnerability snapshot | Local file |
| `tests/test_cli.py` | Six integration tests | Local HTTP fixture |

The `test_01` etc. files are operational scanners despite their names. `SCANNER_MODULES` is an explicit allowlist: copying another `test_*.py` into this folder does not enable it. Each scanner exposes an asynchronous `run(ctx)` function. A result containing `fatal_error` becomes incomplete; an ordinary dictionary becomes complete. A complete return can still contain uncertainty or informational findings.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r code/requirements.txt
```

Python 3.10+; third-party runtime dependencies are `aiohttp`, `beautifulsoup4` and `packaging`. The HTML renderer uses only the standard library. Requirements currently specify minimum versions, not a lockfile; record installed versions when reproducing an experiment.

Windows: activate with `.venv\Scripts\activate` (Command Prompt) or `.venv\Scripts\Activate.ps1` (PowerShell). All later `python` commands are the same.

## CLI reference

```bash
python code/main_scanner.py --help
python code/main_scanner.py --url "https://example.com"
python code/main_scanner.py --url "example.com" --html
python code/main_scanner.py --url "https://example.com" --html --output results/example.json
```

| Argument | Behavior |
| --- | --- |
| `--url` | Required. HTTP(S) website; a bare hostname receives `https://`. Embedded URL credentials are rejected. |
| `--html` | Optional. Loads `report/html_report.py` after JSON is saved and creates HTML beside it. |
| `--output` | Optional JSON filename; must end in `.json`. Relative paths resolve from the shell's current directory. Existing explicit output files are overwritten. |

Default filenames are `<host>_<UUID>.json` and, when requested, the matching `.html`. The default results directory and CSV path are resolved relative to the project, not the shell directory. Parent output directories are created automatically.

| Exit code | Meaning |
| --- | --- |
| `0` | All five scanners completed; findings may still exist. |
| `2` | Incomplete/blocked scan, or argument-parser rejection. For a completed scan attempt, inspect the saved JSON; invalid arguments do not create a scan result. |
| `1` | Caught execution/output/report error. Report generation failure leaves the previously saved JSON available. |

`run_scout(url, scan_id, config=None)` returns the result dictionary; it does not save files. The CLI owns persistence and optional rendering. The orchestrator forces the bundled CSV and clears `CVE_TABLE_ENDPOINT` in its process; the unchanged frontend scanner's dormant cloud loader is not used. There is no CLI flag to change the CSV, enable HTML by default, or turn on live secret verification.

## Tests

```bash
python -m unittest discover -s code/tests -v
```

The suite starts a local server, launches the actual CLI in subprocesses and requires no external website. It temporarily enables `BRAVO6_VALIDATION_ALLOW_PRIVATE_TARGETS` only in fixture subprocesses. Normal execution keeps the original private-address/redirect checks enabled.

The scanner source also contains regression suites. These four source-level commands were executed during the initial extraction (19, 18, 10 and 11 tests respectively); they are distinct from the current six-test evidence record:

```bash
python code/test_01_secrets.py --test
python code/test_03_cookies.py --test
python code/test_05_security_headers.py --test
python code/test_08_cors.py --test
```

The frontend file includes legacy cloud-loader tests; its full `--test` suite is not part of the minimal-dependency verification claim. Current integration tests exercise its real local CSV path. See [validation](../validation/README.md) for missing detector-level coverage.

## Making changes

1. Reproduce the intended behavior with a controlled fixture or a focused regression test.
2. Update the relevant module; keep shared orchestration separate from detection logic.
3. Run the integration suite and affected regression tests.
4. Inspect both structured output and optional HTML when a schema changes.
5. Update the folder documentation and regenerate validation fingerprints if publishing new evidence.

Keep cloud deployment files and unrelated checks out of this project. Do not treat a missing finding on a failed scan as a passing check. If dependencies cannot import, use the active virtual environment; if a website fails, inspect per-test errors before changing detection rules.
