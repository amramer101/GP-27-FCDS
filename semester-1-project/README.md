# Semester 1 — Local Website Scanner

## Layout

```text
semester-1-project/
├── code/
│   ├── main_scanner.py
│   ├── test_01_secrets.py
│   ├── test_02_frontend_libs.py
│   ├── test_03_cookies.py
│   ├── test_05_security_headers.py
│   ├── test_08_cors.py
│   ├── data/cve_database_v2.csv
│   ├── requirements.txt
│   └── tests/test_cli.py
├── report/
│   └── html_report.py
└── results/
```

The five scanner files and frontend CVE database are unchanged from the extracted source. The orchestrator loads exactly these five files; adding other Python files does not enable additional scans. The shared cache, finding normalization, deduplication, and scoring are retained. Scores apply only to the five included checks.

## Install

Use Python 3.10 or newer. From the repository root:

```bash
cd semester-1-project
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r code/requirements.txt
```

On Windows, activate with `.venv\Scripts\activate` instead.

## Run

JSON only (default):

```bash
python code/main_scanner.py --url "https://example.com"
```

JSON plus HTML:

```bash
python code/main_scanner.py --url "https://example.com" --html
```

Choose a filename:

```bash
python code/main_scanner.py --url "https://example.com" --html --output results/example.json
```

Both files go into `results/` by default, with the same unique basename and `.json` / `.html` extensions. A custom `--output` path is relative to your current working directory; HTML is saved beside it. Default paths and the bundled database work from any directory. Open the HTML file directly in a browser; no server or internet is required to view it.

Without `--html`, the report module is not loaded and no HTML is generated. JSON is saved first, including when a scan is blocked or incomplete. A failed HTML export never deletes the JSON. Existing files supplied explicitly through `--output` are overwritten; default filenames are unique.

Exit codes: `0` = all five checks completed, `2` = incomplete/blocked scan or invalid CLI arguments, `1` = execution/output/report failure. Unreachable or blocked pages are reported as incomplete, not as clean scans.

The scanner runs locally but needs network access to the website and its JavaScript assets. It uses the bundled CSV snapshot for frontend CVEs, with no automatic updates. No Azure SDK, credentials, Terraform, or API gateway are required. The unchanged frontend script still contains a dormant Azure loader; the orchestrator disables its environment trigger and always uses the CSV. Original public-target safety checks remain enabled.

Generated results stay on your computer and are ignored by Git; the tracked placeholder keeps the results folder visible after cloning.

## Verify

```bash
python -m unittest discover -s code/tests -v
```

These integration tests use a local fixture server, run the real five scanners, verify CVE matching and JSON/HTML output, and exercise incomplete scans and HTML escaping. The private-target override is enabled only in the fixture subprocesses.
