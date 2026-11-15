# Tests — current integration coverage

From `semester-1-project/`:

```bash
python -m unittest discover -s code/tests -v
```

`test_cli.py` starts a standard-library HTTP server on an available loopback port. Subprocesses run the actual orchestrator and five scanners with a fixture-only private-target override. The page includes a synthetic jQuery 3.3.1 signature and a cookie; OPTIONS responds with a wildcard CORS header. No live credential verification or external website is needed.

| Test | Main assertion |
| --- | --- |
| `test_json_only_and_local_database` | Exactly five completed modules, a frontend CVE finding, no HTML; an inherited cloud endpoint does not divert the CSV path. |
| `test_html_and_json` | Both files exist and the five expected report sections appear. |
| `test_blocked_page_still_saves_both` | HTTP 403 produces zero completed checks, exit 2 and incomplete report text. |
| `test_report_escapes_target_content_and_filters_modules` | Markup is escaped and unrelated module findings are excluded. |
| `test_default_results_directory_and_optional_report` | Default output is project-relative; no report module is needed for JSON; failed HTML export preserves JSON. |
| `test_invalid_output_extension_rejected` | Non-JSON output extension is rejected before creating a result. |

These assertions do not check every emitted finding or every detector decision. The CVE assertion checks that a CVE finding exists, not an independently reviewed complete list of correct CVEs. See [validation](../../validation/README.md) for the proposed positive/negative detector benchmark and recorded execution.
