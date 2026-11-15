# Report — optional offline HTML

`html_report.py` turns a scan result into a self-contained HTML document with inline CSS. It performs no scanning, cloud calls, template downloads or score recalculation.

## Call path

```text
main_scanner.py --url ... --html
  → run_scout(...)
  → save JSON
  → dynamically load report/html_report.py
  → write_report(result, JSON path with .html suffix, SCANNER_MODULES)
```

Without `--html`, this module is not imported. Both outputs normally live in `../results/`. When a custom JSON path is used, HTML is written beside it. A renderer failure produces exit code 1 after JSON has already been saved.

## Functions

| Function | Contract |
| --- | --- |
| `text(value)` | Converts a value to escaped HTML text; `None` becomes an em dash. Quotes and markup are escaped. |
| `render_report(result, modules)` | Returns an HTML string. Selects module names that are present in the fixed `LABELS` map; renders their raw findings and status. Does not write files. |
| `write_report(result, destination, modules)` | Creates the output parent directory, writes UTF-8 HTML and returns the destination `Path`. |

The CLI supplies exactly the five supported module names. Sections cover Secrets, Frontend Libraries, Cookies, Security Headers and CORS. Missing results display “not run”; incomplete checks do not display a clean-result claim.

The top summary uses the already computed combined count, score and grade. Section bodies use `tests[module].findings`, so they are not a second view of the normalized/deduplicated array. See the [result schema](../results/README.md).

## Content and display

The document includes URL, scan ID, time/duration, completion count, combined finding count, score/grade, coverage note, five check sections, expandable evidence and scan errors. No JavaScript or remote assets are required. Open the file directly in a browser; expand findings to inspect details. Escaping is covered by an automated test using hostile-looking markup in target content.

## Hashes: three different concepts

- **Report source fingerprint:** SHA-256 of `html_report.py` identifies the renderer bytes used for an experiment. It does not prove detection accuracy.
- **Generated report checksum:** SHA-256 of a particular HTML file identifies that exact artifact. It changes when content, timestamps, scan IDs or rendering change. It is not embedded automatically.
- **Finding ID:** the truncated hash assigned by the orchestrator to a finding is a grouping identifier, not an HTML checksum.

Renderer SHA-256 at this documentation revision:

```text
8702f6a5bd1bf2329a4900232a005b3ed6e77a2492508eace7a5f09d552814b3
```

From `semester-1-project/`, reproduce or calculate an artifact checksum with:

```bash
python -c "import hashlib; from pathlib import Path; print(hashlib.sha256(Path('report/html_report.py').read_bytes()).hexdigest())"
python -c "import hashlib; from pathlib import Path; print(hashlib.sha256(Path('results/example.html').read_bytes()).hexdigest())"
```

The second command requires that example output to exist. After changing renderer code, update this fingerprint and rerun the HTML tests. A checksum establishes identity only when compared with a trusted recorded value; it is not a digital signature.

## Tests

```bash
python -m unittest discover -s code/tests -v
```

Assertions cover optional generation, five section headings, target-content escaping, exclusion of unrelated modules, incomplete-state messaging, and JSON preservation when the renderer is unavailable. They do not constitute a browser visual-layout audit.
