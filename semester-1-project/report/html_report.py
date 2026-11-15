"""Offline HTML reporting for the five Semester 1 checks (standard library only)."""
from html import escape
from pathlib import Path

LABELS = {
    "test_01_secrets": "Secrets",
    "test_02_frontend_libs": "Frontend Libraries",
    "test_03_cookies": "Cookies",
    "test_05_security_headers": "Security Headers",
    "test_08_cors": "CORS",
}


def text(value):
    return escape(str(value if value is not None else "—"), quote=True)


def render_report(result, modules):
    """Escape all scan content and restrict the report to the selected modules."""
    allowed = tuple(name for name in modules if name in LABELS)
    tests = result.get("tests", {})
    sections = []
    for name in allowed:
        test = tests.get(name, {})
        status = test.get("status", "not run")
        findings = test.get("findings", [])
        items = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            details = "".join(
                f"<dt>{text(key.replace('_', ' ').title())}</dt><dd>{text(value)}</dd>"
                for key, value in finding.items() if key not in {"title", "severity"}
            )
            items.append(
                f'<details><summary><span class="severity">{text(finding.get("severity", "info"))}</span> '
                f'{text(finding.get("title", "Finding"))}</summary><dl>{details}</dl></details>'
            )
        empty = "No findings reported." if status == "complete" else "Check did not complete; no clean result can be inferred."
        error = f'<p class="error">{text(test["fatal_error"])}</p>' if test.get("fatal_error") else ""
        sections.append(
            f'<section><header><h2>{text(LABELS[name])}</h2><span class="status">{text(status)}</span></header>'
            f'<p class="muted">{len(items)} findings · {text(test.get("duration_seconds"))} seconds</p>'
            f'{error}{"".join(items) or f"<p>{empty}</p>"}</section>'
        )
    complete = sum(tests.get(name, {}).get("status") == "complete" for name in allowed)
    note = result.get("coverage_note") or "Results cover only the five Semester 1 checks."
    errors = result.get("errors", [])
    error_html = '<section><h2>Scan errors</h2><ul>' + ''.join(f'<li>{text(e)}</li>' for e in errors) + '</ul></section>' if errors else ''
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Semester 1 Scan — {text(result.get('url'))}</title>
<style>
:root{{font-family:system-ui,sans-serif;color:#17243b;background:#eef2f6;line-height:1.6}}
*{{box-sizing:border-box}}body{{margin:0}}main{{max-width:1050px;margin:auto;padding:40px 22px}}
.banner{{background:#142b45;color:#fff;border-radius:18px;padding:30px;margin-bottom:24px}}
h1{{font-size:2rem;margin:0 0 8px}}h2{{font-size:1.2rem;margin:0}}p{{margin:10px 0}}
.kicker{{font-size:.8rem;letter-spacing:.15em;text-transform:uppercase;color:#81ddd3}}
.url{{overflow-wrap:anywhere;color:#dce9f5}}.stats{{display:flex;flex-wrap:wrap;gap:24px;margin-top:24px}}
.stats strong{{font-size:1.8rem;display:block}}.stats span{{font-size:.85rem;color:#c9d7e5}}
section{{background:white;border:1px solid #dce3eb;border-radius:14px;padding:22px;margin:18px 0}}
header{{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap}}
.status,.severity{{border-radius:6px;background:#eaf0f6;padding:3px 10px;font-size:.8rem;font-weight:650}}
.muted,footer{{color:#58687b;font-size:.9rem}}details{{border-top:1px solid #e2e8f0;padding:14px 0}}
summary{{cursor:pointer;font-weight:600;overflow-wrap:anywhere}}dl{{margin:14px 0 0}}dt{{font-weight:650;font-size:.85rem;color:#526175}}
dd{{margin:0 0 12px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:.9rem}}.error{{color:#a52626;overflow-wrap:anywhere}}
.notice{{border-left:4px solid #258b83;padding-left:16px}}li{{overflow-wrap:anywhere}}
@media print{{body{{background:white}}main{{padding:0}}section{{break-inside:avoid}}.banner{{color:#17243b;background:#eef2f6}}.url,.stats span{{color:#17243b}}}}
</style></head><body><main>
<div class="banner"><div class="kicker">Graduation Project · Semester 1</div><h1>Website Security Scan</h1>
<p class="url">{text(result.get('url'))}</p><div class="stats">
<div><strong>{complete}/{len(allowed)}</strong><span>Checks completed</span></div>
<div><strong>{text(result.get('total_findings', 0))}</strong><span>Deduplicated findings</span></div>
<div><strong>{text(result.get('score'))}</strong><span>Score · Grade {text(result.get('grade'))}</span></div>
</div></div>
<p class="notice">{text(note)} Score reliability: {'reliable' if result.get('grade_reliable') else 'limited / incomplete'}.</p>
<p class="muted">Scan ID: {text(result.get('scanId'))}<br>Started: {text(result.get('start_time'))} · Duration: {text(result.get('duration_seconds'))} seconds</p>
{''.join(sections)}{error_html}
<footer>Five checks: Secrets, Frontend Libraries, Cookies, Security Headers, CORS. Per-check findings may overlap; the JSON includes the deduplicated result.</footer>
</main></body></html>'''


def write_report(result, destination, modules):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_report(result, modules), encoding="utf-8")
    return destination
