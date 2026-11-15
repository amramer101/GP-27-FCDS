#!/usr/bin/env python3
"""Semester 1 local orchestrator: five original Bravo6 scanners and local JSON output."""
import asyncio
import contextlib
import hashlib
import importlib.util
import inspect
import io
import ipaddress
import json
import logging
import math
import os
import socket
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
from aiohttp.resolver import ThreadedResolver
from bs4 import BeautifulSoup

# ------------------------------------------------------------------------------
# Configuration & Constants
# ------------------------------------------------------------------------------
USER_AGENT = "Bravo6-Scanner/8.5"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=15)
MAX_RETRIES = 3
RETRY_BACKOFF = 2

# Retry policy for the pre-flight fetch (fetch_main_page_and_analyze) only.
# Live-confirmed (cross-tool-calibration diagnosis, 2026-09-16): running many
# scans concurrently (asyncio.gather over a site batch) causes a fraction of
# pre-flight fetches to hit REQUEST_TIMEOUT purely from local contention
# (event loop / DNS resolver thread pool / TLS handshake queueing) even
# against targets that are completely healthy and respond in well under a
# second in isolation -- reproduced directly: 1 of 10 concurrent requests to
# a healthy site timed out at the full 15s ceiling with no other cause.
# Deliberately separate from MAX_RETRIES/RETRY_BACKOFF above (unused
# elsewhere, and tuned differently) since this retry is specifically for
# transient network failures on the one request every scout's
# representativeness gate depends on -- not a general-purpose retry knob.
PREFLIGHT_MAX_RETRIES = 2
PREFLIGHT_RETRY_BACKOFF_SECONDS = (0.5, 1.5)

# Default timeouts per module (seconds)
SCANNER_MODULES = ('test_01_secrets', 'test_02_frontend_libs', 'test_03_cookies', 'test_05_security_headers', 'test_08_cors')
DEFAULT_TIMEOUTS = {'test_01_secrets': 60, 'test_02_frontend_libs': 45, 'test_03_cookies': 15, 'test_05_security_headers': 20, 'test_08_cors': 15}

# ------------------------------------------------------------------------------
# Logging Configuration
# ------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-7s | %(name)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("Bravo6-Orchestrator")

# ------------------------------------------------------------------------------
# SSRF / Target Safety
# ------------------------------------------------------------------------------
class SSRFBlockedError(Exception):
    """Raised when a target hostname/IP resolves to (or is) a non-public
    address -- private, loopback, link-local (which includes the cloud
    metadata endpoint 169.254.169.254), reserved, or multicast."""

    def __init__(self, host: str, address: str):
        self.host = host
        self.address = address
        super().__init__(
            f"Refusing to connect to '{host}' -- resolves to non-public address {address}"
        )


def _is_ip_safe(ip: "ipaddress._BaseAddress") -> bool:
    """Stdlib classification only -- deliberately not hand-rolled CIDR
    checks. is_private already subsumes loopback/link-local/reserved for
    both address families in Python's ipaddress module, but each is listed
    explicitly here so the intent (and the metadata-endpoint case
    specifically) is legible without reading CPython's source.

    BRAVO6_VALIDATION_ALLOW_PRIVATE_TARGETS is a local synthetic-benchmark flag
    ONLY. It must NEVER be set in any deployed or production environment; the
    default path remains strictly deny-private/loopback/reserved addresses.
    """
    if os.environ.get("BRAVO6_VALIDATION_ALLOW_PRIVATE_TARGETS", "").strip().lower() in {"1", "true", "yes", "on"}:
        return True
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def is_target_address_safe(hostname_or_ip: str) -> bool:
    """True if it's safe to issue an outbound scan request to hostname_or_ip.

    A bare IP literal is checked directly. A hostname is resolved (A and
    AAAA) and EVERY returned address must be safe -- one unsafe answer
    among several fails the whole lookup, since a scanning HTTP client has
    no reliable way to force which of several returned addresses it will
    actually connect to.

    An unresolvable hostname returns True: nothing unsafe has been proven,
    and the connection attempt will simply fail on its own right after.
    """
    try:
        return _is_ip_safe(ipaddress.ip_address(hostname_or_ip))
    except ValueError:
        pass  # not a literal IP -- resolve it below

    try:
        infos = socket.getaddrinfo(hostname_or_ip, None)
    except socket.gaierror:
        return True

    addresses = {info[4][0] for info in infos}
    if not addresses:
        return True

    return all(_is_ip_safe(ipaddress.ip_address(addr)) for addr in addresses)


class SSRFSafeConnector(aiohttp.TCPConnector):
    """Closes a gap SSRFSafeResolver alone can't cover: aiohttp's own
    TCPConnector._resolve_host() special-cases a literal IP host and
    returns it directly WITHOUT ever calling the resolver (verified against
    aiohttp 3.14.1's source -- `if is_ip_address(host): return [...]`, no
    resolver call at all on that branch). A target given as a bare IP, or
    an HTTP redirect Location pointing at one, would sail straight past
    SSRFSafeResolver on that path. _resolve_host() is called uniformly
    for the initial connection and every redirect hop, so overriding it
    here covers a literal-IP host the same way the resolver covers a
    hostname. Hostnames are deliberately NOT re-checked here (left to
    SSRFSafeResolver): checking them again with a second, independent
    getaddrinfo() call here would open a TOCTOU/DNS-rebinding gap between
    what this check saw and what the resolver actually connects to.
    """

    async def _resolve_host(self, host, port, traces=None):
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None and not _is_ip_safe(ip):
            raise SSRFBlockedError(host, host)
        return await super()._resolve_host(host, port, traces)


class SSRFSafeResolver(ThreadedResolver):
    """Drop-in replacement for aiohttp's default resolver that rejects any
    DNS answer pointing at a non-public address, wired into the single
    aiohttp.TCPConnector every scout's requests share (see run_scout()).

    This is also what makes the check apply to redirects, not just the
    initial hostname: aiohttp opens a fresh connection -- and therefore
    performs a fresh resolve() through this same connector/resolver -- for
    every redirect hop, including a hop to a different host. A publicly
    resolving hostname that 302s to an internal address is blocked here,
    at the redirect target, the same way the initial target would be.
    """

    async def resolve(self, host, port=0, family=socket.AF_INET):
        hosts = await super().resolve(host, port, family)
        for h in hosts:
            if not _is_ip_safe(ipaddress.ip_address(h["host"])):
                raise SSRFBlockedError(host, h["host"])
        return hosts


# Canonical, shared table of known sensitive paths, owned by Orchestrator
# Expanded to be a superset including all test_06_info_disclosure targets
COMMON_SENSITIVE_PATHS = [
    # Environment & Secrets
    "/.env", "/.aws/credentials", "/.npmrc", "/.htpasswd",
    # Version Control
    "/.git/config", "/.git/HEAD", "/.svn/entries",
    # Server & PHP Info
    "/server-status", "/phpinfo.php", "/info.php",
    # Config files & Backups
    "/config.php", "/config.php.bak", "/wp-config.php", "/wp-config.php.bak",
    "/web.config", "/docker-compose.yml",
    # DB Tools
    "/adminer.php",
    # IDEs & OS files
    "/.vscode/settings.json", "/.DS_Store",
    # Package Managers
    "/composer.json", "/package.json"
]

# ------------------------------------------------------------------------------
# Context & Dependency Injection
# ------------------------------------------------------------------------------
@dataclass
class ScannerContext:
    """
    Centralized context for dependency injection across all plugins.
    Passed as a single explicit parameter to all scouts.
    """
    url: str
    session: aiohttp.ClientSession
    config: Dict[str, Any] = field(default_factory=dict)

    # Shared signal telling scouts if response is representative
    page_is_representative: bool = True
    waf_challenge_detected: Optional[str] = None

    # Set when the pre-flight fetch was refused by SSRFSafeResolver -- the
    # target (or something it redirected to) resolved to a non-public
    # address. run_scout() checks this immediately after the pre-flight
    # fetch and aborts the scan before any scout runs.
    ssrf_blocked: bool = False
    ssrf_block_reason: Optional[str] = None

    # Path enumeration ownership belongs here
    sensitive_paths: List[str] = field(default_factory=lambda: COMMON_SENSITIVE_PATHS)

    metrics: Dict[str, Any] = field(default_factory=lambda: {
        "http_requests": 0,
        "cache_hits": 0,
        "modules_executed": 0,
        "errors": [],
        # Additive instrumentation only (no scoring/detection impact):
        # base_url_gets  -- actual HTTP GETs issued against ctx.url itself
        #                   (expected: exactly 1, the pre-flight fetch).
        # cache_reads    -- number of cache-consuming scouts (test_01/02/03/
        #                   05/06/09) that served their main-page needs from
        #                   ctx.main_page_cache instead of issuing a fetch.
        "base_url_gets": 0,
        "cache_reads": 0
    })

    main_page_cache: Dict[str, Any] = field(default_factory=dict)

    # Centralized event-gated Cache
    js_cache: Dict[str, str] = field(default_factory=dict)
    _js_fetch_events: Dict[str, asyncio.Event] = field(default_factory=dict)

    async def fetch_js(self, js_url: str) -> str:
        """Fetch JS file with caching and asyncio Event deduplication."""
        if js_url in self.js_cache:
            self.metrics["cache_hits"] += 1
            logger.debug(f"Cache HIT for JS: {js_url}")
            return self.js_cache[js_url]

        if js_url in self._js_fetch_events:
            await self._js_fetch_events[js_url].wait()
            if js_url in self.js_cache:
                self.metrics["cache_hits"] += 1
                logger.debug(f"Cache HIT (waited) for JS: {js_url}")
                return self.js_cache[js_url]

        logger.debug(f"Cache MISS for JS: {js_url}")
        event = asyncio.Event()
        self._js_fetch_events[js_url] = event

        try:
            self.metrics["http_requests"] += 1
            async with self.session.get(js_url, timeout=10) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    self.js_cache[js_url] = text
                    return text
        except Exception as e:
            logger.debug(f"Failed to fetch JS {js_url}: {e}")
        finally:
            event.set()
            self._js_fetch_events.pop(js_url, None)
        return ""

# ------------------------------------------------------------------------------
# Initialization & Pre-Flight
# ------------------------------------------------------------------------------
def detect_waf_and_representativeness(status: int, headers: Dict[str, Any], html: str) -> tuple:
    """Pure WAF/challenge-page detection, factored out of
    fetch_main_page_and_analyze() so it's directly unit-testable without
    mocking an HTTP session. Returns (waf_name_or_None, page_is_representative).
    """
    headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
    html_lower = html.lower()

    waf = None
    rep = True

    if "cf-ray" in headers_lower or "cloudflare" in headers_lower.get("server", ""):
        waf = "Cloudflare"
    elif "x-sucuri-id" in headers_lower: waf = "Sucuri"
    elif "x-amz-cf-id" in headers_lower: waf = "AWS CloudFront"
    # Live-confirmed regression: elcorteingles.es's real Akamai block page
    # ("Access Denied", Server: AkamaiGHost) has neither the
    # x-akamai-transformed header nor the literal word "akamai" anywhere in
    # its 374-byte body -- only in the Server header value ("AkamaiGHost").
    # Check that too, mirroring how the Cloudflare branch above already
    # checks the Server header's content, not just specific header names.
    elif "x-akamai-transformed" in headers_lower or "akamai" in headers_lower.get("server", ""): waf = "Akamai"
    elif "x-iinfo" in headers_lower or "x-cdn" in headers_lower: waf = "Imperva/Incapsula"

    if status >= 400:
        rep = False

    if "cf-chl" in html_lower or "cf-mitigated" in html_lower or "just a moment..." in html_lower:
        waf = "Cloudflare"
        rep = False
    elif "akamai" in html_lower and "access denied" in html_lower:
        rep = False
        waf = "Akamai"
    elif "incapsula incident id" in html_lower:
        rep = False
        waf = "Imperva/Incapsula"

    return waf, rep


def _format_fetch_error(e: BaseException) -> str:
    """type(e).__name__ is always included, never just str(e) alone --
    asyncio.TimeoutError (and aiohttp.ServerTimeoutError, which subclasses
    it) stringify to '' with no message, which previously left
    ctx.main_page_cache["error"] indistinguishable from an unset/empty
    value. "TimeoutError: " (trailing, no message) is expected and fine --
    the type name alone is the signal that matters here."""
    return f"{type(e).__name__}: {e}"


async def fetch_main_page_and_analyze(ctx: ScannerContext):
    """Fetch main page once, store it, and analyze for WAF/Challenge Pages.

    Retries up to PREFLIGHT_MAX_RETRIES times, with a short fixed backoff
    (PREFLIGHT_RETRY_BACKOFF_SECONDS), but ONLY for transient failures --
    a timeout or connection error where no response was ever received.
    A clean HTTP response is never retried even when it's a WAF/anti-bot
    block (e.g. a 401): aiohttp does not raise on a non-2xx status, so that
    case never enters the except branch below at all -- it's a real,
    deterministic result that detect_waf_and_representativeness() below is
    responsible for classifying, not a fetch failure to retry.
    """
    url = ctx.url
    ctx.main_page_cache = {"status": 0, "html": "", "headers": {}, "set_cookie_headers": [], "soup": None, "error": None}
    ctx.metrics["base_url_gets"] = ctx.metrics.get("base_url_gets", 0) + 1

    attempt = 0
    while True:
        try:
            ctx.metrics["http_requests"] += 1
            async with ctx.session.get(url) as resp:
                status = resp.status
                headers = dict(resp.headers)
                # dict(resp.headers) keeps only ONE value per header name, so a response
                # setting multiple cookies (the common case) silently loses all but one
                # Set-Cookie header here. Cookie-auditing scouts need every cookie, not
                # just the last one, so also capture the raw multi-value list separately
                # -- additive only, "headers" above is untouched for existing consumers.
                set_cookie_headers = resp.headers.getall("Set-Cookie", [])
                html = await resp.text()

                ctx.main_page_cache["status"] = status
                ctx.main_page_cache["headers"] = headers
                ctx.main_page_cache["set_cookie_headers"] = set_cookie_headers
                ctx.main_page_cache["html"] = html
                ctx.main_page_cache["soup"] = BeautifulSoup(html, "html.parser")

                # WAF and Representative Page Gate
                waf, rep = detect_waf_and_representativeness(status, headers, html)
                ctx.waf_challenge_detected = waf
                ctx.page_is_representative = rep
            return

        except SSRFBlockedError as e:
            # Not transient -- retrying changes nothing about where the
            # target resolves -- and retrying would also mean re-running
            # the SSRF check redundantly for no benefit.
            ctx.main_page_cache["error"] = _format_fetch_error(e)
            ctx.page_is_representative = False
            ctx.ssrf_blocked = True
            ctx.ssrf_block_reason = str(e)
            return

        except (asyncio.TimeoutError, aiohttp.ClientConnectionError) as e:
            if attempt < PREFLIGHT_MAX_RETRIES:
                backoff = PREFLIGHT_RETRY_BACKOFF_SECONDS[min(attempt, len(PREFLIGHT_RETRY_BACKOFF_SECONDS) - 1)]
                logger.warning(
                    f"Pre-flight fetch attempt {attempt + 1}/{PREFLIGHT_MAX_RETRIES + 1} for {url} "
                    f"failed ({_format_fetch_error(e)}); retrying in {backoff}s"
                )
                attempt += 1
                await asyncio.sleep(backoff)
                continue
            ctx.main_page_cache["error"] = _format_fetch_error(e)
            ctx.page_is_representative = False
            return

        except Exception as e:
            ctx.main_page_cache["error"] = _format_fetch_error(e)
            ctx.page_is_representative = False
            return

def discover_plugins() -> List[Any]:
    plugins = []
    current_dir = Path(__file__).resolve().parent
    for name in SCANNER_MODULES:
        filepath = current_dir / (name + ".py")
        module_name = filepath.stem
        try:
            spec = importlib.util.spec_from_file_location(module_name, filepath)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            if hasattr(module, "run") and inspect.iscoroutinefunction(module.run):
                plugins.append(module)
                logger.debug(f"Loaded plugin: {module_name}")
        except Exception as e:
            raise RuntimeError(f"Failed to load required scanner {module_name}: {e}") from e
    return plugins

# ------------------------------------------------------------------------------
# Finding Normalization & Schema Enforcement
# ------------------------------------------------------------------------------
def get_confidence_tier(raw_conf: Any) -> str:
    """Map numeric values or unknown strings to the 4 strictly permitted tiers."""
    allowed = ["verified-live", "verified-static", "plausible-unconfirmed", "informational"]
    if isinstance(raw_conf, str) and raw_conf in allowed:
        return raw_conf
    try:
        val = int(raw_conf)
        if val >= 90: return "verified-live"
        if val >= 70: return "verified-static"
        if val >= 30: return "plausible-unconfirmed"
        return "informational"
    except (ValueError, TypeError):
        return "informational"

def normalize_finding(raw: Dict[str, Any], module_name: str, index: int) -> Dict[str, Any]:
    """
    Enforce strict 12+1-field schema and preserve location verbatim.
    """
    title = raw.get("title") or raw.get("type") or raw.get("cve") or "Unknown Finding"
    cwe = raw.get("cwe") or ""
    owasp = raw.get("owasp") or ""

    location = raw.get("location") or raw.get("header") or raw.get("exact_js_file") or ""

    stable_fields = {
        "module": module_name,
        "title": title,
        "cwe": cwe,
        "owasp": owasp,
        "location": location
    }
    stable_str = json.dumps(stable_fields, sort_keys=True, default=str)
    finding_id = hashlib.sha256(stable_str.encode()).hexdigest()[:12]

    severity = (raw.get("severity") or "info").lower()
    if severity not in ["critical", "high", "medium", "low", "info"]:
        severity = "info"

    confidence = get_confidence_tier(raw.get("confidence", 50))

    evidence_parts = []
    if raw.get("evidence"): evidence_parts.append(str(raw["evidence"]))
    if raw.get("context"): evidence_parts.append(f"Context: {raw['context']}")
    if raw.get("value_masked"): evidence_parts.append(f"Value: {raw['value_masked']}")

    evidence = "\n".join(evidence_parts) if evidence_parts else json.dumps(raw, default=str)[:500]
    poc = raw.get("poc") or raw.get("poc_curl") or raw.get("poc_js") or "Manual verification required."
    remediation = raw.get("remediation") or "Consult security team for remediation."
    detection_method = raw.get("detection_method") or raw.get("source") or module_name

    # Extract tier safely from raw or nested raw["raw_data"]
    raw_tier = raw.get("tier")
    if not raw_tier and isinstance(raw.get("raw_data"), dict):
        raw_tier = raw.get("raw_data").get("tier")

    # NOTE: the scout's raw finding dict is deliberately NOT echoed back into
    # the normalized finding. The 12 explicit fields above (plus `tier`) are
    # the single source of truth; keeping a verbatim `raw_data` copy only
    # duplicated every field, roughly doubled the persisted result size, and
    # re-stored free-text evidence/context that a scout might have failed to
    # redact (see test_01_secrets._redact_secrets). `tier` is preserved as a
    # first-class field so compute_bravo6_score() still has everything it
    # needs.
    return {
        "id": finding_id,
        "module": module_name,
        "title": str(title)[:200],
        "severity": severity,
        "confidence": confidence,
        "cwe": str(cwe),
        "owasp": str(owasp),
        "location": str(location)[:500],
        "evidence": str(evidence)[:1000],
        "poc": str(poc)[:500],
        "remediation": str(remediation)[:500],
        "detection_method": str(detection_method)[:100],
        "tier": str(raw_tier)[:50] if raw_tier else "",
    }

# ------------------------------------------------------------------------------
# Deduplication & Filtering
# ------------------------------------------------------------------------------
_CONF_RANK = {"verified-live": 4, "verified-static": 3, "plausible-unconfirmed": 2, "informational": 1}
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Location MUST be included in the deduplication key to preserve distinct resources."""
    best: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        loc = f.get("location", "").strip().lower()
        key = f"{f['module']}|{f['title']}|{f['cwe']}|{f['owasp']}|{loc}"

        if key not in best:
            best[key] = f
            continue

        existing = best[key]
        f_conf = _CONF_RANK.get(f["confidence"], 0)
        ex_conf = _CONF_RANK.get(existing["confidence"], 0)

        if f_conf > ex_conf:
            best[key] = f
        elif f_conf == ex_conf:
            if _SEV_RANK.get(f["severity"], 0) > _SEV_RANK.get(existing["severity"], 0):
                best[key] = f
    return list(best.values())

# ------------------------------------------------------------------------------
# Unified Scoring Methodology
# ------------------------------------------------------------------------------
def compute_bravo6_score(
    findings: List[Dict[str, Any]],
    waf: Optional[str] = None,
    tests_run: Optional[int] = None,
    modules_discovered: Optional[int] = None,
    page_is_representative: bool = True,
) -> Dict[str, Any]:
    """
    Two-Tier Scoring Calibration Fix:
    Prevent heavily weighing bleeding-edge headers like COOP, COEP, etc.
    (Bug 1 Fix: reads directly from raw_data tier).

    Coverage-awareness fix: `score`/`grade` are computed exactly as before
    (unchanged for any fully-covered scan, e.g. tests_run == modules_discovered
    and page_is_representative == True) so existing consumers reading those two
    fields keep seeing identical values. Additive-only: this also returns
    `grade_reliable` (False when the page wasn't representative -- e.g. a WAF/
    challenge page -- or when fewer modules ran than were discovered) and a
    human-readable `coverage_note` explaining why, so a confident-looking grade
    can no longer be produced from a scan that examined little of the target.

    Score-resolution fix: `score` stays clamped to [0, 100] as before (needed
    for the letter-grade thresholds and any consumer expecting a 0-100 value).
    A very small number of critical/high findings is enough to reach that
    floor, after which two sites with very different real-world risk (e.g. a
    site missing every baseline header outright vs. a mostly-solid site with
    a couple of inflated findings) become indistinguishable at "0/F". The
    additive `raw_score` field is NOT clamped at 0, so sites that both floor
    the visible `score` can still be told apart by how far below the floor
    their actual deduction total falls.
    """
    BASE_PENALTY = {"critical": 30, "high": 15, "medium": 5, "low": 2, "info": 0}

    tier1_deduction = 0.0
    tier2_deduction = 0.0

    for f in findings:
        sev = f["severity"].lower()
        penalty = BASE_PENALTY.get(sev, 0)

        # Read the tier assigned natively by the scout. normalize_finding()
        # flattens both the top-level and the nested raw_data["tier"] form
        # into this single field; the nested-dict fallback is kept only for
        # callers that pass un-normalized findings straight in (some tests).
        raw_tier = f.get("tier", "")
        if not raw_tier and isinstance(f.get("raw_data"), dict):
            raw_tier = f["raw_data"].get("tier", "")

        is_tier2 = (raw_tier == "hardening")

        if is_tier2:
            tier2_deduction += penalty
        else:
            tier1_deduction += penalty

    # Tier 2 deduction capped so it never alone tanks a score
    tier2_deduction = min(tier2_deduction, 10.0)

    total_deduction = tier1_deduction + tier2_deduction
    raw_score = round(100.0 - total_deduction, 2)
    score = max(0.0, 100.0 - total_deduction)
    int_score = round(score)

    if int_score >= 85: grade = "A"
    elif int_score >= 75: grade = "B"
    elif int_score >= 65: grade = "C"
    elif int_score >= 55: grade = "D"
    else: grade = "F"

    coverage_gaps = []
    if not page_is_representative:
        coverage_gaps.append("page was not representative (WAF/challenge/error response detected)")
    if (
        tests_run is not None
        and modules_discovered is not None
        and tests_run < modules_discovered
    ):
        coverage_gaps.append(f"only {tests_run}/{modules_discovered} scan modules completed")

    grade_reliable = len(coverage_gaps) == 0
    coverage_note = ("Grade may be unreliable: " + "; ".join(coverage_gaps) + ".") if coverage_gaps else None

    return {
        "score": int_score,
        "raw_score": raw_score,
        "grade": grade,
        "deductions": {
            "tier1": round(tier1_deduction, 2),
            "tier2": round(tier2_deduction, 2)
        },
        "waf_detected": waf is not None,
        "grade_reliable": grade_reliable,
        "coverage_note": coverage_note
    }

async def run_scout(url: str, scan_id: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    start_time = time.time()
    start_time_iso = datetime.now().isoformat()

    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    config = dict(config or {})
    config["cve_csv_url"] = str(Path(__file__).resolve().parent / "data" / "cve_database_v2.csv")
    if not Path(config["cve_csv_url"]).is_file():
        raise FileNotFoundError(config["cve_csv_url"])
    # The original frontend scanner prioritizes this environment setting.
    # Disable it here so this standalone application always uses its local CSV.
    os.environ.pop("CVE_TABLE_ENDPOINT", None)
    logger.info(f"Starting Bravo6 Enterprise Scan for {url}")

    # SSRFSafeResolver is shared by every request this session makes --
    # the pre-flight fetch below, every scout's ctx.session.get/head/
    # options() call, and (critically) any redirect hop any of those
    # requests follows -- since it's installed on the one connector the
    # whole session uses, not called ad hoc per request.
    #
    # request_timeout_seconds is config-overridable (default: the 15s in
    # REQUEST_TIMEOUT, unchanged) rather than hand-raised here. Raising the
    # per-request ceiling doesn't fix the contention a large concurrent batch
    # causes -- it just gives each stuck request more slack while holding
    # its event-loop task/DNS-resolver-thread slot longer, which can make
    # contention worse under sustained high concurrency, not better. The
    # lever that actually matters at 500-800-site scale is bounding how many
    # scans run at once (e.g. a semaphore in the batch harness), which is
    # out of this module's scope. This override exists so a batch harness
    # that DOES cap concurrency can still raise the ceiling for a slower
    # target population without a code change here.
    session_timeout = aiohttp.ClientTimeout(total=config.get("request_timeout_seconds", REQUEST_TIMEOUT.total))
    connector = SSRFSafeConnector(ssl=True, limit=20, limit_per_host=10, resolver=SSRFSafeResolver())
    async with aiohttp.ClientSession(
        timeout=session_timeout,
        headers={"User-Agent": USER_AGENT},
        connector=connector
    ) as session:

        ctx = ScannerContext(url=url, session=session, config=config)
        await fetch_main_page_and_analyze(ctx)

        if ctx.ssrf_blocked:
            logger.warning(f"Blocked unsafe target {url}: {ctx.ssrf_block_reason}")
            return {
                "scanId": scan_id,
                "url": url,
                "status": "blocked_ssrf",
                "ssrf_block_reason": ctx.ssrf_block_reason,
                "start_time": start_time_iso,
                "end_time": datetime.now().isoformat(),
                "duration_seconds": round(time.time() - start_time, 2),
                "tests_run": 0,
                "total_findings": 0,
                "findings": [],
                "tests": {},
                "waf": None,
                "page_is_representative": False,
                "errors": [ctx.ssrf_block_reason],
                "errors_count": 1,
                "deduplicated_count": 0,
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "score": None,
                "raw_score": None,
                "grade": None,
                "grade_reliable": False,
                "coverage_note": "Scan aborted before any scout ran: target blocked by SSRF safety check.",
                "metrics": ctx.metrics,
            }

        plugins = discover_plugins()
        if not plugins:
            return {"error": "No test plugins found."}

        # FIX 2: Wrapper function to measure time precisely for each coroutine
        #
        # Deliberately does NOT catch asyncio.CancelledError: a caller
        # cancelling this scan (e.g. run_evaluation.py's outer
        # asyncio.wait_for(run_scout(...), OUTER_TIMEOUT_SECONDS) firing on a
        # genuine hang) must actually be able to cancel it. Catching
        # CancelledError here and returning it as an ordinary value made
        # gather() below complete "normally" instead of propagating the
        # cancellation, so run_scout() would return a partial result rather
        # than actually stopping -- defeating the one mechanism meant to
        # catch a hang above the per-module timeouts already enforced by
        # asyncio.wait_for(coro, timeout=timeout_val) below.
        async def _timed(coro, mod_name):
            t0 = time.time()
            try:
                result = await coro
                return mod_name, result, round(time.time() - t0, 2)
            except Exception as e:
                return mod_name, e, round(time.time() - t0, 2)

        test_coroutines = []

        for mod in plugins:
            module_name = mod.__name__
            sig = inspect.signature(mod.run)

            if "ctx" in sig.parameters:
                coro = mod.run(url=url, ctx=ctx) if "url" in sig.parameters else mod.run(ctx)
            elif "url" in sig.parameters:
                coro = mod.run(url=url, ctx=ctx)
            else:
                coro = mod.run(ctx)

            timeout_val = DEFAULT_TIMEOUTS.get(module_name, 60)
            coro_with_timeout = asyncio.wait_for(coro, timeout=timeout_val)

            test_coroutines.append(_timed(coro_with_timeout, module_name))

        # Execute concurrently and fetch correctly tracked timings
        timed_results = await asyncio.gather(*test_coroutines)

        duration = time.time() - start_time
        tests = {}
        all_raw_findings = []
        errors = []
        tests_run = 0

        for mod_name, res, dur_plugin in timed_results:

            if isinstance(res, Exception) or isinstance(res, asyncio.CancelledError):
                err_msg = f"{type(res).__name__}: {res}"
                if isinstance(res, asyncio.TimeoutError):
                    err_msg = f"Timed out after {DEFAULT_TIMEOUTS.get(mod_name, 60)}s"

                errors.append(f"{mod_name}: {err_msg}")
                tests[mod_name] = {
                    "status": "incomplete",
                    "fatal_error": err_msg,
                    "duration_seconds": dur_plugin
                }
                continue

            if isinstance(res, dict):
                if "fatal_error" in res:
                    errors.append(f"{mod_name}: {res['fatal_error']}")
                    tests[mod_name] = {
                        "status": "incomplete",
                        "fatal_error": res["fatal_error"],
                        "duration_seconds": dur_plugin
                    }
                else:
                    tests_run += 1
                    ctx.metrics["modules_executed"] += 1
                    res["status"] = "complete"
                    res["duration_seconds"] = dur_plugin
                    tests[mod_name] = res

                    for key in ["findings", "evidence", "vulnerabilities"]:
                        if key in res and isinstance(res[key], list):
                            for idx, f in enumerate(res[key]):
                                if isinstance(f, dict):
                                    all_raw_findings.append(normalize_finding(f, mod_name, idx))

                    if "details" in res and isinstance(res["details"], dict):
                        ctx.metrics["http_requests"] += res["details"].get("requests_made", 0)
            else:
                err_msg = f"Unexpected return type {type(res).__name__}"
                errors.append(f"{mod_name}: {err_msg}")
                tests[mod_name] = {"status": "incomplete", "fatal_error": err_msg, "duration_seconds": dur_plugin}

        deduplicated = deduplicate_findings(all_raw_findings)

        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in deduplicated:
            sev = f["severity"]
            if sev in summary: summary[sev] += 1

        try:
            score_info = compute_bravo6_score(
                deduplicated,
                ctx.waf_challenge_detected,
                tests_run=tests_run,
                modules_discovered=len(plugins),
                page_is_representative=ctx.page_is_representative,
            )
        except Exception as e:
            logger.error(f"Score computation failed: {e}")
            score_info = {
                "score": 0, "raw_score": 0, "grade": "F", "deductions": {}, "waf_detected": False,
                "grade_reliable": False, "coverage_note": f"Score computation failed: {e}"
            }

        final_result = {
            "scanId": scan_id,
            "url": url,
            "start_time": start_time_iso,
            "end_time": datetime.now().isoformat(),
            "duration_seconds": round(duration, 2),
            "tests_run": tests_run,
            "total_findings": len(deduplicated),
            "findings": deduplicated,
            "tests": tests,
            "waf": ctx.waf_challenge_detected,
            "page_is_representative": ctx.page_is_representative,
            "errors": errors,
            "errors_count": len(errors),
            "deduplicated_count": len(all_raw_findings) - len(deduplicated),
            "summary": summary,
            "score": score_info.get("score"),
            "raw_score": score_info.get("raw_score"),
            "grade": score_info.get("grade"),
            "grade_reliable": score_info.get("grade_reliable", True),
            "coverage_note": score_info.get("coverage_note"),
            "metrics": ctx.metrics
        }

        return final_result

def main():
    import argparse
    import uuid
    from urllib.parse import urlsplit

    parser = argparse.ArgumentParser(description="Run five local security scanners and save JSON.")
    parser.add_argument("--url", required=True, help="Target website URL (https:// is optional)")
    parser.add_argument("--output", type=Path, help="JSON output path; default: results/<host>_<scan-id>.json")
    parser.add_argument("--html", action="store_true", help="Also save an HTML report alongside the JSON")
    args = parser.parse_args()
    url = args.url.strip()
    if not url:
        parser.error("--url must not be empty")
    if "://" not in url:
        url = "https://" + url
    try:
        parsed = urlsplit(url)
        port = parsed.port
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Use an HTTP(S) URL without embedded credentials")
    except ValueError as exc:
        parser.error(str(exc))
    scan_id = str(uuid.uuid4())
    host = "".join(c if c.isalnum() or c in ".-" else "_" for c in parsed.hostname)
    output = args.output or Path(__file__).resolve().parent.parent / "results" / f"{host}_{scan_id}.json"
    if output.suffix.lower() != ".json":
        parser.error("--output must end with .json")
    try:
        result = asyncio.run(run_scout(url, scan_id=scan_id))
        output = output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, RuntimeError) as exc:
        parser.exit(1, f"Scan failed: {exc}\n")
    print(f"JSON saved: {output}")
    if args.html:
        try:
            report_file = Path(__file__).resolve().parent.parent / "report" / "html_report.py"
            spec = importlib.util.spec_from_file_location("semester1_html_report", report_file)
            report = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(report)
            html_path = report.write_report(result, output.with_suffix(".html"), SCANNER_MODULES)
        except Exception as exc:
            parser.exit(1, f"JSON saved, but HTML report failed: {exc}\n")
        print(f"HTML saved: {html_path}")
    print(f"Completed scanners: {result.get('tests_run', 0)}/5; findings: {result.get('total_findings', 0)}")
    return 0 if result.get("tests_run") == 5 else 2


if __name__ == "__main__":
    raise SystemExit(main())
