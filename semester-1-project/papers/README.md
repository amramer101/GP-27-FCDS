# Papers — research background and project positioning

**Reference check: 15 November 2026.** This is a selected historical reading guide, not a systematic literature review or a claim to cover the latest state of the art. Titles, authors, venues and the summaries below were checked against conference/publisher or author-institution sources. Summaries use the official abstracts and relevant paper text; no paper is claimed to have been fully reproduced.

These references justify studying the selected problem categories and help design evaluation. They do not establish that the existing detector code was originally derived from each paper, nor that the project reproduces its method or accuracy. No third-party paper PDFs or historical private experiment datasets are redistributed here.

## Historical progression

| Year | Reference | Main connection |
| --- | --- | --- |
| 2015 | P1 — Cookies Lack Integrity | Cookie security extends beyond the presence of one flag. |
| 2016 | P2 — CSP Is Dead, Long Live CSP! | A deployed security policy can still be ineffective. |
| 2017 | P3 — Thou Shalt Not Depend on Me | Client-side library versions and inclusion paths matter. |
| 2018 | P4 — We Still Don't Have Secure Cross-Domain Requests | CORS needs interpretation of trust and browser behavior. |
| 2019 | P5 — How Bad Can It Git? | Secret discovery requires conservative detection and validation. |

## P1 — Cookies Lack Integrity: Real-World Implications

**Xiaofeng Zheng, Jian Jiang, Jinjin Liang, Haixin Duan, Shuo Chen, Tao Wan and Nicholas Weaver. USENIX Security, 2015, pp. 707–721.** [Official paper record](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/zheng).

The paper investigates cookie injection and integrity problems involving HTTP/HTTPS and related domains, with empirical attacks and browser observations. It discusses mitigations including HSTS. These are historical findings, not claims about every current browser.

**Connection:** motivates examining cookie attributes and transport context together. Our cookie scanner inspects observed response cookies and applies attribute/sensitivity rules; it does not reproduce the paper's injection attacks or browser experiments. **Validation implication:** test secure/insecure configurations and applicability separately; do not call an unauthenticated, cookie-free page proof of safe session handling.

## P2 — CSP Is Dead, Long Live CSP! On the Insecurity of Whitelists and the Future of Content Security Policy

**Lukas Weichselbaum, Michele Spagnuolo, Sebastian Lekies and Artur Janc. ACM CCS, 2016.** [Google Research publication record](https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists-and-the-future-of-content-security-policy/).

The authors analyze deployed CSP policies, identify weaknesses in script-source allowlists, and discuss nonce-based policies and `strict-dynamic`. A header's presence alone is not a sufficient measure of its protection.

**Connection:** supports examining policy content rather than recording only “CSP present.” Our headers module performs selected static checks; it does not reproduce the study's web-scale corpus, endpoint analysis or bypass evaluation. **Validation implication:** include a missing policy, a present-but-weak policy, a relevant restrictive policy and malformed directives. A clean static result must not be described as proof that XSS is impossible.

## P3 — Thou Shalt Not Depend on Me: Analysing the Use of Outdated JavaScript Libraries on the Web

**Tobias Lauinger, Abdelberi Chaabane, Sajjad Arshad, William Robertson, Christo Wilson and Engin Kirda. NDSS, 2017.** [Official paper record](https://www.ndss-symposium.org/ndss2017/ndss-2017-programme/thou-shalt-not-depend-me-analysing-use-outdated-javascript-libraries-web/).

The study examines client-side JavaScript library usage and known vulnerabilities, including direct/transitive inclusion and multiple versions within a page. It motivates better maintenance and dependency visibility.

**Connection:** our frontend module identifies selected library fingerprints/versions and compares them with a bundled affected-range CSV. It does not execute page JavaScript, reconstruct the paper's inclusion graph or exhaustively discover dynamically loaded dependencies. **Validation implication:** independently review affected/fixed version boundaries, unknown versions and conflicting fingerprints. Library/CVE identification is a lead for application review, not demonstration that the vulnerable function is reachable.

## P4 — We Still Don't Have Secure Cross-Domain Requests: an Empirical Study of CORS

**Jianjun Chen, Jian Jiang, Haixin Duan, Tao Wan, Shuo Chen, Vern Paxson and Min Yang. USENIX Security, 2018.** [Official publication PDF](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-chen.pdf) · [Conference record](https://www.usenix.org/conference/usenixsecurity18/presentation/chen-jianjun).

The paper studies CORS design, implementation and deployment, including subtle sending permissions and risky trust dependencies. Its scope is broader than checking two response headers.

**Connection:** our CORS module makes HTTP probes and interprets returned headers. It does not reproduce authenticated browser execution, internal-network attacks or the study's complete methodology. **Validation implication:** cover origin reflection, allowlist rejection, credentials, OPTIONS fallback and inconclusive probes. Separate observed configuration from demonstrated browser-readable sensitive data.

## P5 — How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories

**Michael Meli, Matthew R. McNiece and Bradley Reaves. NDSS, 2019.** [Official paper record](https://www.ndss-symposium.org/ndss-paper/how-bad-can-it-git-characterizing-secret-leakage-in-public-github-repositories/) · [Official PDF](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf).

The authors investigate secret leakage in public GitHub content using distinctive formats and conservative evaluation. The paper explicitly distinguishes finding a candidate secret from knowing that it is exploitable.

**Connection:** this is research motivation for secret discovery, not the same collection setting: our scanner examines delivered website content, not Git history. Its local CLI does not enable live secret verification. **Validation implication:** use synthetic format/context positives, realistic non-secret negatives and redaction assertions. Report a suspected pattern as a candidate, not as a confirmed active account credential.

## Specifications and data references — not research papers

| Reference | Role in this project / validation | Boundary |
| --- | --- | --- |
| [RFC 6265: HTTP State Management Mechanism](https://www.rfc-editor.org/rfc/rfc6265.html), Adam Barth, 2011 | Foundation for Cookie/Set-Cookie handling. | The original RFC alone does not document all later SameSite/prefix behavior. |
| [MDN Set-Cookie reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie) | Supplementary browser documentation for attributes, prefixes and compatibility. | Documentation, not an independent detector benchmark; record browser versions for experiments. |
| [RFC 6797: HTTP Strict Transport Security](https://www.rfc-editor.org/rfc/rfc6797.html), Hodges, Jackson and Barth, 2012 | HSTS interpretation and transport context. | Reading a header is not a full browser-state experiment. |
| [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/) | Policy syntax and behavior for reviewing CSP test expectations. | The checked publication is a W3C Working Draft dated 27 October 2026, not a final Recommendation. |
| [WHATWG Fetch: CORS protocol and credentials](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials) | Normative CORS credential-sharing behavior. | Living standard; pin a version/date for a published experiment. |
| [Open Source Vulnerability schema](https://ossf.github.io/osv-schema/) | Background for advisory/version-range representation. | Our local CSV is not a complete OSV record and this link does not establish each row's provenance. |

**A concrete interpretation issue to validate:** under Fetch's credential rules, `Access-Control-Allow-Origin: *` does not authorize sharing a response with a request whose credentials mode is `include`, even when `Access-Control-Allow-Credentials: true` is present. The current detector can emit a high-severity configuration finding for that combination; that output must not be presented as proof of credentialed response theft. An echoed allowed origin and wildcard policy are distinct cases. [Fetch specification](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials).

## What we contribute, and what remains open

Our implemented contribution is a local five-check integration: one CLI, shared observations, structured findings, an explicit incomplete-state path and optional offline HTML. We do not claim to improve on the research above or outperform other tools. We are not claiming an unstudied vulnerability class or a newly proven detector.

The empirical question for the next milestone is: **on independently labeled controlled cases, which of our selected rules detect the expected condition, which generate false positives, and which cannot reach a conclusion?** The [validation plan](../validation/README.md) defines the proposed per-rule labels, confusion matrices and coverage accounting. The six existing integration tests are evidence of their own assertions, not a substitute for that study.

## How to use these references in slides or writing

1. Cite the original paper for its research claim; do not cite our README as the authority for that claim.
2. State the paper's observation setting and date before comparing it with ours.
3. Identify our actual implemented scope and the method we have not reproduced.
4. Describe benchmark work as planned until an executed run and independent labels exist.
5. Keep code commit, case labels, dataset fingerprints and run outputs with any future performance table.

Suggested related-work paragraph: prior research has studied secret exposure, vulnerable JavaScript dependencies and browser-facing policy weaknesses in different collection settings. This project brings a selected subset of observable checks into a local, inspectable pipeline. Its evaluation focuses first on reproducible execution and will next assess per-rule detection against independently labeled fixtures. The references above provide background and evaluation guidance, not borrowed accuracy claims.
