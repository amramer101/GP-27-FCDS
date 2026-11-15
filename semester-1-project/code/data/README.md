# Data — frontend vulnerability snapshot

`cve_database_v2.csv` is the bundled input for the frontend-library scanner. It is read locally through the orchestrator's fixed path; no dataset download or refresh occurs during a scan.

| Column | Use |
| --- | --- |
| `library` | Library identifier |
| `min_affected` | Inclusive lower bound of the affected version range |
| `fixed_in` | Exclusive upper bound; an empty bound represents an open-ended range |
| `cve` | Vulnerability identifier |
| `cvss`, `cwe` | Stored severity/classification metadata |
| `summary` | Vulnerability description |
| `signature` | Content pattern used in library identification |
| `upgrade_rec` | Stored upgrade guidance |

Version matching uses parsed versions and the scanner's fingerprint checks. This file is a snapshot, not an exhaustive or automatically current vulnerability database. Its original generation date and upstream references are not encoded as a complete per-row provenance record; do not invent them from file modification times.

For a future dataset update, record the upstream advisory references, collection time, transformation steps and SHA-256; test affected versions, fixed-version boundaries and unparseable versions. A production input file must not also be the sole independent authority for assessing its own correctness. Validation cases should cite reviewed advisory/version-range evidence separately.
