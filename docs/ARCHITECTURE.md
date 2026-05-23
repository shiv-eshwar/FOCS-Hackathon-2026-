# Architecture

## Pipeline

1. `scanner/sbom.py`: run Syft, generate CycloneDX JSON
2. `scanner/vuln.py`: run Grype against SBOM, collect findings
3. `scanner/enrich.py`: annotate findings with EPSS + KEV from `scanner/cache.py`
4. `scanner/scorer.py`: compute weighted risk score and grade
5. `scanner/policy.py`: evaluate YAML policy rules
6. `scanner/diff.py`: compare with baseline report when provided
7. `scanner/report.py`: render terminal/JSON/HTML outputs

## Operational choices

- Offline-first SQLite cache avoids demo failures without internet
- Policy supports expiring exceptions to avoid permanent bypasses
- Output is deterministic JSON, suitable for CI artifacts and SIEM ingestion
