# FOCS PS-15 Container Vulnerability Scanner

A hackathon-ready container image vulnerability scanner that uses Syft + Grype, enriched scoring, policy-as-code, diffing, and offline-first threat intel cache.

## Quick setup (3 commands)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Install external binaries:

```bash
# Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
# Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

## Usage

```bash
python main.py --image nginx:1.14 --output terminal
python main.py --image nginx:1.14 --output json --report-file report.json
python main.py --image nginx:1.14 --output html --report-file report.html
```

Important flags:
- `--fail-on critical|high`
- `--policy policies/default.yaml`
- `--baseline report.json`
- `--refresh` or `--live` (refresh EPSS + KEV feeds)

## Demo flow

```bash
make demo
```

The demo scans a vulnerable image, shows a blocked pipeline, then compares against a newer image.

## MITRE ATT&CK Mapping

- Primary: **T1195.001** — Compromise Software Dependencies and Development Tools
- Supporting: T1190, T1059, T1610
- D3FEND counterpart: D3-SCA

## Rubric checklist

- [x] Core functionality (SBOM + CVE + reports + exit codes)
- [x] Implementation correctness (unit tests + fixtures)
- [x] Complexity (enriched risk score + policy engine + diff)
- [x] Code quality (typed modules + docstrings + linters)
- [x] Threat model write-up
- [x] ATT&CK alignment
- [x] Attack/defense validity path in demo
- [x] Limitation/bypass awareness
- [x] Architecture and deployment viability docs
- [x] README + setup + comments

## Architecture (ASCII)

```text
CLI (main.py)
  -> syft wrapper (scanner/sbom.py)
  -> grype wrapper (scanner/vuln.py)
  -> enrichment (scanner/cache.py + scanner/enrich.py)
  -> scoring (scanner/scorer.py)
  -> policy evaluation (scanner/policy.py)
  -> diff (scanner/diff.py)
  -> terminal/json/html report (scanner/report.py)
```
