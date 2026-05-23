# VaultShield Container Security Scanner

VaultShield is a CI/CD security gate that blocks deployment of vulnerable container images and allows deploy simulation only when security policy passes.

## What this demo proves

A real project (VaultShield landing page) is containerized in two variants:

- Vulnerable image: `nginx:1.14` (`Dockerfile.vulnerable`) -> pipeline fails.
- Fixed image: `nginx:1.25-alpine` (`Dockerfile`) -> pipeline passes and deploy simulation runs.

This demonstrates supply-chain protection with evidence in GitHub Actions artifacts.

## How it works in 5 steps

1. Build application image in CI (`vaultshield-app:$GITHUB_SHA`).
2. Generate SBOM with Syft and detect CVEs with Grype.
3. Enrich and score findings, then evaluate policy gate.
4. Emit terminal output + JSON + HTML reports.
5. Fail pipeline on critical vulnerabilities; otherwise continue to deploy simulation.

## Demo instructions (live in front of judges)

### 1) Prepare local environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Install scanner binaries:

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

### 2) Prepare demo branches

```bash
bash setup-demo.sh
```

Push both branches:

```bash
git checkout main && git push -u origin main
git checkout vulnerable && git push -u origin vulnerable
git checkout main
```

### 3) Show failure in GitHub Actions

- Open Actions tab -> workflow `VaultShield Security Gate`.
- Open latest run for `vulnerable` branch.
- Show failed `security-scan` job and downloaded report artifact.

### 4) Show pass + deploy simulation

- Open latest run for `main` branch.
- Show `security-scan` passed.
- Show `deploy-simulation` passed and health-check curl output.

### 5) Show live local site + report

```bash
bash run-local-demo.sh
```

- Site opens at `http://localhost:8080`
- Reports generated in `reports/report.html` and `reports/report.json`

## Scanner usage

```bash
python main.py --image nginx:1.14 --output terminal
python main.py --image vaultshield-app:demo --output both --reports-dir reports --project "VaultShield Demo App" --branch main
```

## Architecture (ASCII)

```text
Developer Push
   -> GitHub Actions (.github/workflows/ci.yml)
      -> Build vaultshield image
      -> Run VaultShield scanner (main.py)
         -> scanner/sbom.py (Syft)
         -> scanner/vuln.py (Grype)
         -> scanner/scorer.py + scanner/policy.py
         -> scanner/report.py (terminal + JSON + HTML)
      -> Upload security report artifact
      -> If gate passed: deploy-simulation job
```

## MITRE ATT&CK T1195.001 mapping

**Technique:** T1195.001 - Compromise Software Dependencies and Development Tools

### Threat behavior

Attackers exploit vulnerable dependencies inherited via container base images and packaged libraries.

### VaultShield defense

- Scans image components before deployment.
- Blocks critical findings through policy and exit codes.
- Generates audit-grade reports with exact vulnerable package/CVE evidence.

### Why this is valid for PS-15

The scanner enforces a pre-deployment control in the software supply chain and prevents vulnerable artifacts from promotion into production paths.

## Tech stack

- Python 3.11+
- Syft (SBOM)
- Grype (vulnerability matching)
- Rich (terminal reporting)
- Jinja2 (HTML report rendering)
- Chart.js CDN (report charts)
- Docker / nginx (`1.14` vulnerable, `1.25-alpine` fixed)
- GitHub Actions

## PS-15 rubric checklist

- [x] Core functionality: scans real images and blocks on critical findings.
- [x] Correctness: tested scanner modules and deterministic CLI behavior.
- [x] Complexity: policy gate, scoring, metadata-rich reporting, CI integration.
- [x] Code quality: modular scanner package with lint/type/test checks.
- [x] Threat model and ATT&CK alignment: documented in `docs/THREAT_MODEL.md`.
- [x] Attack/defense validity: vulnerable branch fails, fixed branch passes.
- [x] Limitations and bypasses: documented in `docs/BYPASSES.md`.
- [x] Architecture fit and feasibility: CI workflow + deploy simulation.
- [x] Communication/demo clarity: scripted branch/setup/demo flows.
- [x] Documentation completeness: setup, usage, mapping, architecture, checklist.

## Useful commands

```bash
make lint
make typecheck
make test
make demo-setup
make demo-local
```
