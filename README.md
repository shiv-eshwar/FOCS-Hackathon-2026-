# VaultShield Container Security Scanner

[![CI](https://github.com/shiv-eshwar/FOCS-Hackathon-2026-/actions/workflows/ci.yml/badge.svg)](https://github.com/shiv-eshwar/FOCS-Hackathon-2026-/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

VaultShield is an open-source container security gate for CI/CD pipelines. It generates an SBOM, scans vulnerabilities, applies policy-based gating, and produces actionable reports before deployment.

## Why VaultShield

Teams frequently deploy container images without enforcing vulnerability checks in CI. VaultShield converts scanning from an informational step into an enforceable release control.

## Key Features

- SBOM generation with Syft (`scanner/sbom.py`)
- CVE matching with Grype (`scanner/vuln.py`)
- Risk scoring and severity summarization (`scanner/scorer.py`)
- Policy-as-code gate with non-zero exit blocking (`scanner/policy.py`, `main.py`)
- Rich terminal output and JSON/HTML reports (`scanner/report.py`, `templates/report.html`)
- GitHub Actions integration with artifact upload and deployment gating (`.github/workflows/ci.yml`)
- Public static landing-page publishing through GitHub Pages

## Architecture Overview

```text
Developer Push
  -> GitHub Actions (VaultShield Security Gate)
     -> Build container image
     -> Generate SBOM (Syft)
     -> Scan vulnerabilities (Grype)
     -> Score + evaluate policy
     -> Emit JSON/HTML artifacts
     -> Exit code gate:
          0 = allow downstream jobs
          1 = block deployment
```

## Quick Start

### Prerequisites

- Docker
- Python 3.11+
- Syft
- Grype

### Install

```bash
git clone https://github.com/shiv-eshwar/FOCS-Hackathon-2026-.git
cd FOCS-Hackathon-2026-
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Install scanner binaries (if missing):

```bash
mkdir -p "$HOME/.local/bin"
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "$HOME/.local/bin"
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"
```

### Run a Scan

```bash
python main.py \
  --image nginx:1.14 \
  --output both \
  --reports-dir reports \
  --fail-on critical \
  --policy policies/default.yaml \
  --project "VaultShield Demo App" \
  --branch local
```

Exit codes:

- `0` -> pass / continue pipeline
- `1` -> blocked by policy or gate thresholds
- `2` -> scanner runtime/tooling error

## CI/CD Integration

Use `.github/workflows/ci.yml` as reference. The pipeline:

1. Builds image from the current commit
2. Runs VaultShield scanner
3. Uploads report artifacts (`reports/`)
4. Blocks deploy-simulation when gate fails
5. Publishes static landing page to GitHub Pages when `main` passes

## Demo Flow (Red -> Green)

- `vulnerable` branch: `Dockerfile.vulnerable` (`nginx:1.14`) -> expected fail
- `main` branch: fixed Dockerfile + main policy -> expected pass

Useful scripts:

```bash
bash setup-demo.sh
bash run-local-demo.sh
```

## Documentation

- Setup guide: [`INSTALL.md`](INSTALL.md)
- Threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- Bypasses/limitations: [`docs/BYPASSES.md`](docs/BYPASSES.md)
- Code comments evidence: [`docs/CODE_COMMENTS.md`](docs/CODE_COMMENTS.md)
- Presentation script: [`presentation.md`](presentation.md)
- Submission index: [`FINAL_SUBMISSION.md`](FINAL_SUBMISSION.md)

## MITRE ATT&CK Alignment

Primary mapping: **T1195.001 - Compromise Software Dependencies and Development Tools**.

VaultShield mitigates this technique by enforcing supply-chain scanning before artifact promotion.

## Contributing

Contributions are welcome. For meaningful changes:

1. Create a feature branch
2. Run local checks:
   ```bash
   .venv/bin/ruff check .
   .venv/bin/mypy scanner main.py
   .venv/bin/pytest -q
   ```
3. Open a pull request with a clear summary and test evidence

## Security

If you find a vulnerability in this project, please open a private report with reproduction details, affected versions, and potential impact.

## Roadmap

- Reusable GitHub Action package (`uses: ...`)
- PyPI distribution for `pip install`
- Registry admission controls and signed-image verification
- Centralized exception workflow with approvals and expiry

## License

Licensed under the [MIT License](LICENSE).
