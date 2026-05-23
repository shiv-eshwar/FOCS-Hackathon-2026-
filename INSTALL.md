# VaultShield Installation and External Usage Guide

This guide explains how any developer can install VaultShield and use it to gate container deployments before production.

---

## What VaultShield does

VaultShield scans container images in a CI/CD-friendly way:

1. Generates SBOM (Syft)
2. Matches CVEs (Grype)
3. Scores risk and applies policy
4. Produces JSON + HTML report
5. Exits non-zero when policy blocks deployment

Use it as a **pre-deployment security gate**.

---

## 1) Prerequisites

Install these tools on your machine/CI runner:

- Docker
- Python 3.11+
- Syft
- Grype

Check prerequisites:

```bash
docker --version
python3 --version
syft version
grype version
```

---

## 2) Clone and install VaultShield

```bash
git clone https://github.com/shiv-eshwar/FOCS-Hackathon-2026-.git
cd FOCS-Hackathon-2026-

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

If Syft/Grype are missing, install quickly:

```bash
mkdir -p "$HOME/.local/bin"
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "$HOME/.local/bin"
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"
```

---

## 3) Run your first scan

Example scan:

```bash
python main.py \
  --image nginx:1.25-alpine \
  --output both \
  --reports-dir reports \
  --fail-on critical \
  --policy policies/default.yaml \
  --project "My App" \
  --branch local
```

Outputs:

- `reports/report.json`
- `reports/report.html`
- terminal summary banner

Exit code behavior:

- `0`: pass (safe to continue pipeline)
- `1`: blocked by policy / severity gate
- `2`: scanner execution error (tool/runtime issue)

---

## 4) Scan your own built image

Build your app image first:

```bash
docker build -t my-app:scan .
```

Scan it:

```bash
python main.py \
  --image my-app:scan \
  --output both \
  --reports-dir reports \
  --fail-on critical \
  --policy policies/default.yaml \
  --project "My App" \
  --branch local
echo "EXIT_CODE=$?"
```

If `EXIT_CODE=1`, treat as deploy block and remediate.

---

## 5) Integrate into GitHub Actions

Minimal pattern:

```yaml
name: Security Gate

on:
  push:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t my-app:${GITHUB_SHA} .

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install syft + grype
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

      - name: Install VaultShield
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"

      - name: Run scanner
        run: |
          python main.py \
            --image my-app:${GITHUB_SHA} \
            --output both \
            --reports-dir reports \
            --fail-on critical \
            --policy policies/default.yaml \
            --project "My App" \
            --branch ${GITHUB_REF_NAME}

      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report-${{ github.ref_name }}
          path: reports/
```

Any non-zero exit from scanner fails this job and blocks downstream deploy jobs.

---

## 6) Policy files

Default policy file:

- `policies/default.yaml`

Demo/main policy file:

- `policies/main-demo.yaml`

You can create your own policy file and pass it via:

```bash
--policy path/to/your-policy.yaml
```

---

## 7) Common command patterns

Terminal-only output:

```bash
python main.py --image my-app:scan --output terminal --fail-on critical
```

JSON report only:

```bash
python main.py --image my-app:scan --output json --report-file report.json
```

HTML report only:

```bash
python main.py --image my-app:scan --output html --report-file report.html
```

Both reports in a folder:

```bash
python main.py --image my-app:scan --output both --reports-dir reports
```

---

## 8) Troubleshooting

### `syft is not installed` or `grype is not installed`
- Ensure binaries are installed and in `PATH`.
- Re-run `syft version` and `grype version` to verify.

### `TemplateNotFound: report.html`
- Ensure `templates/report.html` exists in the repository checkout.
- Ensure workflow checks out the repository before scanner execution.

### Scan unexpectedly fails on "fixed" image
- Base images may still contain residual CVEs depending on feed updates.
- Use policy tuning (`policies/*.yaml`) and explicit remediation tracking.

### CI scan takes too long
- First run can be slower due to vulnerability DB/cache warm-up.
- Keep scanner runs on stable runner images and cache where possible.

---

## 9) Recommended production rollout

1. Start in monitor mode (report + warn path)
2. Enable blocking on critical CVEs
3. Add exception process with expiry + owner
4. Extend to high severity once remediation cycle is stable
5. Add runtime and config scanning as complementary controls

---

## 10) Support and contribution

- Open issues in the repository for feature requests or integration help.
- Include scanner command, exit code, and report snippet when reporting bugs.
