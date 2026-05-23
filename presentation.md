# VaultShield PS-15 Presentation (End-to-End)

## 1) Opening (30-45 seconds)

Good morning judges.  
Our project is **VaultShield**, a **Container Image Vulnerability Scanner** built for PS-15.

The problem we solved is simple but high-impact: teams pull base images from Docker Hub and ship them without CI vulnerability gates.  
That creates supply-chain risk.

VaultShield enforces a security checkpoint in CI/CD:

1. Pull/build image
2. Generate SBOM
3. Scan CVEs
4. Risk score + policy evaluate
5. Block pipeline on unsafe images

This directly aligns to **MITRE ATT&CK T1195.001 (Compromise Software Dependencies)**.

---

## 2) Problem Statement (PS-15) and Our Response

### PS-15 asks for:

- CLI that accepts image name
- SBOM generation
- CVE scan across OS + language packages
- Severity-sorted report
- Risk score
- Non-zero exit to block CI on Critical CVEs
- Demo with vulnerable `nginx:1.14` vs patched image

### VaultShield delivers:

- CLI entrypoint: `main.py`
- SBOM: `scanner/sbom.py` using **Syft**
- CVE scan: `scanner/vuln.py` using **Grype**
- Risk score engine: `scanner/scorer.py`
- Policy/CI gate: `scanner/policy.py` + CLI exit code
- Reports: terminal + JSON + HTML (`scanner/report.py`, `templates/report.html`)
- CI pipeline: `.github/workflows/ci.yml`
- Demo branches: `main` (fixed path) and `vulnerable` (failing path)

---

## 3) Architecture (Cloud-Native Fit)

```text
Developer Push
  -> GitHub Actions (VaultShield Security Gate)
     -> Build Docker image from current branch
     -> Syft: generate SBOM
     -> Grype: match CVEs
     -> Scorer + Policy engine
     -> Report outputs (terminal/json/html artifacts)
     -> Exit code gate:
         0 => continue to deploy-simulation + Pages publish
         1 => stop pipeline
```

Why this is cloud-native:

- Runs in ephemeral CI runners
- Treats images as immutable artifacts
- Gates promotion, not just local scans
- Produces machine-readable artifacts for automation/SIEM workflows
- Can be attached to any containerized service repo

---

## 4) Threat Model and MITRE Mapping

### Threat
An attacker exploits vulnerable dependencies inherited from base images/libraries.

### MITRE ATT&CK
- **T1195.001**: Compromise Software Dependencies and Development Tools

### Defensive control
VaultShield prevents risky images from advancing through CI/CD by enforcing policy before deployment.

### Security value
- Converts “best effort scanning” into an enforceable control
- Adds auditable evidence for each build
- Reduces blast radius by catching vulnerabilities pre-deploy

---

## 5) Technical Flow (Deep Dive)

1. **Build/Pull image**
   - CI builds image tagged with commit SHA.

2. **SBOM generation**
   - `syft <image> -o cyclonedx-json`
   - Captures package inventory.

3. **Vulnerability matching**
   - `grype sbom:sbom.json -o json`
   - Maps packages to CVEs and severities.

4. **Enrichment and scoring**
   - Severity-weighted risk scoring in `scanner/scorer.py`
   - Counts critical/high/medium/low
   - Produces grade and summary metrics.

5. **Policy gate**
   - YAML policy rules (`policies/default.yaml`, `policies/main-demo.yaml`)
   - Branch-specific gate behavior for demo (strict vulnerable branch, controlled main branch)
   - CLI returns non-zero on block.

6. **Reporting**
   - Terminal banner for quick CI visibility
   - JSON for automation/analysis
   - HTML artifact for human-friendly review (charts + mitigation context)

---

## 6) Production Viability (How this serves production)

This is not just a classroom script. It is deployable as a CI control:

- **Policy-as-code**: security decisions are versioned and reviewable
- **Fail-fast gating**: blocks bad images before deploy, reducing downstream remediation cost
- **Artifact evidence**: security reports archived per build
- **Scalable pattern**: same workflow can be reused across services
- **Public status + private details**: CI status gives go/no-go, artifacts provide investigation depth

What would be added next for enterprise production:

- Registry admission controls (Kubernetes admission/webhook)
- Signed image provenance checks (e.g., cosign)
- Runtime + config scanning complements
- Central vulnerability exceptions workflow with approvals/expiry

---

## 7) Demo Storyboard (what to show live)

### Part A: Vulnerable path (RED)

1. Checkout/push `vulnerable` branch (`Dockerfile` uses `nginx:1.14`)
2. Open GitHub Actions run
3. Show `security-scan` failed
4. Show artifact report and critical findings
5. Explain: pipeline blocked before deploy

### Part B: Fixed path (GREEN)

1. Checkout/push `main` branch (`Dockerfile` fixed image + main policy)
2. Open GitHub Actions run
3. Show `security-scan` passed
4. Show `deploy-simulation` passed
5. Show `publish-pages` passed and open public landing page

### Close line
Same app, same pipeline, different dependency risk posture.  
VaultShield enforces secure promotion and blocks risky artifacts.

---

## 8) Team Roles Mapping (PS-15 format)

- **Person 1-2 (SBOM + CVE matching)**  
  Syft integration (`scanner/sbom.py`), Grype integration (`scanner/vuln.py`)

- **Person 3 (Risk scoring + CI gate)**  
  Scoring model (`scanner/scorer.py`), policy evaluation and exit behavior (`scanner/policy.py`, `main.py`)

- **Person 4 (Report output)**  
  Terminal/JSON/HTML report pipeline (`scanner/report.py`, `templates/report.html`)

- **Person 5 (Demo pipeline setup)**  
  GitHub Actions + demo scripts (`.github/workflows/ci.yml`, `setup-demo.sh`, `run-local-demo.sh`)

---

## 9) Tech Stack Mapping (PS-15)

Implemented:

- **Syft** (SBOM generation)
- **Grype** (vulnerability scanning)
- **Python** (orchestration + reporting)
- **GitHub Actions** (CI gate and demo pipeline)
- **Docker** (vulnerable vs fixed container variants)

Notes for judges:

- Vulnerability intelligence is sourced through Grype’s DB ecosystem.
- Current implementation uses robust CLI subprocess orchestration (portable and explicit).
- Docker SDK and direct NVD/OSV integration are valid future extensions if centralized intelligence control is required.

---

## 10) Rubric Fit Summary (explicit)

- **Technical Implementation (10/10 target)**  
  Full CLI scanner + CI integration + branch-based demo + report artifacts.

- **Security Depth & Accuracy (8/8 target)**  
  ATT&CK mapping, risk scoring, gate enforcement, documented bypass awareness.

- **Architecture Fit & Feasibility (6/6 target)**  
  Cloud-native CI workflow, deploy simulation, policy-driven control.

- **Communication & Demo (4/4 target)**  
  Clear red-vs-green narrative with reproducible commands and visible artifacts.

- **Documentation (2/2 target)**  
  README, threat model, bypass notes, architecture narrative, this presentation script.

---

## 11) Final 20-Second Closing Script

VaultShield operationalizes supply-chain defense in CI/CD.  
We transform vulnerability scanning from informational output into an enforceable release control.  
With SBOM generation, CVE detection, policy gating, and artifact evidence, we block risky images before production and allow only trusted promotions.
