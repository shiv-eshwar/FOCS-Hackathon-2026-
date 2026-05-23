Project structure:

ps15-scanner/
├── main.py              ← CLI entrypoint
├── scanner/
│   ├── sbom.py          ← Syft wrapper
│   ├── vuln.py          ← Grype wrapper
│   ├── scorer.py        ← risk scoring engine
│   └── report.py        ← JSON + Rich terminal + HTML
├── templates/
│   └── report.html      ← Jinja2 + Chart.js
├── demo.sh              ← full demo sequence
├── Makefile             ← CI gate simulation
├── .github/workflows/
│   └── scan.yml         ← GitHub Actions pipeline
├── Dockerfile
├── docker-compose.yml
└── README.md            ← MITRE mapping + rubric checklist



Exact Claude Code prompt — paste this, walk away:


Build a complete container image vulnerability scanner for a 
cybersecurity hackathon (PS-15).

DELIVERABLE: CLI tool — takes Docker image name, runs full SBOM 
analysis, outputs CVE report, exits non-zero if Critical CVEs found.

=== FILES TO CREATE ===

1. main.py
   - CLI via argparse: `python main.py --image nginx:1.14 --output html`
   - flags: --image, --output (json|html|terminal), --fail-on (critical|high), --dry-run
   - orchestrates sbom → vuln → score → report pipeline
   - exit code 1 if Critical found, 0 if clean

2. scanner/sbom.py
   - run `syft <image> -o cyclonedx-json --file sbom.json` via subprocess
   - parse output JSON, return structured package list
   - handle: image pull errors, syft not installed, timeout

3. scanner/vuln.py
   - run `grype sbom:sbom.json -o json --file vulns.json` via subprocess
   - parse grype JSON output
   - return list of {pkg, version, cve_id, severity, cvss_score, fixed_version}

4. scanner/scorer.py
   - risk scoring: Critical=10pts, High=7, Medium=4, Low=1, Negligible=0
   - total_score = sum of all weighted vuln scores
   - risk_grade: A(0-10) B(11-30) C(31-60) D(61-100) F(100+)
   - also compute: critical_count, high_count, med_count, low_count
   - flag: ci_block = True if any Critical exists

5. scanner/report.py
   - terminal: Rich table, colour-coded severity (red/orange/yellow/blue)
     show: summary card (grade, score, counts), full CVE table sorted by severity
     banner: "PIPELINE BLOCKED" in red if critical found, "PIPELINE CLEAR" in green if not
   - json: full structured output to file
   - html: Jinja2 template render → report.html

6. templates/report.html
   - Jinja2 template
   - header: image name, scan date, risk grade badge (A=green ... F=red)
   - Chart.js doughnut: severity breakdown (Critical/High/Medium/Low counts)
   - Chart.js bar: top 10 packages by vuln count
   - full CVE table: sortable, colour-coded rows by severity
   - footer: MITRE ATT&CK T1195.001 mapping, remediation tips

7. demo.sh
   - step 1: scan nginx:1.14 → show blocked pipeline + red banner
   - step 2: scan nginx:latest → show clear pipeline + green banner
   - step 3: open generated HTML report
   - clear terminal between steps, add sleep for demo pacing

8. Makefile
   - `make install` → pip install + check syft/grype installed
   - `make scan IMAGE=nginx:1.14` → run scanner
   - `make demo` → run demo.sh
   - `make ci-check IMAGE=nginx:1.14` → exit 1 on critical (CI gate)
   - `make report` → open HTML report in browser

9. .github/workflows/scan.yml
   - trigger: push, pull_request
   - steps: checkout, install syft+grype+python deps, run scanner on nginx:1.14
   - upload HTML report as artifact
   - fail job if exit code 1

10. Dockerfile
    - FROM python:3.11-slim
    - install syft + grype binaries
    - install python deps
    - ENTRYPOINT ["python", "main.py"]

11. docker-compose.yml
    - service: scanner
    - volume mount for output reports
    - env: IMAGE_NAME

12. README.md
    - MITRE ATT&CK T1195.001 mapping with explanation
    - setup in 3 commands
    - demo instructions
    - rubric checklist (every deliverable item checked off)
    - architecture diagram (ASCII)

=== TECH STACK (exact) ===
Python 3.11, subprocess (syft/grype), Rich (terminal), 
Jinja2 (HTML), Chart.js CDN (charts), argparse (CLI),
Docker SDK optional for image pull verification

=== DEMO IMAGES ===
nginx:1.14  → many Critical/High CVEs → pipeline BLOCKED
nginx:latest → clean or minimal → pipeline CLEAR

=== CONSTRAINTS ===
- syft and grype called via subprocess (not Python bindings)
- all errors handled gracefully with clear messages
- HTML report must open standalone in browser (no server needed)
- Rich terminal output must look impressive for live demo
- every function has docstring
- README has copy-paste setup commands