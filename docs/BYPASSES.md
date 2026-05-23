# Known Bypasses and Limitations

This scanner is intentionally transparent about blind spots.

## Potential bypasses

1. Stripped static binaries (Go/Rust) may hide dependency metadata from SBOM tools.
2. Vendored or copied code without package manifests can evade CVE correlation.
3. Runtime-injected libraries (plugins, LD_PRELOAD) are not visible in static image scans.
4. Scratch or heavily minimized images can reduce package visibility.
5. CVE-clean images can still be insecure due to misconfiguration (root user, weak TLS, exposed admin endpoints).

## Mitigations

- Pair with runtime monitoring and EDR
- Add IaC/configuration scanning (e.g., Trivy config checks)
- Enforce signed images and provenance checks
- Regularly refresh KEV/EPSS data and policy rules
