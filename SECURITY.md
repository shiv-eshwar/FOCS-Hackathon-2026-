# Security Policy

## Supported scope

VaultShield is a security-focused project. Security issues in the scanner logic, CI gating behavior, report generation pipeline, or dependency-handling logic are considered in scope.

## Reporting a vulnerability

If you discover a security issue, please report it responsibly.

Please include:

- A clear description of the issue
- Impact assessment (what can go wrong)
- Reproduction steps (commands / input image / policy file)
- Suggested mitigation if available

For now, report via repository issue with enough detail for triage. If private reporting is required by your organization, contact the maintainer directly before public disclosure.

## Response expectations

Target process:

1. Acknowledge report
2. Reproduce and assess severity
3. Prepare mitigation/fix
4. Publish patch and notes

## Severity guidance

Examples of high-impact findings:

- Scanner incorrectly returns pass on clearly blocked policy conditions
- Report tampering that hides critical findings
- CI gate bypass via argument/policy parsing flaws

Examples of lower-impact findings:

- Cosmetic reporting defects without policy impact
- Non-security formatting or documentation issues

## Secure usage recommendations

When deploying VaultShield in production pipelines:

- Pin Syft and Grype versions in CI
- Keep policy files in version control with review requirements
- Require explicit expiry and justification for policy exceptions
- Archive scanner reports as build artifacts
- Pair static scanning with runtime and configuration controls

## Dependency and supply-chain hygiene

- Use trusted sources for external binaries
- Validate scanner behavior regularly with known vulnerable images
- Re-run scans on rebuilt images when base images are updated

## Disclosure policy

Please avoid publishing exploit details publicly before a fix is available and maintainers have had a reasonable time to respond.
