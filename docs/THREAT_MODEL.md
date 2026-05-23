# Threat Model

## System context

The scanner runs in CI/CD or local pre-deploy checks to prevent vulnerable container images from reaching runtime environments.

## Assets

- Production container images
- CI pipeline integrity
- Vulnerability posture and remediation SLAs

## Threat actors

- Opportunistic attackers exploiting known CVEs
- Supply-chain adversaries introducing vulnerable dependencies
- Internal users bypassing scan gates through weak policy exceptions

## ATT&CK and defense mapping

- T1195.001 (Compromise Dependencies) — primary defensive target
- T1190 (Exploit Public-Facing Application) — consequence if vulnerable images deploy
- T1610 (Deploy Container) — stage where policy gate blocks execution
- D3FEND D3-SCA — software composition analysis as proactive control

## Trust boundaries

- External image registries
- Feed providers (CISA KEV / EPSS)
- CI runtime and secrets boundary

## Assumptions

- Syft and Grype are trusted binaries from official releases
- Cached feed data is periodically refreshed and integrity-checked
- Policy exceptions require explicit expiry and justification
