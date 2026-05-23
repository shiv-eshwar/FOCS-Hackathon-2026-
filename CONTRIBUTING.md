# Contributing to VaultShield

Thanks for your interest in contributing to VaultShield.

## Code of conduct

Please be respectful and constructive in all discussions, issues, and pull requests.

## Development setup

```bash
git clone https://github.com/shiv-eshwar/FOCS-Hackathon-2026-.git
cd FOCS-Hackathon-2026-
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Install required scanner binaries:

```bash
mkdir -p "$HOME/.local/bin"
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "$HOME/.local/bin"
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"
```

## Branching model

- Create a topic branch from `main`.
- Keep PRs focused and small when possible.
- Use descriptive commit messages.

Example:

```bash
git checkout -b feat/policy-enhancement
```

## Required checks before PR

Run all checks locally before opening a pull request:

```bash
.venv/bin/ruff check .
.venv/bin/mypy scanner main.py
.venv/bin/pytest -q
```

If your change affects scanner output, include command output samples in the PR description.

## Pull request guidelines

Each PR should include:

1. Problem statement (what is being fixed/improved)
2. Summary of changes
3. Test/verification evidence
4. Any documentation updates

If behavior changes, update relevant docs:

- `README.md`
- `INSTALL.md`
- `docs/THREAT_MODEL.md` / `docs/BYPASSES.md` (if security logic changed)

## Project structure (high-level)

- `main.py` - CLI orchestration
- `scanner/` - SBOM, vuln matching, scoring, policy, reporting
- `templates/` - HTML report template
- `.github/workflows/` - CI/CD workflows
- `docs/` - threat model, bypasses, supporting documentation

## Good first contributions

- Improve policy rule coverage and examples
- Add additional tests for edge-case scanner behavior
- Improve report clarity and remediation guidance
- Enhance CI portability and caching

## Release notes suggestion

For user-facing changes, add a short release note section in the PR:

- Added
- Changed
- Fixed
- Security

