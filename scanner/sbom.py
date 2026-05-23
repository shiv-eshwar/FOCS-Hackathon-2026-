"""Syft wrapper for generating SBOM data."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

from scanner.errors import ToolExecutionError, ToolNotInstalledError


def run_syft(image: str, sbom_path: Path, timeout_seconds: int = 600) -> dict[str, Any]:
    """Generate CycloneDX JSON SBOM for a container image."""
    if shutil.which("syft") is None:
        raise ToolNotInstalledError("syft is not installed. Install syft to continue.")

    command = ["syft", image, "-o", "cyclonedx-json", "--file", str(sbom_path)]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ToolExecutionError(
            f"syft timed out after {timeout_seconds}s for image '{image}'"
        ) from error
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "unknown syft error"
        raise ToolExecutionError(f"syft failed for image '{image}': {message}")

    if not sbom_path.exists():
        raise ToolExecutionError(f"syft completed but output not found at {sbom_path}")

    return cast(dict[str, Any], json.loads(sbom_path.read_text(encoding="utf-8")))


def extract_packages(sbom_data: dict[str, Any]) -> list[dict[str, str]]:
    """Extract package records from CycloneDX JSON content."""
    components = sbom_data.get("components", [])
    packages: list[dict[str, str]] = []
    for component in components:
        name = str(component.get("name", ""))
        version = str(component.get("version", ""))
        purl = str(component.get("purl", ""))
        if not name:
            continue
        packages.append({"name": name, "version": version, "purl": purl})
    return packages
