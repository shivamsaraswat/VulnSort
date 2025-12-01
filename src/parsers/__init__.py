"""
Scanner format parsers.

Supports:
- Trivy (native JSON format)
- Grype (native JSON format)
- SARIF (SARIF 2.1.0 standard)
"""

from .grype import extract_cve_ids as extract_grype_cves
from .grype import extract_original_severities as extract_grype_severities
from .grype import process as process_grype
from .sarif import extract_cve_ids as extract_sarif_cves
from .sarif import extract_original_severities as extract_sarif_severities
from .sarif import process as process_sarif
from .trivy import extract_cve_ids as extract_trivy_cves
from .trivy import extract_original_severities as extract_trivy_severities
from .trivy import process as process_trivy

__all__ = [
    "extract_trivy_cves",
    "extract_trivy_severities",
    "process_trivy",
    "extract_grype_cves",
    "extract_grype_severities",
    "process_grype",
    "extract_sarif_cves",
    "extract_sarif_severities",
    "process_sarif",
    "detect_scanner_format",
]


def detect_scanner_format(data: dict) -> str | None:
    """
    Detect the scanner format from the JSON data.

    Args:
        data: The parsed JSON data.

    Returns:
        Scanner name or None if unknown.
    """

    # SARIF detection (SARIF 2.1.0 standard)
    if "$schema" in data and "sarif" in data.get("$schema", "").lower():
        return "sarif"
    if "version" in data and "runs" in data and isinstance(data.get("runs"), list):
        # Also detect SARIF by structure (has version and runs array)
        if any(run.get("tool", {}).get("driver") for run in data.get("runs", [])):
            return "sarif"

    # Trivy detection (native JSON format)
    if "SchemaVersion" in data and "Results" in data:
        return "trivy"

    # Grype detection (native JSON format)
    if "matches" in data and "source" in data:
        return "grype"

    return None
