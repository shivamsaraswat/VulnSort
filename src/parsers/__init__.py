"""Scanner format parsers."""

from .grype import extract_cve_ids as extract_grype_cves
from .grype import process as process_grype
from .trivy import extract_cve_ids as extract_trivy_cves
from .trivy import process as process_trivy

__all__ = [
    "extract_trivy_cves",
    "process_trivy",
    "extract_grype_cves",
    "process_grype",
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

    # Trivy detection
    if "SchemaVersion" in data and "Results" in data:
        return "trivy"

    # Grype detection
    if "matches" in data and "source" in data:
        return "grype"

    return None
