"""Trivy JSON format parser."""

from ..priority import calculate_priority


def extract_cve_ids(data: dict) -> list[str]:
    """
    Extract CVE IDs from Trivy JSON format.

    Args:
        data: The parsed JSON data.

    Returns:
        List of unique CVE IDs.
    """

    cve_ids = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve_id = vuln.get("VulnerabilityID", "")
            if cve_id.startswith("CVE-"):
                cve_ids.append(cve_id)
    return list(set(cve_ids))


def extract_original_severities(data: dict) -> dict[str, int]:
    """
    Extract original severity counts from Trivy JSON format (all occurrences).

    Args:
        data: The parsed JSON data.

    Returns:
        Dictionary of severity counts (e.g., {"CRITICAL": 5, "HIGH": 10, ...}).
    """

    severity_counts: dict[str, int] = {}
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve_id = vuln.get("VulnerabilityID", "")
            if not cve_id.startswith("CVE-"):
                continue
            severity = vuln.get("Severity", "UNKNOWN").upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return severity_counts


def process(data: dict, kev_cves: set[str], epss_scores: dict[str, float]) -> dict:
    """
    Process Trivy JSON and add vulnsort priority field.

    Args:
        data: The parsed JSON data.
        kev_cves: Set of CVE IDs in the KEV catalog.
        epss_scores: Dictionary of EPSS scores.

    Returns:
        The processed JSON data with vulnsort priority field.
    """

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve_id = vuln.get("VulnerabilityID", "")
            if cve_id.startswith("CVE-"):
                vuln["vulnsort"] = calculate_priority(cve_id, kev_cves, epss_scores)
    return data
