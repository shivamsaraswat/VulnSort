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
