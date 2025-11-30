"""Grype JSON format parser."""

from ..priority import calculate_priority


def extract_cve_ids(data: dict) -> list[str]:
    """
    Extract CVE IDs from Grype JSON format.

    Args:
        data: The parsed JSON data.

    Returns:
        List of unique CVE IDs.
    """

    cve_ids = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        cve_id = vuln.get("id", "")
        if cve_id.startswith("CVE-"):
            cve_ids.append(cve_id)
        # Also check related vulnerabilities
        for related in match.get("relatedVulnerabilities", []):
            related_id = related.get("id", "")
            if related_id.startswith("CVE-"):
                cve_ids.append(related_id)
    return list(set(cve_ids))


def process(data: dict, kev_cves: set[str], epss_scores: dict[str, float]) -> dict:
    """
    Process Grype JSON and add vulnsort priority field.

    Args:
        data: The parsed JSON data.
        kev_cves: Set of CVE IDs in the KEV catalog.
        epss_scores: Dictionary of EPSS scores.

    Returns:
        The processed JSON data with vulnsort priority field.
    """
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        cve_id = vuln.get("id", "")

        # Try to find a CVE ID from related vulnerabilities if main ID is not a CVE
        if not cve_id.startswith("CVE-"):
            for related in match.get("relatedVulnerabilities", []):
                related_id = related.get("id", "")
                if related_id.startswith("CVE-"):
                    cve_id = related_id
                    break

        if cve_id.startswith("CVE-"):
            match["vulnsort"] = calculate_priority(cve_id, kev_cves, epss_scores)

    return data
