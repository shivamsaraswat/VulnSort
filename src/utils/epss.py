"""Fetch EPSS (Exploit Prediction Scoring System) scores."""

import sys

import requests

EPSS_API_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = "VulnSort/1.0"


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """
    Fetch EPSS scores for a list of CVE IDs.

    Args:
        cve_ids: List of CVE IDs to fetch EPSS scores for.

    Returns:
        Dictionary mapping CVE ID to EPSS score (0.0 to 1.0).
    """

    if not cve_ids:
        return {}

    epss_scores = {}
    batch_size = 100  # EPSS API accepts up to 100 CVEs per request

    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i : i + batch_size]
        cve_param = ",".join(batch)

        try:
            response = requests.get(
                EPSS_API_URL,
                params={"cve": cve_param},
                headers={"User-Agent": USER_AGENT},
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            for item in data.get("data", []):
                cve_id = item.get("cve")
                epss = item.get("epss")
                if cve_id and epss:
                    epss_scores[cve_id] = float(epss)

        except requests.exceptions.RequestException as e:
            print(f"Warning: Failed to fetch EPSS scores: {e}", file=sys.stderr)
            continue

    print(f"Fetched EPSS scores for {len(epss_scores)}/{len(cve_ids)} CVEs", file=sys.stderr)
    return epss_scores
