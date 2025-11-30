"""Load CISA KEV (Known Exploited Vulnerabilities) data."""

import json
import sys
from pathlib import Path


def load_kev_data(kev_path: Path) -> set[str]:
    """
    Load CISA KEV CVE IDs into a set for fast lookup.

    Args:
        kev_path: Path to the KEV JSON file.

    Returns:
        Set of CVE IDs in the KEV catalog.
    """

    if not kev_path.exists():
        print(f"Warning: KEV data not found at {kev_path}", file=sys.stderr)
        print("Run 'python scripts/fetch_cisa_kev.py' to download KEV data", file=sys.stderr)
        return set()

    with open(kev_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    kev_cves = {vuln["cveID"] for vuln in data.get("vulnerabilities", [])}
    print(f"Loaded {len(kev_cves)} CVEs from CISA KEV catalog", file=sys.stderr)
    return kev_cves
