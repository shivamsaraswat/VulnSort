"""Priority calculation based on KEV and EPSS scores."""

# Priority thresholds
EPSS_HIGH_THRESHOLD = 0.70  # 70%
EPSS_MEDIUM_THRESHOLD = 0.30  # 30%
EPSS_LOW_THRESHOLD = 0.10  # 10%


def calculate_priority(cve_id: str, kev_cves: set[str], epss_scores: dict[str, float]) -> dict:
    """
    Calculate priority for a CVE based on KEV and EPSS.

    Priority levels:
    - critical: In CISA KEV (actively exploited)
    - high: EPSS >= 0.70
    - medium: EPSS >= 0.30
    - low: EPSS >= 0.10
    - info: EPSS < 0.10 or unknown

    Args:
        cve_id: The CVE ID to calculate priority for.
        kev_cves: Set of CVE IDs in the KEV catalog.
        epss_scores: Dictionary of EPSS scores.

    Returns:
        Dictionary with priority information.
    """

    in_kev = cve_id in kev_cves
    epss_score = epss_scores.get(cve_id)

    if in_kev:
        priority = "critical"
        reason = "In CISA KEV catalog (actively exploited)"
    elif epss_score is not None:
        if epss_score >= EPSS_HIGH_THRESHOLD:
            priority = "high"
            reason = f"EPSS score {epss_score:.2%} >= {EPSS_HIGH_THRESHOLD:.0%}"
        elif epss_score >= EPSS_MEDIUM_THRESHOLD:
            priority = "medium"
            reason = f"EPSS score {epss_score:.2%} >= {EPSS_MEDIUM_THRESHOLD:.0%}"
        elif epss_score >= EPSS_LOW_THRESHOLD:
            priority = "low"
            reason = f"EPSS score {epss_score:.2%} >= {EPSS_LOW_THRESHOLD:.0%}"
        else:
            priority = "info"
            reason = f"EPSS score {epss_score:.2%} < {EPSS_LOW_THRESHOLD:.0%}"
    else:
        priority = "info"
        reason = "No EPSS data available and not in CISA KEV"

    return {
        "priority": priority,
        "in_kev": in_kev,
        "epss_score": epss_score,
        "reason": reason,
    }
