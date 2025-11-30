"""
SARIF format parser.

SARIF (Static Analysis Results Interchange Format) is a standardized format
for security tool output. This parser supports SARIF 2.1.0 output from tools
like Trivy and Grype when run with --format sarif.

GitHub Security tab uses these SARIF fields for severity:
- defaultConfiguration.level: "error" (critical/high), "warning" (medium), "note" (low/info)
- properties.security-severity: numeric score (0-10) used for sorting and display
"""

from ..priority import calculate_priority

# Map vulnsort priority to SARIF level (for GitHub Security tab)
PRIORITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Map vulnsort priority to security-severity score (0-10 scale for GitHub)
PRIORITY_TO_SECURITY_SEVERITY = {
    "critical": "10.0",
    "high": "8.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "1.0",
}


def _format_vulnsort_text(priority_info: dict) -> str:
    """
    Format vulnsort priority info as plain text.

    Args:
        priority_info: Dictionary containing priority information.

    Returns:
        Formatted string with vulnsort priority info.
    """

    priority = priority_info["priority"].upper()
    reason = priority_info["reason"]
    in_kev = priority_info["in_kev"]
    epss = priority_info["epss_score"]

    lines = [
        "",
        "--- VulnSort Priority ---",
        f"Priority: {priority}",
        f"Reason: {reason}",
        f"In CISA KEV: {'Yes' if in_kev else 'No'}",
    ]
    if epss is not None:
        lines.append(f"EPSS Score: {epss:.2%}")

    return "\n".join(lines)


def _format_vulnsort_markdown(priority_info: dict) -> str:
    """
    Format vulnsort priority info as markdown.

    Args:
        priority_info: Dictionary containing priority information.

    Returns:
        Formatted string with vulnsort priority info.
    """

    priority = priority_info["priority"].upper()
    reason = priority_info["reason"]
    in_kev = priority_info["in_kev"]
    epss = priority_info["epss_score"]

    epss_str = f"{epss:.2%}" if epss is not None else "N/A"
    kev_str = "✅ Yes" if in_kev else "❌ No"

    return f"""

---
**🛡️ VulnSort Priority: {priority}**

| Metric | Value |
| --- | --- |
| Priority | **{priority}** |
| In CISA KEV | {kev_str} |
| EPSS Score | {epss_str} |

*{reason}*"""


def extract_cve_ids(data: dict) -> list[str]:
    """
    Extract CVE IDs from SARIF format.

    CVE IDs are typically found in:
    - runs[].tool.driver.rules[].id
    - runs[].results[].ruleId

    Args:
        data: The parsed SARIF JSON data.

    Returns:
        List of unique CVE IDs.
    """

    cve_ids = []

    for run in data.get("runs", []):
        # Extract from rules
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            rule_id = rule.get("id", "")
            if rule_id.startswith("CVE-"):
                cve_ids.append(rule_id)

        # Also check results for CVE IDs (some scanners put CVEs here)
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            if rule_id.startswith("CVE-"):
                cve_ids.append(rule_id)

    return list(set(cve_ids))


def process(data: dict, kev_cves: set[str], epss_scores: dict[str, float]) -> dict:
    """
    Process SARIF JSON and update severity fields based on vulnsort priority.

    Updates SARIF severity fields (level, security-severity) so GitHub Security
    tab displays vulnerabilities with KEV/EPSS-based severity instead of CVSS.

    Args:
        data: The parsed SARIF JSON data.
        kev_cves: Set of CVE IDs in the KEV catalog.
        epss_scores: Dictionary of EPSS scores.

    Returns:
        The processed SARIF data with updated severity fields.
    """

    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})

        # Update rules with vulnsort severity
        for rule in driver.get("rules", []):
            rule_id = rule.get("id", "")
            if rule_id.startswith("CVE-"):
                priority_info = calculate_priority(rule_id, kev_cves, epss_scores)
                priority = priority_info["priority"]

                # Initialize properties if not present
                if "properties" not in rule:
                    rule["properties"] = {}

                # Add vulnsort info to properties
                rule["properties"]["vulnsort"] = priority_info

                # Update security-severity for GitHub Security tab
                rule["properties"]["security-severity"] = PRIORITY_TO_SECURITY_SEVERITY[priority]

                # Update defaultConfiguration.level for GitHub Security tab
                if "defaultConfiguration" not in rule:
                    rule["defaultConfiguration"] = {}
                rule["defaultConfiguration"]["level"] = PRIORITY_TO_SARIF_LEVEL[priority]

                # Append vulnsort reasoning to help text
                if "help" in rule:
                    if "text" in rule["help"]:
                        rule["help"]["text"] += _format_vulnsort_text(priority_info)
                    if "markdown" in rule["help"]:
                        rule["help"]["markdown"] += _format_vulnsort_markdown(priority_info)

        # Update results with vulnsort severity
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            if rule_id.startswith("CVE-"):
                priority_info = calculate_priority(rule_id, kev_cves, epss_scores)
                priority = priority_info["priority"]

                # Initialize properties if not present
                if "properties" not in result:
                    result["properties"] = {}

                result["properties"]["vulnsort"] = priority_info

                # Update result level for GitHub Security tab
                result["level"] = PRIORITY_TO_SARIF_LEVEL[priority]

                # Append vulnsort reasoning to message text
                if "message" in result and "text" in result["message"]:
                    result["message"]["text"] += f" [VulnSort: {priority.upper()} - {priority_info['reason']}]"

    return data
