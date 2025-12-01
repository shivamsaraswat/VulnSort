#!/usr/bin/env python3
"""
VulnSort - Prioritize vulnerabilities based on CISA KEV and EPSS scores.

Supported scanner formats:
- Trivy (JSON or SARIF)
- Grype (JSON or SARIF)
- Any SARIF 2.1.0 compatible scanner output
"""

import argparse
import json
import sys
from pathlib import Path

from .parsers import (detect_scanner_format, extract_grype_cves,
                      extract_grype_severities, extract_sarif_cves,
                      extract_sarif_severities, extract_trivy_cves,
                      extract_trivy_severities, process_grype, process_sarif,
                      process_trivy)
from .utils import fetch_epss_scores, load_kev_data

# Default path to local KEV data (relative to repo root)
DEFAULT_KEV_PATH = Path(__file__).parent.parent / "data" / "cisa_kev.json"


def process_vulnerabilities(input_file: Path, output_file: Path | None, kev_path: Path | None) -> int:
    """
    Main processing function.

    Args:
        input_file: Path to the input JSON file.
        output_file: Path to the output JSON file (or None for stdout).
        kev_path: Optional path to KEV data file.

    Returns:
        0 on success, 1 on error.
    """
    # Load input file
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in input file: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"Error: Input file not found: {input_file}", file=sys.stderr)
        return 1

    # Detect scanner format
    scanner = detect_scanner_format(data)
    if scanner is None:
        print("Error: Unknown scanner format. Supported formats: Trivy, Grype, SARIF", file=sys.stderr)
        return 1

    print(f"Detected scanner format: {scanner}", file=sys.stderr)

    # Extract CVE IDs and original severities based on scanner format
    if scanner == "trivy":
        cve_ids = extract_trivy_cves(data)
        original_severities = extract_trivy_severities(data)
    elif scanner == "grype":
        cve_ids = extract_grype_cves(data)
        original_severities = extract_grype_severities(data)
    elif scanner == "sarif":
        cve_ids = extract_sarif_cves(data)
        original_severities = extract_sarif_severities(data)
    else:
        cve_ids = []
        original_severities = {}

    total_occurrences = sum(original_severities.values())
    print(f"Found {len(cve_ids)} unique CVEs ({total_occurrences} total occurrences)", file=sys.stderr)

    if not cve_ids:
        print("Warning: No CVEs found in input file", file=sys.stderr)

    # Load KEV data
    kev_cves = load_kev_data(kev_path or DEFAULT_KEV_PATH)

    # Fetch EPSS scores
    epss_scores = fetch_epss_scores(cve_ids)

    # Process based on scanner format
    if scanner == "trivy":
        result = process_trivy(data, kev_cves, epss_scores)
    elif scanner == "grype":
        result = process_grype(data, kev_cves, epss_scores)
    elif scanner == "sarif":
        result = process_sarif(data, kev_cves, epss_scores)
    else:
        result = data

    # Count priorities from all occurrences (total)
    priority_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    if scanner == "sarif":
        # Count from results (all occurrences), looking up priority from rules
        for run in result.get("runs", []):
            # Build map of rule_id -> priority from rules
            rule_priorities: dict[str, str] = {}
            driver = run.get("tool", {}).get("driver", {})
            for rule in driver.get("rules", []):
                rule_id = rule.get("id", "")
                vulnsort = rule.get("properties", {}).get("vulnsort")
                if vulnsort:
                    rule_priorities[rule_id] = vulnsort.get("priority", "info")

            # Count all results using the priority from their rule
            for res in run.get("results", []):
                rule_id = res.get("ruleId", "")
                if rule_id in rule_priorities:
                    priority = rule_priorities[rule_id]
                    priority_counts[priority] = priority_counts.get(priority, 0) + 1
    elif scanner == "trivy":
        for res in result.get("Results", []):
            for vuln in res.get("Vulnerabilities", []):
                vulnsort = vuln.get("vulnsort")
                if vulnsort:
                    priority = vulnsort.get("priority", "info")
                    priority_counts[priority] = priority_counts.get(priority, 0) + 1
    elif scanner == "grype":
        for match in result.get("matches", []):
            vulnsort = match.get("vulnsort")
            if vulnsort:
                priority = vulnsort.get("priority", "info")
                priority_counts[priority] = priority_counts.get(priority, 0) + 1

    # Print summary
    print("\n" + "=" * 50, file=sys.stderr)
    print("Scanner Original Severity Counts", file=sys.stderr)
    print("=" * 50, file=sys.stderr)
    # Display original severities in order: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    for sev in severity_order:
        if sev in original_severities:
            print(f"  {sev.capitalize():12} {original_severities[sev]}", file=sys.stderr)
    # Show any other severities not in the standard order
    for sev, count in sorted(original_severities.items()):
        if sev not in severity_order:
            print(f"  {sev.capitalize():12} {count}", file=sys.stderr)
    if not original_severities:
        print("  (no severity data found)", file=sys.stderr)

    print("\n" + "=" * 50, file=sys.stderr)
    print("VulnSort Priority Summary", file=sys.stderr)
    print("=" * 50, file=sys.stderr)
    print(f"  Critical (KEV):     {priority_counts['critical']}", file=sys.stderr)
    print(f"  High (EPSS>=70%):   {priority_counts['high']}", file=sys.stderr)
    print(f"  Medium (EPSS>=30%): {priority_counts['medium']}", file=sys.stderr)
    print(f"  Low (EPSS>=10%):    {priority_counts['low']}", file=sys.stderr)
    print(f"  Info (EPSS<10%):    {priority_counts['info']}", file=sys.stderr)
    print("=" * 50, file=sys.stderr)

    # Output result
    output_json = json.dumps(result, indent=2, ensure_ascii=False)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output_json)
        print(f"\nOutput written to: {output_file}", file=sys.stderr)
    else:
        print(output_json)

    return 0


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="VulnSort - Prioritize vulnerabilities based on CISA KEV and EPSS scores",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported scanner formats:
  - Trivy (JSON or SARIF, auto-detected)
  - Grype (JSON or SARIF, auto-detected)
  - Any SARIF 2.1.0 compatible output

Priority levels:
  - critical: In CISA KEV (actively exploited)
  - high:     EPSS score >= 70%
  - medium:   EPSS score >= 30%
  - low:      EPSS score >= 10%
  - info:     EPSS score < 10% or unknown

Examples:
  python -m src.vulnsort -i scan-results.json
  python -m src.vulnsort -i scan-results.sarif -o prioritized.sarif
  python -m src.vulnsort -i scan-results.json -o prioritized.json
  python -m src.vulnsort -i scan-results.json -k /path/to/kev.json
        """,
    )

    parser.add_argument("-i", "--input", required=True, type=Path, help="Input file from vulnerability scanner (JSON or SARIF)")
    parser.add_argument("-o", "--output", required=False, type=Path, help="Output file (default: stdout)")
    parser.add_argument("-k", "--kev-path", required=False, type=Path, help="Path to CISA KEV JSON file")

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()
    return process_vulnerabilities(args.input, args.output, args.kev_path)


if __name__ == "__main__":
    sys.exit(main())
