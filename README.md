# VulnSort

A GitHub Action and CLI tool that prioritizes vulnerability scan results based on real-world exploitability using **CISA KEV** and **EPSS** scores instead of CVSS.

## What it does

VulnSort takes vulnerability scan results and adds priority levels based on real-world exploitability instead of CVSS scores. It automatically detects the scanner format and enriches results with KEV/EPSS data.

| Priority | Criteria |
|----------|----------|
| 🔴 Critical | In CISA KEV (actively exploited) |
| 🟠 High | EPSS ≥ 70% |
| 🟡 Medium | EPSS ≥ 30% |
| 🟢 Low | EPSS ≥ 10% |
| ⚪ Info | EPSS < 10% |

## Features

- **Auto-detection** - Automatically detects Trivy, Grype, or SARIF formats
- **SARIF support** - Works with any SARIF 2.1.0 compatible scanner output
- **GitHub Security tab integration** - Updates SARIF severity fields for proper display in GitHub's Security tab
- **Bundled KEV data** - Includes CISA KEV catalog (with option to use custom KEV data)
- **CI/CD ready** - GitHub Action with outputs for workflow decisions

## Usage

### CLI

```bash
# Install
pip install requests

# Run with auto-detection
python -m src.vulnsort -i scan-results.json -o prioritized.json

# Run with SARIF format output
python -m src.vulnsort -i scan-results.sarif -o prioritized.sarif

# Use custom KEV data
python -m src.vulnsort -i scan-results.json -o prioritized.json -k /path/to/kev.json

# Output to stdout
python -m src.vulnsort -i scan-results.json
```

### GitHub Action

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Run Trivy scan (JSON format)
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'my-image:latest'
          format: 'json'
          output: 'trivy-results.json'

      # Prioritize vulnerabilities with VulnSort
      - name: Prioritize vulnerabilities
        uses: shivamsaraswat/VulnSort@main
        id: vulnsort
        with:
          scan-results-file: 'trivy-results.json'
          output-file: 'prioritized-results.json'

      # Use the outputs
      - name: Check results
        run: |
          echo "Critical: ${{ steps.vulnsort.outputs.critical-count }}"
          echo "High: ${{ steps.vulnsort.outputs.high-count }}"
          echo "Medium: ${{ steps.vulnsort.outputs.medium-count }}"
          echo "Low: ${{ steps.vulnsort.outputs.low-count }}"
          echo "Info: ${{ steps.vulnsort.outputs.info-count }}"
          echo "Output file: ${{ steps.vulnsort.outputs.output-file }}"

      # Fail on critical vulnerabilities
      - name: Fail on critical vulnerabilities
        if: steps.vulnsort.outputs.critical-count > 0
        run: |
          echo "Found ${{ steps.vulnsort.outputs.critical-count }} critical vulnerabilities!"
          exit 1
```

#### SARIF with GitHub Security Tab

For full GitHub Security tab integration, use SARIF format:

```yaml
name: Security Scan (SARIF)

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      # Run Trivy scan with SARIF output
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'my-image:latest'
          format: 'sarif'
          output: 'trivy-results.sarif'

      # Prioritize with VulnSort (updates SARIF severity fields)
      - name: Prioritize vulnerabilities
        uses: shivamsaraswat/VulnSort@main
        id: vulnsort
        with:
          scan-results-file: 'trivy-results.sarif'
          output-file: 'prioritized-results.sarif'

      # Upload to GitHub Security tab (now with KEV/EPSS-based severity)
      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'prioritized-results.sarif'

      # Fail on critical/high vulnerabilities
      - name: Fail on high-risk vulnerabilities
        if: steps.vulnsort.outputs.critical-count > 0 || steps.vulnsort.outputs.high-count > 0
        run: exit 1
```

### Action Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `scan-results-file` | Path to scan results file (Trivy, Grype, or SARIF) | Yes | - |
| `output-file` | Path to write prioritized results | No | Overwrites input |
| `kev-path` | Path to custom CISA KEV JSON file | No | Uses bundled data |

### Action Outputs

| Output | Description |
|--------|-------------|
| `critical-count` | Number of critical vulnerabilities (in CISA KEV) |
| `high-count` | Number of high priority vulnerabilities (EPSS ≥ 70%) |
| `medium-count` | Number of medium priority vulnerabilities (EPSS ≥ 30%) |
| `low-count` | Number of low priority vulnerabilities (EPSS ≥ 10%) |
| `info-count` | Number of info priority vulnerabilities (EPSS < 10%) |
| `output-file` | Path to the output file with prioritized results |

The action also generates a **step summary** with a priority table visible in the GitHub Actions UI.

## Supported Scanners

- [Trivy](https://github.com/aquasecurity/trivy) (JSON or SARIF)
- [Grype](https://github.com/anchore/grype) (JSON or SARIF)
- Any SARIF 2.1.0 compatible scanner

## How it works

1. **Reads** vulnerability scan results (auto-detects format)
2. **Checks** each CVE against the CISA Known Exploited Vulnerabilities (KEV) catalog
3. **Fetches** EPSS scores from the FIRST.org EPSS API
4. **Assigns** priority based on KEV membership and EPSS score
5. **Updates** the original output with `vulnsort` metadata (and SARIF severity fields for GitHub integration)

## License

See [LICENSE](LICENSE) for details.
