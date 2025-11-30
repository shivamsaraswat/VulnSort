# VulnSort

Prioritize vulnerabilities based on **CISA KEV** and **EPSS** scores.

## What it does

VulnSort takes vulnerability scan results (Trivy or Grype) and adds priority levels based on real-world exploitability:

| Priority | Criteria |
|----------|----------|
| 🔴 Critical | In CISA KEV (actively exploited) |
| 🟠 High | EPSS ≥ 70% |
| 🟡 Medium | EPSS ≥ 30% |
| 🟢 Low | EPSS ≥ 10% |
| ⚪ Info | EPSS < 10% |

## Usage

### CLI

```bash
# Install
pip install requests

# Run
python -m src.vulnsort -i scan-results.json -o prioritized.json
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

      # Run Trivy scan
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
      - name: Check critical vulnerabilities
        if: steps.vulnsort.outputs.critical-count > 0
        run: |
          echo "Found ${{ steps.vulnsort.outputs.critical-count }} critical vulnerabilities!"
          exit 1
```

## Supported Scanners

- [Trivy](https://github.com/aquasecurity/trivy)
- [Grype](https://github.com/anchore/grype)

## License

See [LICENSE](LICENSE) for details.
