# VulnSort

Automated mirror of the [CISA Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

## Data

The KEV database is stored in `data/cisa_kev.json` and is automatically updated every 24 hours via GitHub Actions.

| File | Description |
|------|-------------|
| `data/cisa_kev.json` | Full KEV catalog in JSON format |
| `data/metadata.json` | Fetch metadata (last update, version, count) |

## Source

Data is fetched from the official CISA feed:
- **URL:** https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- **Documentation:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## Usage

### Manual Fetch

```bash
python3 scripts/fetch_cisa_kev.py
```

### GitHub Actions

The workflow runs automatically:
- **Schedule:** Every 24 hours at 06:00 UTC
- **On push:** When scripts or workflow files change

## JSON Structure

```json
{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2025.11.28",
  "dateReleased": "2025-11-28T17:48:26.2003Z",
  "count": 1464,
  "vulnerabilities": [
    {
      "cveID": "CVE-2021-26829",
      "vendorProject": "OpenPLC",
      "product": "ScadaBR",
      "vulnerabilityName": "OpenPLC ScadaBR Cross-site Scripting Vulnerability",
      "dateAdded": "2025-11-28",
      "shortDescription": "...",
      "requiredAction": "...",
      "dueDate": "2025-12-19",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": "...",
      "cwes": ["CWE-79"]
    }
  ]
}
```

## License

See [LICENSE](../LICENSE) for details.
