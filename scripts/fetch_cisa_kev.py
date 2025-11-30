#!/usr/bin/env python3
"""
Fetch CISA Known Exploited Vulnerabilities (KEV) catalog and keep a copy locally.

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DATA_DIR = Path(__file__).parent.parent / "data"
OUTPUT_FILE = DATA_DIR / "cisa_kev.json"
METADATA_FILE = DATA_DIR / "metadata.json"

USER_AGENT = "VulnSort-KEV-Fetcher/1.0"


def fetch_kev_data() -> dict:
    """
    Fetch the KEV catalog from CISA.

    Returns:
        dict: The KEV catalog data.

    Raises:
        requests.exceptions.HTTPError: If the HTTP request fails with a non-200 status code.
        requests.exceptions.RequestException: If the request fails for any reason.
        json.JSONDecodeError: If the JSON data is invalid.
    """

    print(f"Fetching KEV data from {KEV_URL}...")

    try:
        response = requests.get(
            KEV_URL,
            headers={"User-Agent": USER_AGENT},
            timeout=60,
        )
        response.raise_for_status()
        data = response.json()
        print(f"Successfully fetched {data.get('count', 'unknown')} vulnerabilities")
        return data
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e.response.status_code} - {e}", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"JSON Decode Error: {e}", file=sys.stderr)
        sys.exit(1)


def load_existing_data() -> dict | None:
    """
    Load existing KEV data if present.

    Returns:
        dict | None: The existing KEV data or None if the file does not exist or is invalid.

    Raises:
        json.JSONDecodeError: If the JSON data is invalid.
        IOError: If the file cannot be read.
    """

    if OUTPUT_FILE.exists():
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None
    return None


def save_data(data: dict) -> None:
    """
    Save KEV data to file.

    Args:
        data: The KEV catalog data to save.

    Raises:
        IOError: If the file cannot be written.
        PermissionError: If the file cannot be written due to permissions.
    """

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"Saved KEV data to {OUTPUT_FILE}")


def save_metadata(data: dict, updated: bool) -> None:
    """
    Save metadata about the last fetch.

    Args:
        data: The KEV catalog data to save.
        updated: Whether the data was updated since the last fetch.

    Raises:
        IOError: If the file cannot be written.
        PermissionError: If the file cannot be written due to permissions.
    """

    metadata = {
        "last_fetch": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "catalog_version": data.get("catalogVersion"),
        "date_released": data.get("dateReleased"),
        "vulnerability_count": data.get("count"),
        "data_updated": updated,
    }

    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Saved metadata to {METADATA_FILE}")


def has_data_changed(old_data: dict | None, new_data: dict) -> bool:
    """
    Check if the KEV data has changed.

    Args:
        old_data: The existing KEV data.
        new_data: The new KEV data to compare.

    Returns:
        bool: True if the data has changed, False otherwise.
    """

    if old_data is None:
        return True

    # Compare catalog version and count
    old_version = old_data.get("catalogVersion")
    new_version = new_data.get("catalogVersion")

    if old_version != new_version:
        print(f"Catalog version changed: {old_version} -> {new_version}")
        return True

    old_count = old_data.get("count")
    new_count = new_data.get("count")

    if old_count != new_count:
        print(f"Vulnerability count changed: {old_count} -> {new_count}")
        return True

    print("No changes detected in KEV catalog")
    return False


def main() -> int:
    """
    Main entry point for fetching the KEV catalog.

    Returns:
        int: 0 if successful, 1 if there was an error.
    """

    # Print header
    print("=" * 60)
    print("CISA KEV Database Fetcher")
    print("=" * 60)

    # Load existing data if present
    existing_data = load_existing_data()

    # Fetch fresh data from CISA
    new_data = fetch_kev_data()

    # Check for changes since the last fetch
    updated = has_data_changed(existing_data, new_data)

    # Save data if it has changed
    if updated:
        save_data(new_data)
        print("\n✓ KEV database has been updated")
    else:
        print("\n✓ KEV database is already up to date")

    # Always save metadata
    save_metadata(new_data, updated)

    # Output for GitHub Actions
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"updated={str(updated).lower()}\n")
            f.write(f"count={new_data.get('count', 0)}\n")
            f.write(f"version={new_data.get('catalogVersion', 'unknown')}\n")

    return 0 if not updated else 0  # Always exit 0 for success


if __name__ == "__main__":
    sys.exit(main())
