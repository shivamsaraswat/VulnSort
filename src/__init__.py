"""VulnSort - Prioritize vulnerabilities based on CISA KEV and EPSS scores."""

__version__ = "1.0.0"


def __getattr__(name: str):
    """Lazy imports to avoid circular dependency when running as module."""
    if name == "main":
        from .vulnsort import main
        return main
    if name == "process_vulnerabilities":
        from .vulnsort import process_vulnerabilities
        return process_vulnerabilities
    if name == "load_kev_data":
        from .utils import load_kev_data
        return load_kev_data
    if name == "fetch_epss_scores":
        from .utils import fetch_epss_scores
        return fetch_epss_scores
    if name == "calculate_priority":
        from .priority import calculate_priority
        return calculate_priority
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "main",
    "process_vulnerabilities",
    "load_kev_data",
    "fetch_epss_scores",
    "calculate_priority",
]
