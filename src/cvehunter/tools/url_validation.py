"""URL validation against the domain allowlist."""

from __future__ import annotations

from urllib.parse import urlparse

ALLOWED_DOMAINS = {
    "nvd.nist.gov",
    "osv.dev",
    "github.com",
    "gitlab.com",
    "security-tracker.debian.org",
    "access.redhat.com",
    "ubuntu.com",
    "advisories.apache.org",
}


def validate_url(url: str) -> bool:
    """Return True if url's hostname is in ALLOWED_DOMAINS."""
    hostname = urlparse(url).hostname or ""
    return any(hostname == d or hostname.endswith("." + d) for d in ALLOWED_DOMAINS)
