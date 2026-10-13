"""
Passive subdomain discovery via crt.sh (Certificate Transparency logs).

crt.sh reads public CT logs - no traffic to the target. It is often slow or
returns 502, so we retry with a timeout and, if it stays unavailable, report
that clearly instead of failing the whole recon.
"""

import asyncio
import logging
from typing import Dict, Optional

import httpx

log = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"
TIMEOUT = 20.0
RETRIES = 3


def _extract(entries, domain: str) -> list:
    """Unique hostnames under `domain` from crt.sh entries (wildcards dropped)."""
    names = set()
    suffix = "." + domain.lower()
    for entry in entries:
        for raw in (entry.get("name_value") or "").split("\n"):
            name = raw.strip().lower().lstrip("*.")
            if name and (name == domain.lower() or name.endswith(suffix)):
                names.add(name)
    return sorted(names)


async def fetch_subdomains(domain: str, client: Optional[httpx.AsyncClient] = None) -> Dict:
    """Return {"subdomains": [...], "available": bool, "error": str | None}.

    `available` is False when crt.sh could not be reached after retries; the
    recon still succeeds, just without CT data.
    """
    owns_client = client is None
    client = client or httpx.AsyncClient()
    try:
        last_error = None
        for attempt in range(RETRIES):
            try:
                resp = await client.get(CRTSH_URL, params={"q": f"%.{domain}", "output": "json"},
                                        timeout=TIMEOUT, headers={"User-Agent": "VIPER-recon"})
                if resp.status_code == 200:
                    return {"subdomains": _extract(resp.json(), domain), "available": True, "error": None}
                last_error = f"crt.sh returned HTTP {resp.status_code}"
            except Exception as exc:
                last_error = str(exc)
            log.info("crt.sh attempt %d/%d for %s failed: %s", attempt + 1, RETRIES, domain, last_error)
            await asyncio.sleep(1.5 * (attempt + 1))

        return {"subdomains": [], "available": False,
                "error": f"crt.sh unavailable ({last_error}). Certificate-transparency data was skipped."}
    finally:
        if owns_client:
            await client.aclose()
