"""
Light HTTP fingerprint: one request to a host, the way a browser visiting the
page would - NOT a port scan. Records the status, the Server / X-Powered-By
headers and the page <title>. HTTPS is tried first, then HTTP.
"""

import logging
import re
from typing import Dict, Optional

import httpx

log = logging.getLogger(__name__)

TIMEOUT = 10.0
USER_AGENT = "Mozilla/5.0 (compatible; VIPER-recon/1.0)"
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _title(html: str) -> Optional[str]:
    match = _TITLE_RE.search(html)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:200] or None


async def fingerprint(host: str, client: Optional[httpx.AsyncClient] = None) -> Dict:
    """One page request to `host`. Returns what the response revealed, or
    reachable=False if neither HTTPS nor HTTP answered."""
    owns_client = client is None
    client = client or httpx.AsyncClient(follow_redirects=True, verify=False)
    try:
        for scheme in ("https", "http"):
            try:
                resp = await client.get(f"{scheme}://{host}", timeout=TIMEOUT,
                                        headers={"User-Agent": USER_AGENT})
            except Exception as exc:
                log.debug("fingerprint %s://%s failed: %s", scheme, host, exc)
                continue

            ctype = resp.headers.get("content-type", "")
            html = resp.text if ctype.startswith("text/") else ""
            return {
                "host": host,
                "reachable": True,
                "url": str(resp.url),
                "status": resp.status_code,
                "server": resp.headers.get("server"),
                "powered_by": resp.headers.get("x-powered-by"),
                "title": _title(html),
            }
        return {"host": host, "reachable": False, "url": None, "status": None,
                "server": None, "powered_by": None, "title": None}
    finally:
        if owns_client:
            await client.aclose()
