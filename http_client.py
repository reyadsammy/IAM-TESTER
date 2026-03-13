"""Shared HTTP client for security testing."""

import time
import requests
from typing import Optional, Tuple, Any
from dataclasses import dataclass


@dataclass
class RequestResult:
    response: Optional[requests.Response]
    duration: float
    error: Optional[str]
    evidence: str = ""


class SecurityTestClient:
    """HTTP client wrapper for security testing with evidence capture."""

    def __init__(self, base_url: str, timeout: int = 10, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl

    def _url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        return f"{self.base_url}{path}"

    def _request(self, method: str, path: str, **kwargs) -> RequestResult:
        url = self._url(path)
        kwargs.setdefault("timeout", self.timeout)
        start = time.time()
        try:
            resp = self.session.request(method, url, **kwargs)
            duration = time.time() - start
            evidence = self._capture_evidence(method, url, kwargs, resp)
            return RequestResult(response=resp, duration=duration, error=None, evidence=evidence)
        except requests.exceptions.ConnectionError:
            return RequestResult(response=None, duration=time.time() - start,
                                 error="Connection refused", evidence=f"{method} {url} -> Connection refused")
        except requests.exceptions.Timeout:
            return RequestResult(response=None, duration=time.time() - start,
                                 error="Request timeout", evidence=f"{method} {url} -> Timeout")
        except Exception as e:
            return RequestResult(response=None, duration=time.time() - start,
                                 error=str(e), evidence=f"{method} {url} -> {e}")

    def _capture_evidence(self, method: str, url: str, kwargs: dict, resp: requests.Response) -> str:
        lines = [f">> {method} {url}"]
        if "json" in kwargs:
            import json
            body = json.dumps(kwargs["json"], indent=2)
            if len(body) > 500:
                body = body[:500] + "... (truncated)"
            lines.append(f">> Body: {body}")
        if "headers" in kwargs:
            for k, v in kwargs["headers"].items():
                lines.append(f">> {k}: {v}")
        lines.append(f"<< HTTP {resp.status_code}")
        for k, v in list(resp.headers.items())[:10]:
            lines.append(f"<< {k}: {v}")
        body = resp.text
        if len(body) > 800:
            body = body[:800] + "... (truncated)"
        if body:
            lines.append(f"<< {body}")
        return "\n".join(lines)

    def get(self, path: str, **kwargs) -> RequestResult:
        return self._request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> RequestResult:
        return self._request("POST", path, **kwargs)

    def put(self, path: str, **kwargs) -> RequestResult:
        return self._request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs) -> RequestResult:
        return self._request("DELETE", path, **kwargs)

    def options(self, path: str, **kwargs) -> RequestResult:
        return self._request("OPTIONS", path, **kwargs)

    def head(self, path: str, **kwargs) -> RequestResult:
        return self._request("HEAD", path, **kwargs)

    def reset_session(self):
        self.session = requests.Session()
        self.session.verify = self.verify_ssl

    def check_connectivity(self) -> Tuple[bool, str]:
        result = self.get("/")
        if result.error:
            return False, result.error
        if result.response and result.response.status_code < 500:
            return True, f"Connected (HTTP {result.response.status_code})"
        return False, f"Unexpected status: {result.response.status_code if result.response else 'no response'}"
