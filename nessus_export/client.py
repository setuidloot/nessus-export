"""Minimal Nessus REST API client (standard library only).

Covers the endpoints needed for listing scans and exporting results, both via
the native export API and via the direct scan/host/plugin read endpoints used
by the reconstruction fallback.
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


class NessusError(Exception):
    """Generic error returned by the Nessus API."""


class TrialModeError(NessusError):
    """Raised when an action is blocked because the server is in trial mode.

    Nessus Essentials / trial installs return errors such as
    "Export is not allowed in trial mode." for the native export endpoints.
    """


class AuthError(NessusError):
    """Raised on 401/403 — bad or missing API keys."""


def _looks_like_trial(message: str) -> bool:
    m = message.lower()
    return "trial mode" in m or "purchase a full nessus license" in m


class NessusClient:
    def __init__(
        self,
        url: str = "https://localhost:8834",
        access_key: str = "",
        secret_key: str = "",
        verify_ssl: bool = False,
        ca_bundle: Optional[str] = None,
        timeout: int = 60,
    ) -> None:
        if not access_key or not secret_key:
            raise AuthError("access_key and secret_key are required")
        self.url = url.rstrip("/")
        self.timeout = timeout
        self._headers = {
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
            "Content-Type": "application/json",
        }
        if ca_bundle:
            self._ctx = ssl.create_default_context(cafile=ca_bundle)
        elif verify_ssl:
            self._ctx = ssl.create_default_context()
        else:
            self._ctx = ssl.create_default_context()
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    # -- low level ---------------------------------------------------------
    def _request(self, method: str, path: str, body: Optional[dict] = None,
                 raw: bool = False):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.url + path, data=data, headers=self._headers, method=method
        )
        try:
            with urllib.request.urlopen(req, context=self._ctx,
                                        timeout=self.timeout) as resp:
                payload = resp.read()
        except urllib.error.HTTPError as e:
            payload = e.read()
            message = self._extract_error(payload) or f"HTTP {e.code}"
            # Trial-mode restrictions come back as 403, so check the message
            # text before treating a 403 as an authentication failure.
            if _looks_like_trial(message):
                raise TrialModeError(message) from None
            if e.code in (401, 403):
                raise AuthError(message) from None
            raise NessusError(message) from None
        except urllib.error.URLError as e:
            raise NessusError(f"could not reach {self.url}: {e.reason}") from None

        if raw:
            # Even on 200, an export download may actually be a JSON error body.
            message = self._extract_error(payload)
            if message and _looks_like_trial(message):
                raise TrialModeError(message)
            return payload

        parsed = json.loads(payload) if payload else {}
        if isinstance(parsed, dict) and parsed.get("error"):
            message = parsed["error"]
            if _looks_like_trial(message):
                raise TrialModeError(message)
            raise NessusError(message)
        return parsed

    @staticmethod
    def _extract_error(payload: bytes) -> Optional[str]:
        try:
            obj = json.loads(payload)
        except (ValueError, TypeError):
            return None
        if isinstance(obj, dict) and obj.get("error"):
            return str(obj["error"])
        return None

    # -- high level --------------------------------------------------------
    def server_status(self) -> Dict[str, Any]:
        return self._request("GET", "/server/status")

    def list_scans(self) -> List[Dict[str, Any]]:
        data = self._request("GET", "/scans")
        return data.get("scans") or []

    def resolve_scan(self, ref: str) -> Dict[str, Any]:
        """Resolve a scan by numeric id or by (case-insensitive) name."""
        scans = self.list_scans()
        if ref.isdigit():
            for s in scans:
                if str(s.get("id")) == ref:
                    return s
        matches = [s for s in scans if (s.get("name") or "").lower() == ref.lower()]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            ids = ", ".join(str(m["id"]) for m in matches)
            raise NessusError(
                f"scan name {ref!r} is ambiguous (ids: {ids}); use the id"
            )
        raise NessusError(f"no scan matching {ref!r}")

    def get_scan(self, scan_id: int) -> Dict[str, Any]:
        return self._request("GET", f"/scans/{scan_id}")

    def get_host(self, scan_id: int, host_id: int) -> Dict[str, Any]:
        return self._request("GET", f"/scans/{scan_id}/hosts/{host_id}")

    def get_plugin(self, scan_id: int, host_id: int, plugin_id: int) -> Dict[str, Any]:
        return self._request(
            "GET", f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}"
        )

    # -- native export -----------------------------------------------------
    def export_request(self, scan_id: int, fmt: str,
                       extra: Optional[dict] = None) -> Any:
        body: Dict[str, Any] = {"format": fmt}
        if extra:
            body.update(extra)
        data = self._request("POST", f"/scans/{scan_id}/export", body=body)
        # Nessus returns {"file": <id>, "token": <token>} (token on newer builds)
        return data.get("file"), data.get("token")

    def export_status(self, scan_id: int, file_id: Any) -> str:
        data = self._request("GET", f"/scans/{scan_id}/export/{file_id}/status")
        return data.get("status", "")

    def export_download(self, scan_id: int, file_id: Any) -> bytes:
        return self._request(
            "GET", f"/scans/{scan_id}/export/{file_id}/download", raw=True
        )

    def wait_and_download(self, scan_id: int, file_id: Any,
                          poll_interval: float = 2.0,
                          max_wait: float = 600.0) -> bytes:
        waited = 0.0
        while waited < max_wait:
            if self.export_status(scan_id, file_id) == "ready":
                return self.export_download(scan_id, file_id)
            time.sleep(poll_interval)
            waited += poll_interval
        raise NessusError(f"export {file_id} not ready after {max_wait:.0f}s")
