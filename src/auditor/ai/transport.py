"""The real HTTP transport (requests-based; requests is already a core
dependency — no per-provider SDKs). Enforced here, not in callers:

- TLS verification ON (requests' default, never disabled);
- redirects NEVER followed (a 3xx is returned as-is and rejected upstream,
  so an Authorization header can never be re-sent to a redirect target);
- hard timeout on connect+read;
- BOUNDED body read (cap+1 streaming read — an oversized response is
  rejected without ever being slurped into memory);
- failures map to legal codes only; the original exception text (which may
  carry URLs or machine paths) is dropped.
"""
from __future__ import annotations

from typing import Any

import requests

from auditor.ai.contract import (
    MAX_RESPONSE_BYTES,
    HttpResponse,
    TransportFailure,
)


class RequestsTransport:
    def __init__(self, max_response_bytes: int = MAX_RESPONSE_BYTES) -> None:
        self._cap = max_response_bytes

    def request(self, method: str, url: str, headers: dict[str, str],
                json_body: dict[str, Any] | None,
                timeout: float) -> HttpResponse:
        try:
            resp = requests.request(
                method, url, headers=headers, json=json_body,
                timeout=timeout, allow_redirects=False, stream=True)
        except requests.Timeout as e:
            raise TransportFailure("timeout") from e
        except (requests.RequestException, OSError) as e:
            raise TransportFailure("connection_failed") from e
        try:
            body = resp.raw.read(self._cap + 1, decode_content=True)
        except (requests.RequestException, OSError) as e:
            raise TransportFailure("connection_failed") from e
        finally:
            resp.close()
        if len(body) > self._cap:
            raise TransportFailure("invalid_response")
        return HttpResponse(status=resp.status_code, body=body)
