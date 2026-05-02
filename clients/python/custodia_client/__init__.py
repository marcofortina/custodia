from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import requests


@dataclass(frozen=True)
class CustodiaClient:
    server_url: str
    cert_file: str
    key_file: str
    ca_file: str
    timeout: float = 15.0

    def create_secret(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/v1/secrets", json=payload)

    def list_secrets(self) -> dict[str, Any]:
        return self._request("GET", "/v1/secrets")

    def get_secret(self, secret_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/secrets/{_path_escape(secret_id)}")

    def share_secret(self, secret_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/v1/secrets/{_path_escape(secret_id)}/share", json=payload)

    def request_access_grant(self, secret_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/v1/secrets/{_path_escape(secret_id)}/access-requests", json=payload)

    def activate_access_grant(self, secret_id: str, client_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/secrets/{_path_escape(secret_id)}/access/{_path_escape(client_id)}/activate",
            json=payload,
        )

    def revoke_access(self, secret_id: str, client_id: str) -> dict[str, Any]:
        return self._request("DELETE", f"/v1/secrets/{_path_escape(secret_id)}/access/{_path_escape(client_id)}")

    def create_secret_version(self, secret_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/v1/secrets/{_path_escape(secret_id)}/versions", json=payload)

    def delete_secret(self, secret_id: str) -> dict[str, Any]:
        return self._request("DELETE", f"/v1/secrets/{_path_escape(secret_id)}")

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        response = requests.request(
            method,
            f"{self.server_url}{path}",
            cert=(self.cert_file, self.key_file),
            verify=self.ca_file,
            timeout=self.timeout,
            **kwargs,
        )
        response.raise_for_status()
        if not response.content:
            return {}
        return response.json()


def _path_escape(value: str) -> str:
    return quote(value, safe="")
