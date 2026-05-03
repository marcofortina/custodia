from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode
import re

import requests


@dataclass(frozen=True)
class CustodiaClient:
    server_url: str
    cert_file: str
    key_file: str
    ca_file: str
    timeout: float = 15.0


    def me(self) -> dict[str, Any]:
        return self._request("GET", "/v1/me")

    def list_clients(self, limit: int | None = None, active: bool | None = None) -> dict[str, Any]:
        _validate_optional_limit(limit)
        query = _query_params(
            limit=str(limit) if limit is not None else None,
            active=str(active).lower() if active is not None else None,
        )
        path = "/v1/clients"
        if query:
            path += f"?{query}"
        return self._request("GET", path)

    def get_client(self, client_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/clients/{_path_escape(client_id)}")

    def create_client(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/v1/clients", json=payload)

    def revoke_client(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/v1/clients/revoke", json=payload)

    def list_audit_events(
        self,
        limit: int | None = None,
        outcome: str | None = None,
        action: str | None = None,
        actor_client_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
    ) -> dict[str, Any]:
        _validate_optional_limit(limit)
        _validate_audit_filters(outcome, action, actor_client_id, resource_type, resource_id)
        query = _query_params(
            limit=str(limit) if limit is not None else None,
            outcome=outcome,
            action=action,
            actor_client_id=actor_client_id,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        path = "/v1/audit-events"
        if query:
            path += f"?{query}"
        return self._request("GET", path)


    def export_audit_events(
        self,
        limit: int | None = None,
        outcome: str | None = None,
        action: str | None = None,
        actor_client_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
    ) -> str:
        _validate_optional_limit(limit)
        _validate_audit_filters(outcome, action, actor_client_id, resource_type, resource_id)
        query = _query_params(
            limit=str(limit) if limit is not None else None,
            outcome=outcome,
            action=action,
            actor_client_id=actor_client_id,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        path = "/v1/audit-events/export"
        if query:
            path += f"?{query}"
        return self._request_text("GET", path)

    def export_audit_events_with_metadata(
        self,
        limit: int | None = None,
        outcome: str | None = None,
        action: str | None = None,
        actor_client_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
    ) -> dict[str, str]:
        _validate_optional_limit(limit)
        _validate_audit_filters(outcome, action, actor_client_id, resource_type, resource_id)
        query = _query_params(
            limit=str(limit) if limit is not None else None,
            outcome=outcome,
            action=action,
            actor_client_id=actor_client_id,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        path = "/v1/audit-events/export"
        if query:
            path += f"?{query}"
        response = self._request_response("GET", path)
        return {
            "body": response.text,
            "sha256": response.headers.get("X-Custodia-Audit-Export-SHA256", ""),
            "event_count": response.headers.get("X-Custodia-Audit-Export-Events", ""),
        }

    def list_access_grant_requests(
        self,
        secret_id: str | None = None,
        status: str | None = None,
        client_id: str | None = None,
        requested_by_client_id: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        _validate_optional_limit(limit)
        _validate_access_request_filters(secret_id, status, client_id, requested_by_client_id)
        query = _query_params(
            secret_id=secret_id,
            status=status,
            client_id=client_id,
            requested_by_client_id=requested_by_client_id,
            limit=str(limit) if limit is not None else None,
        )
        path = "/v1/access-requests"
        if query:
            path += f"?{query}"
        return self._request("GET", path)

    def create_secret(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/v1/secrets", json=payload)

    def list_secrets(self, limit: int | None = None) -> dict[str, Any]:
        _validate_optional_limit(limit)
        query = _query_params(limit=str(limit) if limit is not None else None)
        path = "/v1/secrets"
        if query:
            path += f"?{query}"
        return self._request("GET", path)

    def get_secret(self, secret_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/secrets/{_path_escape(secret_id)}")

    def list_secret_versions(self, secret_id: str, limit: int | None = None) -> dict[str, Any]:
        _validate_optional_limit(limit)
        query = _query_params(limit=str(limit) if limit is not None else None)
        path = f"/v1/secrets/{_path_escape(secret_id)}/versions"
        if query:
            path += f"?{query}"
        return self._request("GET", path)

    def list_secret_access(self, secret_id: str, limit: int | None = None) -> dict[str, Any]:
        _validate_optional_limit(limit)
        query = _query_params(limit=str(limit) if limit is not None else None)
        path = f"/v1/secrets/{_path_escape(secret_id)}/access"
        if query:
            path += f"?{query}"
        return self._request("GET", path)

    def status(self) -> dict[str, Any]:
        return self._request("GET", "/v1/status")

    def version(self) -> dict[str, Any]:
        return self._request("GET", "/v1/version")

    def diagnostics(self) -> dict[str, Any]:
        return self._request("GET", "/v1/diagnostics")

    def revocation_status(self) -> dict[str, Any]:
        return self._request("GET", "/v1/revocation/status")

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

    def _request_response(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        response = requests.request(
            method,
            f"{self.server_url}{path}",
            cert=(self.cert_file, self.key_file),
            verify=self.ca_file,
            timeout=self.timeout,
            **kwargs,
        )
        response.raise_for_status()
        return response

    def _request_text(self, method: str, path: str, **kwargs: Any) -> str:
        return self._request_response(method, path, **kwargs).text

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        response = self._request_response(method, path, **kwargs)
        if not response.content:
            return {}
        return response.json()


def _path_escape(value: str) -> str:
    return quote(value, safe="")


def _query_params(**kwargs: str | None) -> str:
    return urlencode({key: value for key, value in kwargs.items() if value})

_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_AUDIT_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def _validate_audit_filters(
    outcome: str | None,
    action: str | None,
    actor_client_id: str | None,
    resource_type: str | None,
    resource_id: str | None,
) -> None:
    if outcome is not None and outcome not in {"success", "failure", "degraded"}:
        raise ValueError("outcome must be success, failure or degraded when set")
    if action is not None and not _bounded_token(action, 128):
        raise ValueError("action filter is invalid")
    if actor_client_id is not None and not _CLIENT_ID_RE.fullmatch(actor_client_id):
        raise ValueError("actor client id filter is invalid")
    if resource_type is not None and not _bounded_token(resource_type, 64):
        raise ValueError("resource type filter is invalid")
    if resource_id is not None and (not resource_id or len(resource_id) > 256 or any(ord(ch) < 32 for ch in resource_id)):
        raise ValueError("resource id filter is invalid")


def _validate_access_request_filters(
    secret_id: str | None,
    status: str | None,
    client_id: str | None,
    requested_by_client_id: str | None,
) -> None:
    if secret_id is not None and not _UUID_RE.fullmatch(secret_id.lower()):
        raise ValueError("secret id filter is invalid")
    if status is not None and status not in {"pending", "activated", "revoked", "expired"}:
        raise ValueError("status filter is invalid")
    if client_id is not None and not _CLIENT_ID_RE.fullmatch(client_id):
        raise ValueError("client id filter is invalid")
    if requested_by_client_id is not None and not _CLIENT_ID_RE.fullmatch(requested_by_client_id):
        raise ValueError("requested by client id filter is invalid")


def _bounded_token(value: str, max_length: int) -> bool:
    return bool(value) and len(value) <= max_length and bool(_AUDIT_TOKEN_RE.fullmatch(value))


def _validate_optional_limit(limit: int | None) -> None:
    if limit is not None and (limit <= 0 or limit > 500):
        raise ValueError("limit must be between 1 and 500 when set")
