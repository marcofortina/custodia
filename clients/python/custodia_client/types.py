# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence


PermissionShare = 1
PermissionWrite = 2
PermissionRead = 4
PermissionAll = PermissionShare | PermissionWrite | PermissionRead


@dataclass(frozen=True)
class RecipientEnvelope:
    client_id: str
    envelope: str

    def to_dict(self) -> dict[str, Any]:
        return {"client_id": self.client_id, "envelope": self.envelope}


@dataclass(frozen=True)
class CreateClientPayload:
    client_id: str
    mtls_subject: str

    def to_dict(self) -> dict[str, Any]:
        return {"client_id": self.client_id, "mtls_subject": self.mtls_subject}


@dataclass(frozen=True)
class RevokeClientPayload:
    client_id: str
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"client_id": self.client_id}
        if self.reason:
            payload["reason"] = self.reason
        return payload


@dataclass(frozen=True)
class CreateSecretPayload:
    key: str
    ciphertext: str
    envelopes: Sequence[RecipientEnvelope]
    permissions: int = PermissionAll
    crypto_metadata: Mapping[str, Any] | None = None
    expires_at: str | None = None
    namespace: str = "default"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "key": self.key,
            "ciphertext": self.ciphertext,
            "envelopes": [envelope.to_dict() for envelope in self.envelopes],
            "permissions": self.permissions,
        }
        if self.namespace != "default":
            payload["namespace"] = self.namespace
        if self.crypto_metadata is not None:
            payload["crypto_metadata"] = dict(self.crypto_metadata)
        if self.expires_at:
            payload["expires_at"] = self.expires_at
        return payload


@dataclass(frozen=True)
class CreateSecretVersionPayload:
    ciphertext: str
    envelopes: Sequence[RecipientEnvelope]
    permissions: int = PermissionAll
    crypto_metadata: Mapping[str, Any] | None = None
    expires_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ciphertext": self.ciphertext,
            "envelopes": [envelope.to_dict() for envelope in self.envelopes],
            "permissions": self.permissions,
        }
        if self.crypto_metadata is not None:
            payload["crypto_metadata"] = dict(self.crypto_metadata)
        if self.expires_at:
            payload["expires_at"] = self.expires_at
        return payload


@dataclass(frozen=True)
class ShareSecretPayload:
    version_id: str
    target_client_id: str
    envelope: str
    permissions: int = PermissionRead
    expires_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "version_id": self.version_id,
            "target_client_id": self.target_client_id,
            "envelope": self.envelope,
            "permissions": self.permissions,
        }
        if self.expires_at:
            payload["expires_at"] = self.expires_at
        return payload


@dataclass(frozen=True)
class AccessGrantPayload:
    target_client_id: str
    permissions: int = PermissionRead
    version_id: str | None = None
    expires_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "target_client_id": self.target_client_id,
            "permissions": self.permissions,
        }
        if self.version_id:
            payload["version_id"] = self.version_id
        if self.expires_at:
            payload["expires_at"] = self.expires_at
        return payload


@dataclass(frozen=True)
class ActivateAccessPayload:
    envelope: str

    def to_dict(self) -> dict[str, Any]:
        return {"envelope": self.envelope}
