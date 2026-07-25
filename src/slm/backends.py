"""Backends: the systems that actually hold the credential.

The interface is deliberately four verbs, because those are the four phases a
safe rotation has. A backend that can only `create` cannot be rotated safely,
and the missing method says so at import time rather than at 02:00.

`verify` is the one that matters and the one a naive implementation gets wrong
by returning `True`. Verification means asking the *consumers* what they are
using, not asking the backend what it issued — the backend always knows about
the new version; that was step one. Whether the six services that cached the
old value have picked it up is a different question, and it is the question
that decides whether revocation is safe.

The bundled backends are simulated. Wiring one to Vault or AWS Secrets Manager
is the four methods; the state machine, the overlap window and the refusal to
revoke unverified are what this repository provides.
"""

from __future__ import annotations

import hashlib
import secrets as pysecrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol, runtime_checkable

from .model import Secret, SecretVersion

UTC = timezone.utc


class BackendError(RuntimeError):
    """Raised when a backend operation cannot complete."""


@dataclass(frozen=True)
class CreatedVersion:
    fingerprint: str
    expires_at: datetime | None = None
    note: str = ""


@dataclass(frozen=True)
class VerifyReport:
    migrated: tuple[str, ...] = ()
    stragglers: tuple[str, ...] = ()

    @property
    def all_migrated(self) -> bool:
        return not self.stragglers


@runtime_checkable
class Backend(Protocol):
    name: str

    def create(self, secret: Secret, version: int) -> CreatedVersion: ...
    def promote(self, secret: Secret, version: SecretVersion) -> None: ...
    def verify(self, secret: Secret, version: SecretVersion) -> VerifyReport: ...
    def revoke(self, secret: Secret, version: SecretVersion) -> None: ...
    def discard(self, secret: Secret, version: SecretVersion) -> None: ...


def fingerprint(value: str) -> str:
    """A digest of a secret value.

    The inventory stores this and never the value. A file that lists every
    credential in the estate should not also contain them.
    """
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:32]


@dataclass
class SimulatedBackend:
    """An in-memory backend with the awkward parts a real one has.

    Consumers do not migrate instantly, `verify` can legitimately fail, and a
    version that was never promoted can be discarded cleanly. Those three
    behaviours are what the rotation state machine exists to handle, so a
    backend without them would let the tests pass while the design was wrong.
    """

    name: str = "simulated"
    #: consumer -> the version it is currently using
    consumer_versions: dict[str, int] = field(default_factory=dict)
    #: Consumers that will not migrate, for exercising the verify failure path.
    stubborn: set[str] = field(default_factory=set)
    issued: dict[tuple[str, int], str] = field(default_factory=dict)
    revoked: set[tuple[str, int]] = field(default_factory=set)
    fail_on: set[str] = field(default_factory=set)

    def create(self, secret: Secret, version: int) -> CreatedVersion:
        if "create" in self.fail_on:
            raise BackendError("the backend refused to issue a new version")

        value = pysecrets.token_urlsafe(32)
        self.issued[(secret.id, version)] = value

        expires_at = None
        if secret.kind.value == "tls_certificate":
            # A certificate carries its own expiry, and it is usually shorter
            # than the rotation policy - which is why due_at takes the earlier
            # of the two rather than trusting max_age.
            expires_at = datetime.now(UTC) + timedelta(days=90)

        return CreatedVersion(
            fingerprint=fingerprint(value),
            expires_at=expires_at,
            note=f"issued by {self.name}",
        )

    def promote(self, secret: Secret, version: SecretVersion) -> None:
        if "promote" in self.fail_on:
            raise BackendError("the backend rejected the new version")
        for consumer in secret.consumers:
            if consumer not in self.stubborn:
                self.consumer_versions[consumer] = version.version

    def verify(self, secret: Secret, version: SecretVersion) -> VerifyReport:
        if "verify" in self.fail_on:
            raise BackendError("could not reach the consumers to verify")
        migrated, stragglers = [], []
        for consumer in secret.consumers:
            if self.consumer_versions.get(consumer) == version.version:
                migrated.append(consumer)
            else:
                stragglers.append(consumer)
        return VerifyReport(tuple(migrated), tuple(stragglers))

    def revoke(self, secret: Secret, version: SecretVersion) -> None:
        if "revoke" in self.fail_on:
            raise BackendError("the backend refused to revoke")
        self.revoked.add((secret.id, version.version))
        self.issued.pop((secret.id, version.version), None)

    def discard(self, secret: Secret, version: SecretVersion) -> None:
        self.issued.pop((secret.id, version.version), None)


class ReadOnlyBackend:
    """A backend that can report but not change anything.

    For credentials held somewhere this tool has no write access to — a
    partner's API key, a certificate issued by another team. Rotation is still
    tracked and still comes due; it is just carried out by someone else, and
    saying that is more useful than omitting the secret from the inventory.
    """

    name = "read-only"

    def create(self, secret: Secret, version: int) -> CreatedVersion:
        raise BackendError(
            f"{secret.id} is held in a system this tool cannot write to. "
            f"Rotation is {secret.owner}'s to carry out; record the new version "
            "here afterwards."
        )

    def promote(self, secret: Secret, version: SecretVersion) -> None:
        raise BackendError("read-only backend")

    def verify(self, secret: Secret, version: SecretVersion) -> VerifyReport:
        return VerifyReport(stragglers=secret.consumers)

    def revoke(self, secret: Secret, version: SecretVersion) -> None:
        raise BackendError("read-only backend")

    def discard(self, secret: Secret, version: SecretVersion) -> None:
        return None


_REGISTRY: dict[str, Any] = {}


def register(name: str, factory: Any) -> None:
    _REGISTRY[name] = factory


def get(name: str) -> Backend:
    if name not in _REGISTRY:
        raise BackendError(
            f"unknown backend {name!r}; registered: {', '.join(sorted(_REGISTRY))}"
        )
    return _REGISTRY[name]()


def available() -> list[str]:
    return sorted(_REGISTRY)


register("simulated", SimulatedBackend)
register("read-only", ReadOnlyBackend)
