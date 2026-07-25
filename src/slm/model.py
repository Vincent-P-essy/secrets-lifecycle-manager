"""The inventory model, and why rotation has more than one step.

The naive rotation is: generate a new value, write it where the old one lived,
done. It breaks every consumer that had cached the old value, and it breaks them
at the moment of rotation — which is why rotation gets scheduled for a quiet
Sunday, then postponed, then never done, and the credential is eight years old
when it leaks.

Rotation here is a **state machine with an overlap window**. Both values are
valid at once; consumers migrate; only then is the old one revoked. That turns
rotation from an outage into a background task, which is the only version of it
that actually happens on schedule.

    ACTIVE ──create──▶ PENDING ──promote──▶ OVERLAPPING ──revoke──▶ ACTIVE
                          │                      │
                          └──── discard ─────────┘   (nothing was switched)
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

UTC = timezone.utc


class InventoryError(ValueError):
    """Raised when the inventory is malformed. Always names the secret."""


class SecretKind(str, enum.Enum):
    DATABASE_PASSWORD = "database_password"
    API_KEY = "api_key"
    TLS_CERTIFICATE = "tls_certificate"
    SSH_KEY = "ssh_key"
    SIGNING_KEY = "signing_key"
    SERVICE_ACCOUNT = "service_account"

    @property
    def label(self) -> str:
        return self.value.replace("_", " ")

    @property
    def supports_overlap(self) -> bool:
        """Whether two versions can be valid at the same time.

        This is the property that decides whether rotation is a background task
        or an outage, and it is a property of the *system holding the secret*,
        not of the secret. A database user can have two passwords only if the
        engine allows it; most do not, so that rotation needs a second user
        rather than a second password — which the plan says out loud instead of
        pretending the overlap exists.
        """
        return self in {
            SecretKind.API_KEY,
            SecretKind.TLS_CERTIFICATE,
            SecretKind.SIGNING_KEY,
            SecretKind.SSH_KEY,
        }


class VersionState(str, enum.Enum):
    ACTIVE = "active"            # in use
    PENDING = "pending"          # created, not yet handed to consumers
    OVERLAPPING = "overlapping"  # both valid; consumers migrating
    RETIRED = "retired"          # superseded, not yet revoked
    REVOKED = "revoked"          # gone


@dataclass
class SecretVersion:
    """One version of a secret. The value itself is never stored here."""

    version: int
    state: VersionState
    created_at: datetime
    #: A digest of the value, so a rotation can be verified without the value
    #: ever entering this process. Storing the secret would make the inventory
    #: the most valuable file in the estate.
    fingerprint: str = ""
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    note: str = ""

    @property
    def age(self) -> timedelta:
        return datetime.now(UTC) - self.created_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "state": self.state.value,
            "created_at": self.created_at.isoformat(),
            "fingerprint": self.fingerprint,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "note": self.note,
        }


@dataclass
class Secret:
    """One credential, its rotation policy, and who has to care about it."""

    id: str
    kind: SecretKind
    owner: str
    backend: str
    description: str = ""
    #: How often it should be rotated.
    max_age: timedelta = timedelta(days=90)
    #: How long both versions stay valid. Zero means a hard cutover.
    overlap: timedelta = timedelta(hours=24)
    #: How much warning before expiry or the rotation deadline.
    lead_time: timedelta = timedelta(days=14)
    consumers: tuple[str, ...] = ()
    versions: list[SecretVersion] = field(default_factory=list)
    tags: tuple[str, ...] = ()

    @property
    def current(self) -> SecretVersion | None:
        candidates = [
            v for v in self.versions
            if v.state in (VersionState.ACTIVE, VersionState.OVERLAPPING)
        ]
        return max(candidates, key=lambda v: v.version) if candidates else None

    @property
    def pending(self) -> SecretVersion | None:
        return next((v for v in self.versions if v.state is VersionState.PENDING), None)

    @property
    def age(self) -> timedelta | None:
        return self.current.age if self.current else None

    @property
    def due_at(self) -> datetime | None:
        """When rotation is due: the earlier of max-age and expiry."""
        if not self.current:
            return None
        by_age = self.current.created_at + self.max_age
        expiry = self.current.expires_at
        return min(by_age, expiry) if expiry else by_age

    @property
    def days_remaining(self) -> int | None:
        due = self.due_at
        if due is None:
            return None
        return (due - datetime.now(UTC)).days

    @property
    def overdue(self) -> bool:
        remaining = self.days_remaining
        return remaining is not None and remaining < 0

    @property
    def due_soon(self) -> bool:
        remaining = self.days_remaining
        return remaining is not None and 0 <= remaining <= self.lead_time.days

    @property
    def rotating(self) -> bool:
        return any(
            v.state in (VersionState.PENDING, VersionState.OVERLAPPING)
            for v in self.versions
        )

    @property
    def status(self) -> str:
        if not self.current:
            return "uninitialised"
        if self.rotating:
            return "rotating"
        if self.overdue:
            return "overdue"
        if self.due_soon:
            return "due soon"
        return "ok"

    @property
    def unrevoked_predecessors(self) -> list[SecretVersion]:
        """Retired versions that were never actually revoked.

        The commonest gap in a rotation programme: the new credential is issued
        and adopted, and the old one is left valid forever. Rotation without
        revocation only increases the number of live credentials.
        """
        return [v for v in self.versions if v.state is VersionState.RETIRED]

    def next_version(self) -> int:
        return max((v.version for v in self.versions), default=0) + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "owner": self.owner,
            "backend": self.backend,
            "description": self.description,
            "max_age_days": self.max_age.days,
            "overlap_hours": int(self.overlap.total_seconds() // 3600),
            "lead_time_days": self.lead_time.days,
            "consumers": list(self.consumers),
            "tags": list(self.tags),
            "status": self.status,
            "days_remaining": self.days_remaining,
            "versions": [v.to_dict() for v in self.versions],
        }


@dataclass
class Inventory:
    secrets: list[Secret] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.secrets)

    def get(self, secret_id: str) -> Secret | None:
        return next((s for s in self.secrets if s.id == secret_id), None)

    def overdue(self) -> list[Secret]:
        return sorted(
            (s for s in self.secrets if s.overdue),
            key=lambda s: s.days_remaining or 0,
        )

    def due_soon(self) -> list[Secret]:
        return sorted(
            (s for s in self.secrets if s.due_soon),
            key=lambda s: s.days_remaining or 0,
        )

    def unrevoked(self) -> list[tuple[Secret, SecretVersion]]:
        return [
            (secret, version)
            for secret in self.secrets
            for version in secret.unrevoked_predecessors
        ]

    def to_dict(self) -> dict[str, Any]:
        return {"secrets": [s.to_dict() for s in self.secrets]}


def _duration(value: Any, default: timedelta, where: str, field_name: str) -> timedelta:
    """Parse `30d`, `12h`, `90` (days) into a timedelta."""
    if value is None:
        return default
    text = str(value).strip().lower()
    try:
        if text.endswith("d"):
            return timedelta(days=float(text[:-1]))
        if text.endswith("h"):
            return timedelta(hours=float(text[:-1]))
        if text.endswith("m"):
            return timedelta(minutes=float(text[:-1]))
        return timedelta(days=float(text))
    except ValueError:
        raise InventoryError(
            f"{where}: cannot parse {field_name} {value!r}; use forms like 90d, 24h, 30m"
        ) from None


def _timestamp(value: Any, where: str) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise InventoryError(f"{where}: cannot parse timestamp {value!r}") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse(data: dict[str, Any], where: str = "inventory") -> Inventory:
    if not isinstance(data, dict):
        raise InventoryError(f"{where}: top level must be a mapping")

    inventory = Inventory()
    seen: set[str] = set()

    for raw in data.get("secrets") or []:
        if "id" not in raw:
            raise InventoryError(f"{where}: a secret has no id")
        secret_id = str(raw["id"])
        entry = f"{where} secret {secret_id!r}"
        if secret_id in seen:
            raise InventoryError(f"{entry}: duplicate id")
        seen.add(secret_id)

        try:
            kind = SecretKind(str(raw.get("kind", "api_key")).lower())
        except ValueError:
            raise InventoryError(
                f"{entry}: unknown kind {raw.get('kind')!r}; expected one of "
                f"{', '.join(k.value for k in SecretKind)}"
            ) from None

        if not raw.get("owner"):
            raise InventoryError(
                f"{entry}: no owner. An unowned secret is one nobody rotates."
            )

        versions: list[SecretVersion] = []
        for version_raw in raw.get("versions") or []:
            try:
                state = VersionState(str(version_raw.get("state", "active")).lower())
            except ValueError:
                raise InventoryError(
                    f"{entry}: unknown version state {version_raw.get('state')!r}"
                ) from None
            versions.append(
                SecretVersion(
                    version=int(version_raw.get("version", 1)),
                    state=state,
                    created_at=_timestamp(version_raw.get("created_at"), entry),
                    fingerprint=str(version_raw.get("fingerprint", "")),
                    expires_at=(
                        _timestamp(version_raw["expires_at"], entry)
                        if version_raw.get("expires_at") else None
                    ),
                    revoked_at=(
                        _timestamp(version_raw["revoked_at"], entry)
                        if version_raw.get("revoked_at") else None
                    ),
                    note=str(version_raw.get("note", "")),
                )
            )

        consumers = raw.get("consumers") or []
        if isinstance(consumers, str):
            consumers = [consumers]
        tags = raw.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]

        overlap = _duration(raw.get("overlap"), timedelta(hours=24), entry, "overlap")
        if overlap and not kind.supports_overlap:
            # Better to correct it here than to write a rotation plan whose
            # overlap phase cannot happen.
            overlap = timedelta(0)

        inventory.secrets.append(
            Secret(
                id=secret_id,
                kind=kind,
                owner=str(raw["owner"]),
                backend=str(raw.get("backend", "simulated")),
                description=str(raw.get("description", "")).strip(),
                max_age=_duration(raw.get("max_age"), timedelta(days=90), entry, "max_age"),
                overlap=overlap,
                lead_time=_duration(raw.get("lead_time"), timedelta(days=14), entry, "lead_time"),
                consumers=tuple(str(c) for c in consumers),
                tags=tuple(str(t) for t in tags),
                versions=versions,
            )
        )

    return inventory


def load(path: str | Path) -> Inventory:
    source = Path(path)
    if not source.exists():
        raise InventoryError(f"inventory not found: {source}")
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise InventoryError(f"{source.name}: invalid YAML: {exc}") from None
    return parse(data, source.name)


def save(inventory: Inventory, path: str | Path) -> Path:
    out = Path(path)
    payload = {"secrets": []}
    for secret in inventory.secrets:
        payload["secrets"].append(
            {
                "id": secret.id,
                "kind": secret.kind.value,
                "owner": secret.owner,
                "backend": secret.backend,
                "description": secret.description,
                "max_age": f"{secret.max_age.days}d",
                "overlap": f"{int(secret.overlap.total_seconds() // 3600)}h",
                "lead_time": f"{secret.lead_time.days}d",
                "consumers": list(secret.consumers),
                "tags": list(secret.tags),
                "versions": [
                    {k: v for k, v in version.to_dict().items() if v is not None}
                    for version in secret.versions
                ],
            }
        )
    out.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return out
