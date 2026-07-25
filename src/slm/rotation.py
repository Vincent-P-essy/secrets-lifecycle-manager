"""Rotation as a state machine, with an overlap window and a way back.

Four phases, and each one can be abandoned without leaving the estate broken:

1. **create** — issue a new version. Nothing uses it yet; abandoning here costs
   one unused credential.
2. **promote** — both versions valid. Consumers migrate at their own pace.
   Abandoning here means discarding the new version; nothing switched.
3. **verify** — confirm consumers are actually using the new version. This is
   the step that gets skipped, and skipping it is what turns step 4 into an
   outage.
4. **revoke** — retire the old version. The only irreversible step, and the one
   most rotation programmes never reach: a new credential is issued, adopted,
   and the old one is left valid forever. Rotation without revocation just
   increases the number of live credentials.

Where the backing system cannot hold two valid credentials at once — most
database engines — there is no overlap to have, and the plan says so instead of
describing a phase that cannot happen.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .backends import Backend, BackendError
from .model import Secret, SecretVersion, VersionState

UTC = timezone.utc


class Phase(str, enum.Enum):
    CREATE = "create"
    PROMOTE = "promote"
    VERIFY = "verify"
    REVOKE = "revoke"


class Outcome(str, enum.Enum):
    OK = "ok"
    SKIPPED = "skipped"
    FAILED = "failed"
    PLANNED = "planned"
    ROLLED_BACK = "rolled_back"

    @property
    def is_failure(self) -> bool:
        return self is Outcome.FAILED


@dataclass
class PhaseRecord:
    phase: Phase
    outcome: Outcome
    message: str
    at: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "outcome": self.outcome.value,
            "message": self.message,
            "at": self.at,
            "detail": self.detail,
        }


@dataclass
class RotationResult:
    secret_id: str
    dry_run: bool
    records: list[PhaseRecord] = field(default_factory=list)
    new_version: int | None = None
    rolled_back: bool = False

    @property
    def ok(self) -> bool:
        return not any(r.outcome.is_failure for r in self.records)

    @property
    def completed(self) -> bool:
        """True only when the old version was actually revoked."""
        return any(
            r.phase is Phase.REVOKE and r.outcome is Outcome.OK for r in self.records
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "secret": self.secret_id,
            "dry_run": self.dry_run,
            "ok": self.ok,
            "completed": self.completed,
            "rolled_back": self.rolled_back,
            "new_version": self.new_version,
            "phases": [r.to_dict() for r in self.records],
        }


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def plan(secret: Secret) -> list[str]:
    """The phases this rotation will go through, in words.

    Generated from the secret's own properties rather than a template, so the
    plan for a database password does not describe an overlap window the engine
    cannot provide.
    """
    steps = [f"issue version {secret.next_version()} on backend {secret.backend!r}"]

    if secret.kind.supports_overlap and secret.overlap:
        hours = int(secret.overlap.total_seconds() // 3600)
        steps.append(
            f"hold both versions valid for {hours}h while "
            f"{len(secret.consumers) or 'the'} consumer(s) migrate"
        )
        steps.append("verify every consumer is using the new version")
    else:
        steps.append(
            f"cut over directly — a {secret.kind.label} cannot hold two valid "
            "values at once, so consumers must be restarted together"
        )
        steps.append("verify consumers reconnected")

    steps.append(f"revoke version {secret.current.version if secret.current else '—'}")
    return steps


def rotate(
    secret: Secret,
    backend: Backend,
    *,
    dry_run: bool = True,
    skip_verify: bool = False,
    force_revoke: bool = False,
) -> RotationResult:
    """Run the rotation. Dry run by default."""
    result = RotationResult(secret_id=secret.id, dry_run=dry_run)
    previous = secret.current

    def record(phase: Phase, outcome: Outcome, message: str, **detail: Any) -> None:
        result.records.append(PhaseRecord(phase, outcome, message, _now(), detail))

    if dry_run:
        for index, step in enumerate(plan(secret)):
            record(list(Phase)[min(index, 3)], Outcome.PLANNED, step)
        return result

    # -- 1. create -----------------------------------------------------------
    version_number = secret.next_version()
    try:
        created = backend.create(secret, version_number)
    except BackendError as exc:
        record(Phase.CREATE, Outcome.FAILED, f"could not issue a new version: {exc}")
        return result

    new_version = SecretVersion(
        version=version_number,
        state=VersionState.PENDING,
        created_at=datetime.now(UTC),
        fingerprint=created.fingerprint,
        expires_at=created.expires_at,
        note=created.note,
    )
    secret.versions.append(new_version)
    result.new_version = version_number
    record(
        Phase.CREATE, Outcome.OK,
        f"issued version {version_number} ({created.fingerprint[:12]})",
        fingerprint=created.fingerprint,
    )

    # -- 2. promote ----------------------------------------------------------
    try:
        backend.promote(secret, new_version)
    except BackendError as exc:
        # Nothing has switched yet, so discarding the new version leaves the
        # estate exactly as it was.
        secret.versions.remove(new_version)
        backend.discard(secret, new_version)
        record(Phase.PROMOTE, Outcome.FAILED, f"could not promote: {exc}")
        record(Phase.PROMOTE, Outcome.ROLLED_BACK, "discarded the unused new version")
        result.rolled_back = True
        return result

    new_version.state = VersionState.OVERLAPPING if secret.overlap else VersionState.ACTIVE
    if previous:
        previous.state = (
            VersionState.OVERLAPPING if secret.overlap else VersionState.RETIRED
        )
    record(
        Phase.PROMOTE, Outcome.OK,
        f"version {version_number} is live"
        + (
            f"; both valid for {int(secret.overlap.total_seconds() // 3600)}h"
            if secret.overlap else "; direct cutover"
        ),
    )

    # -- 3. verify -----------------------------------------------------------
    if skip_verify:
        record(
            Phase.VERIFY, Outcome.SKIPPED,
            "verification skipped — the old version will not be revoked without it",
        )
    else:
        try:
            report = backend.verify(secret, new_version)
        except BackendError as exc:
            record(Phase.VERIFY, Outcome.FAILED, f"verification failed: {exc}")
            report = None

        if report is None or not report.all_migrated:
            stragglers = report.stragglers if report else list(secret.consumers)
            record(
                Phase.VERIFY, Outcome.FAILED,
                f"{len(stragglers)} consumer(s) still using the old version: "
                f"{', '.join(stragglers)}",
                stragglers=stragglers,
            )
            record(
                Phase.REVOKE, Outcome.SKIPPED,
                "old version left valid — revoking now would break those consumers",
            )
            return result
        record(
            Phase.VERIFY, Outcome.OK,
            f"all {len(report.migrated)} consumer(s) are using version {version_number}",
        )

    # -- 4. revoke -----------------------------------------------------------
    if previous is None:
        record(Phase.REVOKE, Outcome.SKIPPED, "no previous version to revoke")
        new_version.state = VersionState.ACTIVE
        return result

    if skip_verify and not force_revoke:
        # The step people skip, and the reason rotation programmes accumulate
        # live credentials instead of replacing them.
        record(
            Phase.REVOKE, Outcome.SKIPPED,
            "not revoking without verification — pass --force-revoke if you accept "
            "that consumers may break",
        )
        return result

    try:
        backend.revoke(secret, previous)
    except BackendError as exc:
        record(Phase.REVOKE, Outcome.FAILED, f"could not revoke version {previous.version}: {exc}")
        return result

    previous.state = VersionState.REVOKED
    previous.revoked_at = datetime.now(UTC)
    new_version.state = VersionState.ACTIVE
    record(Phase.REVOKE, Outcome.OK, f"revoked version {previous.version}")
    return result


def due(secrets: list[Secret], within: timedelta | None = None) -> list[Secret]:
    """Secrets needing rotation now, or inside a window."""
    horizon = within.days if within else 0
    out = []
    for secret in secrets:
        remaining = secret.days_remaining
        if remaining is None:
            out.append(secret)  # never initialised
        elif remaining <= horizon:
            out.append(secret)
    return sorted(out, key=lambda s: s.days_remaining if s.days_remaining is not None else -9999)
