"""The inventory model, and the rotation state machine's refusals."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from slm.backends import ReadOnlyBackend, SimulatedBackend, fingerprint
from slm.model import (
    InventoryError,
    Secret,
    SecretKind,
    SecretVersion,
    VersionState,
    load,
    parse,
    save,
)
from slm.rotation import Outcome, Phase, due, plan, rotate

UTC = timezone.utc
EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def make(kind=SecretKind.API_KEY, *, age_days=10, max_age=90, overlap=24,
         consumers=("svc-a", "svc-b"), state=VersionState.ACTIVE, expires_days=None):
    created = datetime.now(UTC) - timedelta(days=age_days)
    return Secret(
        id="test-secret", kind=kind, owner="Test Team", backend="simulated",
        max_age=timedelta(days=max_age), overlap=timedelta(hours=overlap),
        lead_time=timedelta(days=14), consumers=consumers,
        versions=[SecretVersion(
            version=1, state=state, created_at=created, fingerprint="sha256:abc",
            expires_at=created + timedelta(days=expires_days) if expires_days else None,
        )],
    )


class TestModel:
    def test_example_inventory_loads(self):
        inventory = load(EXAMPLES / "inventory.yaml")
        assert len(inventory) == 6
        assert inventory.get("payments-db-app")

    def test_missing_file(self, tmp_path):
        with pytest.raises(InventoryError, match="not found"):
            load(tmp_path / "nope.yaml")

    def test_an_unowned_secret_is_rejected(self):
        # An unowned secret is one nobody rotates.
        with pytest.raises(InventoryError, match="no owner"):
            parse({"secrets": [{"id": "x", "kind": "api_key"}]})

    def test_duplicate_ids(self):
        with pytest.raises(InventoryError, match="duplicate id"):
            parse({"secrets": [
                {"id": "x", "owner": "t"}, {"id": "x", "owner": "t"},
            ]})

    def test_unknown_kind_lists_the_valid_ones(self):
        with pytest.raises(InventoryError, match="expected one of"):
            parse({"secrets": [{"id": "x", "owner": "t", "kind": "magic"}]})

    def test_duration_forms(self):
        inventory = parse({"secrets": [
            {"id": "a", "owner": "t", "max_age": "45d", "lead_time": "72h", "overlap": "30m"},
        ]})
        secret = inventory.secrets[0]
        assert secret.max_age == timedelta(days=45)
        assert secret.lead_time == timedelta(hours=72)

    def test_bad_duration_is_named(self):
        with pytest.raises(InventoryError, match="cannot parse max_age"):
            parse({"secrets": [{"id": "a", "owner": "t", "max_age": "soon"}]})

    def test_overlap_is_zeroed_for_kinds_that_cannot_hold_two_values(self):
        # A database engine that allows one password per role has no overlap to
        # have, and a plan describing one would be fiction.
        inventory = parse({"secrets": [
            {"id": "db", "owner": "t", "kind": "database_password", "overlap": "24h"},
        ]})
        assert inventory.secrets[0].overlap == timedelta(0)

    def test_expiry_beats_max_age_when_it_is_sooner(self):
        # A certificate carries its own expiry, usually shorter than the policy.
        secret = make(kind=SecretKind.TLS_CERTIFICATE, age_days=10, max_age=365,
                      expires_days=40)
        assert secret.days_remaining is not None
        assert secret.days_remaining < 365

    def test_status_transitions(self):
        assert make(age_days=1).status == "ok"
        assert make(age_days=85, max_age=90).status == "due soon"
        assert make(age_days=200, max_age=90).status == "overdue"
        assert Secret(id="x", kind=SecretKind.API_KEY, owner="t", backend="b").status == "uninitialised"

    def test_unrevoked_predecessors_are_surfaced(self):
        inventory = load(EXAMPLES / "inventory.yaml")
        unrevoked = inventory.unrevoked()
        assert unrevoked
        assert any(s.id == "legacy-batch-ftp" for s, _ in unrevoked)

    def test_round_trips_through_yaml(self, tmp_path):
        original = load(EXAMPLES / "inventory.yaml")
        restored = load(save(original, tmp_path / "out.yaml"))
        assert len(restored) == len(original)
        assert {s.id for s in restored.secrets} == {s.id for s in original.secrets}

    def test_serialises(self):
        json.dumps(load(EXAMPLES / "inventory.yaml").to_dict())


class TestPlan:
    def test_an_overlap_capable_kind_gets_an_overlap_phase(self):
        steps = " ".join(plan(make(kind=SecretKind.API_KEY, overlap=48)))
        assert "both versions valid" in steps
        assert "48h" in steps

    def test_a_database_password_says_the_overlap_is_impossible(self):
        secret = make(kind=SecretKind.DATABASE_PASSWORD, overlap=0)
        steps = " ".join(plan(secret))
        assert "cannot hold two valid values" in steps
        assert "restarted together" in steps

    def test_every_plan_ends_in_revocation(self):
        for kind in SecretKind:
            assert "revoke" in plan(make(kind=kind))[-1]


class TestRotation:
    def test_dry_run_changes_nothing(self):
        secret = make()
        backend = SimulatedBackend()
        result = rotate(secret, backend, dry_run=True)
        assert result.dry_run
        assert all(r.outcome is Outcome.PLANNED for r in result.records)
        assert len(secret.versions) == 1
        assert not backend.issued

    def test_dry_run_is_the_default(self):
        assert rotate(make(), SimulatedBackend()).dry_run

    def test_full_rotation_revokes_the_old_version(self):
        secret = make()
        backend = SimulatedBackend()
        result = rotate(secret, backend, dry_run=False)
        assert result.ok and result.completed
        assert [r.phase for r in result.records] == [
            Phase.CREATE, Phase.PROMOTE, Phase.VERIFY, Phase.REVOKE
        ]
        assert secret.current.version == 2
        assert secret.versions[0].state is VersionState.REVOKED
        assert secret.versions[0].revoked_at is not None

    def test_the_old_version_stays_valid_when_a_consumer_has_not_migrated(self):
        # The whole point of the verify phase.
        secret = make(consumers=("svc-a", "svc-b", "svc-stuck"))
        backend = SimulatedBackend(stubborn={"svc-stuck"})
        result = rotate(secret, backend, dry_run=False)

        assert not result.ok
        assert not result.completed
        verify = next(r for r in result.records if r.phase is Phase.VERIFY)
        assert verify.outcome is Outcome.FAILED
        assert "svc-stuck" in verify.message
        revoke = next(r for r in result.records if r.phase is Phase.REVOKE)
        assert revoke.outcome is Outcome.SKIPPED
        assert secret.versions[0].state is not VersionState.REVOKED

    def test_skipping_verification_also_skips_revocation(self):
        # Rotation without revocation increases the number of live credentials,
        # so the tool makes you say you meant it.
        secret = make()
        result = rotate(secret, SimulatedBackend(), dry_run=False, skip_verify=True)
        revoke = next(r for r in result.records if r.phase is Phase.REVOKE)
        assert revoke.outcome is Outcome.SKIPPED
        assert "--force-revoke" in revoke.message

    def test_force_revoke_overrides_that(self):
        secret = make()
        result = rotate(
            secret, SimulatedBackend(), dry_run=False, skip_verify=True, force_revoke=True
        )
        assert result.completed

    def test_a_failed_promotion_discards_the_new_version(self):
        # Nothing switched, so the estate is exactly as it was.
        secret = make()
        backend = SimulatedBackend(fail_on={"promote"})
        result = rotate(secret, backend, dry_run=False)

        assert not result.ok
        assert result.rolled_back
        assert len(secret.versions) == 1
        assert secret.current.version == 1
        assert not backend.issued

    def test_a_failed_creation_leaves_nothing_behind(self):
        secret = make()
        result = rotate(secret, SimulatedBackend(fail_on={"create"}), dry_run=False)
        assert not result.ok
        assert len(secret.versions) == 1
        assert [r.phase for r in result.records] == [Phase.CREATE]

    def test_a_failed_revocation_is_reported_not_hidden(self):
        secret = make()
        result = rotate(secret, SimulatedBackend(fail_on={"revoke"}), dry_run=False)
        revoke = next(r for r in result.records if r.phase is Phase.REVOKE)
        assert revoke.outcome is Outcome.FAILED
        assert secret.versions[0].state is not VersionState.REVOKED

    def test_an_unreachable_verifier_does_not_revoke(self):
        secret = make()
        result = rotate(secret, SimulatedBackend(fail_on={"verify"}), dry_run=False)
        assert not result.completed
        assert secret.versions[0].state is not VersionState.REVOKED

    def test_first_rotation_has_nothing_to_revoke(self):
        secret = Secret(
            id="new", kind=SecretKind.API_KEY, owner="t", backend="simulated",
            consumers=("svc-a",),
        )
        result = rotate(secret, SimulatedBackend(), dry_run=False)
        assert result.ok
        assert secret.current.version == 1
        assert secret.current.state is VersionState.ACTIVE

    def test_a_read_only_backend_explains_who_must_act(self):
        secret = make()
        result = rotate(secret, ReadOnlyBackend(), dry_run=False)
        assert not result.ok
        assert "Test Team" in result.records[0].message

    def test_the_inventory_never_holds_the_value(self):
        secret = make()
        backend = SimulatedBackend()
        rotate(secret, backend, dry_run=False)
        stored = json.dumps(secret.to_dict())
        for value in backend.issued.values():
            assert value not in stored
        assert secret.current.fingerprint.startswith("sha256:")

    def test_fingerprints_differ_per_value(self):
        assert fingerprint("a") != fingerprint("b")

    def test_serialises(self):
        result = rotate(make(), SimulatedBackend(), dry_run=False)
        json.dumps(result.to_dict())


class TestDue:
    def test_overdue_first(self):
        inventory = load(EXAMPLES / "inventory.yaml")
        pending = due(inventory.secrets)
        assert pending
        assert pending[0].days_remaining <= (pending[-1].days_remaining or 0)

    def test_look_ahead_widens_the_set(self):
        inventory = load(EXAMPLES / "inventory.yaml")
        assert len(due(inventory.secrets, timedelta(days=60))) >= len(due(inventory.secrets))

    def test_a_never_initialised_secret_is_always_due(self):
        secret = Secret(id="x", kind=SecretKind.API_KEY, owner="t", backend="b")
        assert due([secret]) == [secret]
