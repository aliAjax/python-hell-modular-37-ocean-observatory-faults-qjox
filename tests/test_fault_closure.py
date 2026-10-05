import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from src.domain import Actor, ConflictError, PermissionDenied, ValidationError
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


class FaultClosureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repository = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(self.repository, RuleEngine())
        self.admin = Actor("admin", "admin")
        self.operator = Actor("op-1", "operator")
        self.engineer = Actor("eng-1", "engineer")

    def tearDown(self):
        self.tmp.cleanup()

    def station_asset(self):
        station = self.service.create(self.admin, "station", {"name": "S", "region": "R"})
        asset = self.service.create(self.admin, "asset", {"station_id": station["id"], "asset_type": "sensor", "serial_no": "S-1", "last_seen": "2026-09-27T09:00:00Z"})
        return station, asset

    def incident_payload(self, station, asset, kind="link_loss"):
        return {"station_id": station["id"], "asset_id": asset["id"], "kind": kind, "severity": "high", "summary": "no data"}

    def drive_to_resolved(self, incident):
        for action in ("diagnose", "plan_recovery", "start_recovery"):
            incident = self.service.transition(self.admin, incident["id"], action)
        return self.service.transition(self.admin, incident["id"], "resolve", {"summary": "restored"})

    # ---- 需求一：同一资产同一故障类型同时提交，先到生效，后到拿到活动事件编号 ----

    def test_duplicate_submission_gets_active_incident_id(self):
        station, asset = self.station_asset()
        first = self.service.create(self.operator, "incident", self.incident_payload(station, asset))
        second = self.service.create(self.engineer, "incident", self.incident_payload(station, asset))
        self.assertEqual(first["id"], second["id"])
        self.assertTrue(second["deduplicated"])
        incidents = self.service.list("incident")
        self.assertEqual(len(incidents), 1)
        creates = [a for a in self.service.audit_log(first["id"]) if a["action"] == "create"]
        self.assertEqual(len(creates), 1)

    def test_concurrent_submission_only_first_wins(self):
        station, asset = self.station_asset()
        results, errors = [], []

        def submit(user):
            try:
                results.append(self.service.create(Actor(user, "operator"), "incident", self.incident_payload(station, asset)))
            except Exception as exc:  # pragma: no cover - 记录意外失败
                errors.append(exc)

        threads = [threading.Thread(target=submit, args=("op-%d" % i,)) for i in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 6)
        self.assertEqual({item["id"] for item in results}, {results[0]["id"]})
        self.assertEqual(len(self.service.list("incident")), 1)
        creates = [a for a in self.service.audit_log(results[0]["id"]) if a["action"] == "create"]
        self.assertEqual(len(creates), 1)

    def test_different_fault_kind_not_deduplicated(self):
        station, asset = self.station_asset()
        first = self.service.create(self.operator, "incident", self.incident_payload(station, asset, "link_loss"))
        second = self.service.create(self.operator, "incident", self.incident_payload(station, asset, "power"))
        self.assertNotEqual(first["id"], second["id"])

    def test_slot_released_after_resolve(self):
        station, asset = self.station_asset()
        first = self.service.create(self.operator, "incident", self.incident_payload(station, asset))
        self.drive_to_resolved(first)
        second = self.service.create(self.operator, "incident", self.incident_payload(station, asset))
        self.assertNotEqual(first["id"], second["id"])
        self.assertFalse(second.get("deduplicated"))

    # ---- 需求二：关闭记下遥测修订号，修订更新后旧结论失效并重新确认 ----

    def test_resolve_records_telemetry_revision_basis(self):
        station, asset = self.station_asset()
        self.service.create(self.admin, "telemetry", {"asset_id": asset["id"], "metric": "pressure", "value": 10, "observed_at": "2026-09-27T09:00:00Z", "revision": 3})
        incident = self.service.create(self.operator, "incident", self.incident_payload(station, asset))
        resolved = self.drive_to_resolved(incident)
        basis = resolved["data"]["closure_basis"]
        self.assertEqual(basis["asset_id"], asset["id"])
        self.assertEqual(basis["telemetry_revision"], 3)
        self.assertTrue(resolved["data"]["closure_valid"])

    def test_late_revision_invalidates_closed_conclusion(self):
        station, asset = self.station_asset()
        telemetry = self.service.create(self.admin, "telemetry", {"asset_id": asset["id"], "metric": "pressure", "value": 10, "observed_at": "2026-09-27T09:00:00Z", "revision": 1})
        incident = self.service.create(self.operator, "incident", self.incident_payload(station, asset))
        resolved = self.drive_to_resolved(incident)
        closed = self.service.transition(self.admin, resolved["id"], "close")
        self.assertEqual(closed["status"], "closed")

        revised = self.service.transition(self.operator, telemetry["id"], "revise", {"value": 12, "revision": 2})
        self.assertEqual(revised["data"]["revision"], 2)

        reopened = self.service.get(incident["id"])
        self.assertEqual(reopened["status"], "reconfirm")
        self.assertFalse(reopened["data"]["closure_valid"])
        self.assertEqual(reopened["data"]["invalidated_by"]["telemetry_id"], telemetry["id"])
        self.assertEqual(reopened["data"]["invalidated_by"]["revision"], 2)
        self.assertEqual(reopened["data"]["invalidated_by"]["previous_basis_revision"], 1)

        audits = self.service.audit_log(incident["id"])
        invalidations = [a for a in audits if a["action"] == "invalidate_closure"]
        self.assertEqual(len(invalidations), 1)
        self.assertEqual(invalidations[0]["from_status"], "closed")
        self.assertEqual(invalidations[0]["to_status"], "reconfirm")
        self.assertEqual(invalidations[0]["actor_id"], "op-1")

    def test_new_telemetry_revision_on_create_invalidates(self):
        station, asset = self.station_asset()
        self.service.create(self.admin, "telemetry", {"asset_id": asset["id"], "metric": "pressure", "value": 10, "observed_at": "2026-09-27T09:00:00Z", "revision": 1})
        incident = self.service.create(self.operator, "incident", self.incident_payload(station, asset))
        self.drive_to_resolved(incident)
        self.service.create(self.admin, "telemetry", {"asset_id": asset["id"], "metric": "pressure", "value": 11, "observed_at": "2026-09-27T10:00:00Z", "revision": 2})
        self.assertEqual(self.service.get(incident["id"])["status"], "reconfirm")

    def test_confirm_closure_revalidates_and_records_new_basis(self):
        station, asset = self.station_asset()
        telemetry = self.service.create(self.admin, "telemetry", {"asset_id": asset["id"], "metric": "pressure", "value": 10, "observed_at": "2026-09-27T09:00:00Z", "revision": 1})
        incident = self.service.create(self.operator, "incident", self.incident_payload(station, asset))
        self.drive_to_resolved(incident)
        self.service.transition(self.operator, telemetry["id"], "revise", {"value": 12, "revision": 2})
        self.assertEqual(self.service.get(incident["id"])["status"], "reconfirm")

        with self.assertRaises(PermissionDenied):
            self.service.transition(self.operator, incident["id"], "confirm_closure", {"summary": "ok"})
        with self.assertRaises(ValidationError):
            self.service.transition(self.engineer, incident["id"], "confirm_closure", {})

        confirmed = self.service.transition(self.engineer, incident["id"], "confirm_closure", {"summary": "re-checked with rev 2"})
        self.assertEqual(confirmed["status"], "resolved")
        self.assertTrue(confirmed["data"]["closure_valid"])
        self.assertEqual(confirmed["data"]["closure_basis"]["telemetry_revision"], 2)
        self.assertIsNone(confirmed["data"]["invalidated_by"])

        self.service.transition(self.operator, telemetry["id"], "revise", {"value": 13, "revision": 3})
        self.assertEqual(self.service.get(incident["id"])["status"], "reconfirm")

    def test_reconfirm_blocks_new_incident_until_concluded(self):
        station, asset = self.station_asset()
        telemetry = self.service.create(self.admin, "telemetry", {"asset_id": asset["id"], "metric": "pressure", "value": 10, "observed_at": "2026-09-27T09:00:00Z", "revision": 1})
        incident = self.service.create(self.operator, "incident", self.incident_payload(station, asset))
        self.drive_to_resolved(incident)
        self.service.transition(self.operator, telemetry["id"], "revise", {"value": 12, "revision": 2})
        duplicate = self.service.create(self.operator, "incident", self.incident_payload(station, asset))
        self.assertEqual(duplicate["id"], incident["id"])
        self.assertTrue(duplicate["deduplicated"])

    def test_reopen_from_reconfirm(self):
        station, asset = self.station_asset()
        telemetry = self.service.create(self.admin, "telemetry", {"asset_id": asset["id"], "metric": "pressure", "value": 10, "observed_at": "2026-09-27T09:00:00Z", "revision": 1})
        incident = self.service.create(self.operator, "incident", self.incident_payload(station, asset))
        self.drive_to_resolved(incident)
        self.service.transition(self.operator, telemetry["id"], "revise", {"value": 12, "revision": 2})
        reopened = self.service.transition(self.engineer, incident["id"], "reopen")
        self.assertEqual(reopened["status"], "open")

    # ---- 需求三：写入失败一起回滚，重试不重复记审计 ----

    def test_failed_write_rolls_back_state_and_audit(self):
        station, asset = self.station_asset()
        telemetry = self.service.create(self.admin, "telemetry", {"asset_id": asset["id"], "metric": "pressure", "value": 10, "observed_at": "2026-09-27T09:00:00Z", "revision": 1})
        before_audits = len(self.service.audit_log())
        with self.assertRaises(ConflictError):
            self.service.transition(self.admin, telemetry["id"], "revise", {"revision": 2}, expected_version=999)
        unchanged = self.service.get(telemetry["id"])
        self.assertEqual(unchanged["status"], "current")
        self.assertEqual(unchanged["data"]["revision"], 1)
        self.assertEqual(len(self.service.audit_log()), before_audits)

    def test_cascade_conflict_rolls_back_revision_and_audit(self):
        station, asset = self.station_asset()
        telemetry = self.service.create(self.admin, "telemetry", {"asset_id": asset["id"], "metric": "pressure", "value": 10, "observed_at": "2026-09-27T09:00:00Z", "revision": 1})
        incident = self.service.create(self.operator, "incident", self.incident_payload(station, asset))
        self.drive_to_resolved(incident)
        before_audits = len(self.service.audit_log())

        original_apply = self.repository.apply

        def racing_apply(**plan):
            # 模拟并发：修订事务提交前，事件被另一值班员改动（版本号前移）。
            if plan.get("update") and plan["update"]["entity_id"] == telemetry["id"]:
                current = self.repository.get_entity(incident["id"])
                self.repository.update_entity(incident["id"], None, current["status"], current["data"])
            return original_apply(**plan)

        self.repository.apply = racing_apply
        try:
            with self.assertRaises(ConflictError):
                self.service.transition(self.operator, telemetry["id"], "revise", {"value": 12, "revision": 2})
        finally:
            self.repository.apply = original_apply

        unchanged = self.service.get(telemetry["id"])
        self.assertEqual(unchanged["data"]["revision"], 1)
        self.assertEqual(self.service.get(incident["id"])["status"], "resolved")
        self.assertEqual(len(self.service.audit_log()), before_audits)

    def test_repository_apply_rolls_back_on_audit_failure(self):
        station, asset = self.station_asset()
        broken_audit = {
            "entity_id": asset["id"], "actor_id": None, "actor_role": "admin",
            "action": "fail", "from_status": "healthy", "to_status": "faulty",
            "detail": {}, "idem_key": None,
        }
        with self.assertRaises(sqlite3.IntegrityError):
            self.repository.apply(
                update={"entity_id": asset["id"], "expected_version": asset["version"], "status": "faulty", "data": asset["data"]},
                audits=[broken_audit],
            )
        unchanged = self.service.get(asset["id"])
        self.assertEqual(unchanged["status"], "healthy")
        self.assertEqual(unchanged["version"], asset["version"])

    def test_retry_with_idempotency_key_does_not_duplicate_audit(self):
        station, asset = self.station_asset()
        telemetry = self.service.create(self.admin, "telemetry", {"asset_id": asset["id"], "metric": "pressure", "value": 10, "observed_at": "2026-09-27T09:00:00Z", "revision": 1})
        first = self.service.transition(self.operator, telemetry["id"], "revise", {"value": 11, "revision": 2}, idempotency_key="revise-1")
        second = self.service.transition(self.operator, telemetry["id"], "revise", {"value": 11, "revision": 2}, idempotency_key="revise-1")
        self.assertEqual(first["version"], second["version"])
        self.assertEqual(second["data"]["revision"], 2)
        revises = [a for a in self.service.audit_log(telemetry["id"]) if a["action"] == "revise"]
        self.assertEqual(len(revises), 1)

    def test_retry_after_rollback_applies_exactly_once(self):
        station, asset = self.station_asset()
        telemetry = self.service.create(self.admin, "telemetry", {"asset_id": asset["id"], "metric": "pressure", "value": 10, "observed_at": "2026-09-27T09:00:00Z", "revision": 1})
        with self.assertRaises(ConflictError):
            self.service.transition(self.operator, telemetry["id"], "revise", {"value": 11, "revision": 2}, expected_version=999, idempotency_key="revise-2")
        applied = self.service.transition(self.operator, telemetry["id"], "revise", {"value": 11, "revision": 2}, idempotency_key="revise-2")
        self.assertEqual(applied["data"]["revision"], 2)
        revises = [a for a in self.service.audit_log(telemetry["id"]) if a["action"] == "revise"]
        self.assertEqual(len(revises), 1)

    def test_create_retry_with_idempotency_key(self):
        station, asset = self.station_asset()
        payload = self.incident_payload(station, asset)
        first = self.service.create(self.operator, "incident", payload, idempotency_key="inc-1")
        second = self.service.create(self.operator, "incident", payload, idempotency_key="inc-1")
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(len(self.service.list("incident")), 1)
        creates = [a for a in self.service.audit_log(first["id"]) if a["action"] == "create"]
        self.assertEqual(len(creates), 1)

    def test_idempotency_key_reuse_on_other_entity_rejected(self):
        station, asset = self.station_asset()
        first = self.service.create(self.admin, "telemetry", {"asset_id": asset["id"], "metric": "pressure", "value": 10, "observed_at": "2026-09-27T09:00:00Z", "revision": 1})
        second = self.service.create(self.admin, "telemetry", {"asset_id": asset["id"], "metric": "temperature", "value": 3, "observed_at": "2026-09-27T09:00:00Z", "revision": 1})
        self.service.transition(self.operator, first["id"], "revise", {"value": 11, "revision": 2}, idempotency_key="shared-key")
        with self.assertRaises(ConflictError):
            self.service.transition(self.operator, second["id"], "revise", {"value": 4, "revision": 2}, idempotency_key="shared-key")


if __name__ == "__main__":
    unittest.main()
