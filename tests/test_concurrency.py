import tempfile
import threading
import unittest
from pathlib import Path

from src.domain import Actor
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


class ConcurrencyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = DomainService(SQLiteRepository(Path(self.tmp.name) / "test.db"), RuleEngine())
        self.actor = Actor("admin", "admin")

    def tearDown(self):
        self.tmp.cleanup()

    def station_asset(self):
        station = self.service.create(self.actor, "station", {"name": "S", "region": "R"})
        asset = self.service.create(
            self.actor, "asset",
            {"station_id": station["id"], "asset_type": "sensor", "serial_no": "S-1",
             "last_seen": "2026-09-27T09:00:00Z"},
        )
        return station, asset

    def incident_payload(self, station, asset):
        return {
            "station_id": station["id"], "asset_id": asset["id"],
            "kind": "link_loss", "severity": "high", "summary": "no data",
        }

    def test_concurrent_incident_submissions_first_wins(self):
        station, asset = self.station_asset()
        results = {}
        errors = {}

        def submit(name):
            try:
                results[name] = self.service.create(
                    self.actor, "incident", self.incident_payload(station, asset)
                )
            except Exception as exc:
                errors[name] = exc

        threads = [threading.Thread(target=submit, args=(name,)) for name in ("a", "b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        incidents = self.service.list("incident")
        self.assertEqual(len(incidents), 1)
        self.assertFalse(errors)
        self.assertEqual(results["a"]["id"], results["b"]["id"])

    def test_duplicate_incident_returns_active_event(self):
        station, asset = self.station_asset()
        first = self.service.create(self.actor, "incident", self.incident_payload(station, asset))
        second = self.service.create(self.actor, "incident", self.incident_payload(station, asset))
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(len(self.service.list("incident")), 1)

    def test_closure_records_telemetry_revision(self):
        station, asset = self.station_asset()
        telemetry = self.service.create(
            self.actor, "telemetry",
            {"asset_id": asset["id"], "metric": "pressure", "value": 10,
             "observed_at": "2026-09-27T09:00:00Z", "revision": 1},
        )
        telemetry = self.service.transition(
            self.actor, telemetry["id"], "revise", {"value": 10.5, "revision": 2}
        )
        incident = self.service.create(self.actor, "incident", self.incident_payload(station, asset))
        for action in ("diagnose", "plan_recovery", "start_recovery"):
            incident = self.service.transition(self.actor, incident["id"], action)
        action = self.service.create(
            self.actor, "recovery_action",
            {"incident_id": incident["id"], "action_type": "remote_restart", "dedupe_key": "k"},
        )
        for transition_action in ("approve", "start", "succeed"):
            action = self.service.transition(
                self.actor, action["id"], transition_action,
                {"outcome": "ok"} if transition_action == "succeed" else {},
            )
        incident = self.service.transition(self.actor, incident["id"], "resolve", {"summary": "restored"})
        incident = self.service.transition(self.actor, incident["id"], "close", {})
        self.assertEqual(incident["data"]["closure_basis"]["telemetry_revision"], 2)

    def test_late_revision_invalidates_closed_conclusion(self):
        station, asset = self.station_asset()
        telemetry = self.service.create(
            self.actor, "telemetry",
            {"asset_id": asset["id"], "metric": "pressure", "value": 10,
             "observed_at": "2026-09-27T09:00:00Z", "revision": 1},
        )
        telemetry = self.service.transition(
            self.actor, telemetry["id"], "revise", {"value": 10.5, "revision": 2}
        )
        incident = self.service.create(self.actor, "incident", self.incident_payload(station, asset))
        for action in ("diagnose", "plan_recovery", "start_recovery"):
            incident = self.service.transition(self.actor, incident["id"], action)
        incident = self.service.transition(self.actor, incident["id"], "resolve", {"summary": "restored"})
        incident = self.service.transition(self.actor, incident["id"], "close", {})
        self.assertEqual(incident["status"], "closed")

        telemetry = self.service.transition(
            self.actor, telemetry["id"], "revise", {"value": 11.0, "revision": 3}
        )
        incident = self.service.get(incident["id"])
        self.assertEqual(incident["status"], "open")
        self.assertTrue(incident["data"]["reconfirmation_required"])
        self.assertEqual(incident["data"]["stale_from_revision"], 2)
        self.assertEqual(incident["data"]["stale_to_revision"], 3)
        audit_actions = [entry["action"] for entry in self.service.audit_log(incident["id"])]
        self.assertIn("reopen", audit_actions)

    def test_write_failure_rolls_back_state_version_and_audit(self):
        station, asset = self.station_asset()
        telemetry = self.service.create(
            self.actor, "telemetry",
            {"asset_id": asset["id"], "metric": "pressure", "value": 10,
             "observed_at": "2026-09-27T09:00:00Z", "revision": 1},
        )
        original_append = self.service.repository.append_audit

        def fail_append(*args, **kwargs):
            raise RuntimeError("audit write failed")

        self.service.repository.append_audit = fail_append
        before = self.service.get(telemetry["id"])
        with self.assertRaises(RuntimeError):
            self.service.transition(
                self.actor, telemetry["id"], "revise", {"value": 11, "revision": 2}
            )
        self.service.repository.append_audit = original_append

        after = self.service.get(telemetry["id"])
        self.assertEqual(after["version"], before["version"])
        self.assertEqual(after["status"], before["status"])
        self.assertEqual(after["data"]["revision"], 1)
        revise_audits = [
            entry for entry in self.service.audit_log(telemetry["id"])
            if entry["action"] == "revise"
        ]
        self.assertFalse(revise_audits)

    def test_idempotent_retry_does_not_duplicate_audit(self):
        station, asset = self.station_asset()
        telemetry = self.service.create(
            self.actor, "telemetry",
            {"asset_id": asset["id"], "metric": "pressure", "value": 10,
             "observed_at": "2026-09-27T09:00:00Z", "revision": 1},
        )
        first = self.service.transition(
            self.actor, telemetry["id"], "revise", {"value": 11, "revision": 2},
            idempotency_key="rev-1",
        )
        second = self.service.transition(
            self.actor, telemetry["id"], "revise", {"value": 11, "revision": 2},
            idempotency_key="rev-1",
        )
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(second["data"]["revision"], 2)
        revise_audits = [
            entry for entry in self.service.audit_log(telemetry["id"])
            if entry["action"] == "revise"
        ]
        self.assertEqual(len(revise_audits), 1)


if __name__ == "__main__":
    unittest.main()
