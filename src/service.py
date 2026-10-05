import hashlib
from uuid import uuid4

from .audit import AuditTrail
from .domain import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .repository import ACTIVE_INCIDENT_STATUSES
from .rules import RuleEngine


class DomainService:
    def __init__(self, repository, rules=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)

    def _lookup(self, kind, field, value):
        return self.repository.find_entities(self.rules.normalize_kind(kind), field, value)

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    def create(self, actor, kind, data, idempotency_key=None):
        kind = self.rules.normalize_kind(kind)
        payload = dict(data or {})
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return entity
        self.rules.validate_create(actor, kind, payload, self._lookup)
        entity_id = str(payload.pop("id", "") or uuid4())
        if self.repository.get_entity(entity_id):
            raise ConflictError("entity already exists: " + entity_id)
        status = self.rules.initial_status(kind, payload)
        with self.repository.transaction() as conn:
            if kind == "incident":
                # First writer wins: under the write lock, if an active incident
                # for the same (asset, fault kind) already exists, the later
                # caller gets the active incident instead of a duplicate event.
                active = self._find_active_incident(conn, payload)
                if active:
                    return active
            entity = self.repository.create_entity(
                entity_id, kind, status, payload, actor.user_id, conn=conn
            )
            self.repository.append_audit(
                entity_id,
                actor.user_id,
                actor.role,
                "create",
                None,
                status,
                {"kind": kind},
                conn=conn,
            )
            if idempotency_key:
                self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id, conn=conn)
        return entity

    def transition(self, actor, entity_id, action, data=None, expected_version=None, idempotency_key=None):
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return entity
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        expected = int(expected_version) if expected_version is not None else entity["version"]
        next_status, patch = self.rules.validate_transition(
            actor, entity, action, dict(data or {}), self._lookup
        )
        with self.repository.transaction() as conn:
            current = self.repository.get_entity(entity_id, conn=conn)
            if not current:
                raise NotFoundError("entity not found: " + entity_id)
            extra_audits = []
            if current["kind"] == "incident" and action == "close":
                # Re-snapshot under the lock so the recorded revision is the
                # latest committed one at close time.
                patch["closure_basis"] = self._closure_basis(conn, current)
            if current["kind"] == "telemetry" and action == "revise":
                extra_audits = self._invalidate_stale_incidents(conn, current, patch, actor)
            merged = dict(current["data"])
            merged.update(patch)
            updated = self.repository.update_entity(entity_id, expected, next_status, merged, conn=conn)
            self.repository.append_audit(
                entity_id,
                actor.user_id,
                actor.role,
                action,
                current["status"],
                updated["status"],
                {"patch": patch},
                conn=conn,
            )
            for audit in extra_audits:
                self.repository.append_audit(
                    audit["entity_id"],
                    audit["actor_id"],
                    audit["actor_role"],
                    audit["action"],
                    audit["from_status"],
                    audit["to_status"],
                    audit["detail"],
                    conn=conn,
                )
            if idempotency_key:
                self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id, conn=conn)
        return updated

    def _find_active_incident(self, conn, payload):
        asset_id = payload.get("asset_id")
        fault_kind = payload.get("kind")
        if not asset_id or not fault_kind:
            return None
        for item in self.repository.list_entities(kind="incident", conn=conn):
            if (
                item["status"] in ACTIVE_INCIDENT_STATUSES
                and item["data"].get("asset_id") == asset_id
                and item["data"].get("kind") == fault_kind
            ):
                return item
        return None

    def _has_active_incident(self, conn, asset_id, fault_kind, exclude_id=None):
        for item in self.repository.list_entities(kind="incident", conn=conn):
            if item["id"] == exclude_id:
                continue
            if (
                item["status"] in ACTIVE_INCIDENT_STATUSES
                and item["data"].get("asset_id") == asset_id
                and item["data"].get("kind") == fault_kind
            ):
                return True
        return False

    def _closure_basis(self, conn, incident):
        asset_id = incident["data"].get("asset_id")
        revisions = {}
        max_revision = None
        if asset_id:
            for item in self.repository.find_entities("telemetry", "asset_id", asset_id, conn=conn):
                try:
                    revision = int(item["data"].get("revision", 0))
                except (TypeError, ValueError):
                    continue
                metric = item["data"].get("metric")
                revisions[metric] = revision
                if max_revision is None or revision > max_revision:
                    max_revision = revision
        return {"telemetry_revision": max_revision, "telemetry_revisions": revisions}

    def _invalidate_stale_incidents(self, conn, telemetry, patch, actor):
        """Reopen closed incidents whose closure basis is behind the new revision."""
        asset_id = telemetry["data"].get("asset_id")
        if not asset_id:
            return []
        try:
            new_revision = int(patch.get("revision", telemetry["data"].get("revision", 0)))
        except (TypeError, ValueError):
            return []
        audits = []
        for incident in self.repository.find_entities("incident", "asset_id", asset_id, conn=conn):
            if incident["status"] != "closed":
                continue
            basis = incident["data"].get("closure_basis") or {}
            recorded = basis.get("telemetry_revision")
            if recorded is None or new_revision <= int(recorded):
                continue
            fault_kind = incident["data"].get("kind")
            if self._has_active_incident(conn, asset_id, fault_kind, exclude_id=incident["id"]):
                # An active incident already covers this (asset, kind); the
                # closed one does not need to be reopened.
                continue
            new_data = dict(incident["data"])
            new_data["reconfirmation_required"] = True
            new_data["closure_stale"] = True
            new_data["stale_from_revision"] = recorded
            new_data["stale_to_revision"] = new_revision
            self.repository.update_entity(
                incident["id"], incident["version"], "open", new_data, conn=conn
            )
            audits.append(
                {
                    "entity_id": incident["id"],
                    "actor_id": actor.user_id,
                    "actor_role": actor.role,
                    "action": "reopen",
                    "from_status": "closed",
                    "to_status": "open",
                    "detail": {
                        "reason": "telemetry revision advanced past closure basis",
                        "from_revision": recorded,
                        "to_revision": new_revision,
                    },
                }
            )
        return audits

    def merge_offline(self, actor, records):
        """Merge field records by a stable (source_id, record_id) identity."""
        if not isinstance(records, list):
            raise ValidationError("records must be a list")
        created = []
        for raw in records:
            if not isinstance(raw, dict):
                raise ValidationError("each offline record must be an object")
            source_id = str(raw.get("source_id", "")).strip()
            record_id = str(raw.get("record_id", "")).strip()
            if not source_id or not record_id:
                raise ValidationError("source_id and record_id are required")
            digest = hashlib.sha256((source_id + "\0" + record_id).encode("utf-8")).hexdigest()[:32]
            entity_id = "offline-" + digest
            existing = self.repository.get_entity(entity_id)
            if existing:
                created.append(existing)
                continue
            payload = dict(raw)
            self.rules.validate_create(actor, "offline_record", payload, self._lookup)
            entity = self.repository.create_entity(
                entity_id,
                "offline_record",
                self.rules.initial_status("offline_record", payload),
                payload,
                actor.user_id,
            )
            self.audit.record(
                entity_id, actor, "merge_offline", None, entity["status"],
                {"source_id": source_id, "record_id": record_id},
            )
            created.append(entity)
        return created

    def get(self, entity_id):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        return entity

    def list(self, kind=None, status=None):
        if kind:
            kind = self.rules.normalize_kind(kind)
        return self.repository.list_entities(kind=kind, status=status)

    def audit_log(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)
