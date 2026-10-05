import hashlib
from uuid import uuid4

from .audit import AuditTrail
from .domain import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .repository import utcnow
from .rules import ACTIVE_INCIDENT_STATUSES, RuleEngine, incident_scope, incidents_invalidated_by


class DomainService:
    def __init__(self, repository, rules=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)

    def _lookup(self, kind, field, value):
        return self.repository.find_entities(self.rules.normalize_kind(kind), field, value)

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    def _closure_invalidations(self, actor, asset_id, new_revision, telemetry_id):
        """新遥测修订使依据更旧修订号收口的事件结论失效，需重新确认。"""
        cascades, audits, active_ops = [], [], []
        for incident, basis_revision in incidents_invalidated_by(self._lookup, asset_id, new_revision):
            data = dict(incident["data"])
            data.update({
                "closure_valid": False,
                "invalidated_by": {
                    "telemetry_id": telemetry_id,
                    "revision": new_revision,
                    "previous_basis_revision": basis_revision,
                },
                "invalidated_at": utcnow(),
            })
            cascades.append({
                "entity_id": incident["id"],
                "expected_version": incident["version"],
                "status": "reconfirm",
                "data": data,
            })
            audits.append(self.audit.entry(
                incident["id"],
                actor,
                "invalidate_closure",
                incident["status"],
                "reconfirm",
                {
                    "telemetry_id": telemetry_id,
                    "revision": new_revision,
                    "previous_basis_revision": basis_revision,
                },
            ))
            active_ops.append((
                "acquire_ensure",
                incident_scope(incident["data"]),
                incident["data"].get("kind"),
                incident["id"],
            ))
        return cascades, audits, active_ops

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
        status = self.rules.initial_status(kind, payload)
        active_scope = None
        if kind == "incident":
            active_scope = (incident_scope(payload), payload.get("kind"))
        cascades, extra_audits, active_ops = [], [], []
        if kind == "telemetry":
            cascades, extra_audits, active_ops = self._closure_invalidations(
                actor, payload.get("asset_id"), int(payload.get("revision")), entity_id
            )
        audits = [self.audit.entry(entity_id, actor, "create", None, status, {"kind": kind})]
        audits.extend(extra_audits)
        result = self.repository.apply(
            create={
                "entity_id": entity_id,
                "kind": kind,
                "status": status,
                "data": payload,
                "actor_id": actor.user_id,
                "active_scope": active_scope,
            },
            cascades=cascades,
            active_ops=active_ops,
            audits=audits,
            idem={"actor_id": actor.user_id, "key": idempotency_key, "entity_id": entity_id} if idempotency_key else None,
        )
        if result["outcome"] == "deduplicated":
            # 后到的提交拿到活动事件编号，不新建事件、不重复记审计。
            entity = self.repository.get_entity(result["entity_id"])
            entity["deduplicated"] = True
            return entity
        if result["outcome"] == "exists":
            raise ConflictError("entity already exists: " + entity_id)
        return self.repository.get_entity(result.get("entity_id") or entity_id)

    def transition(self, actor, entity_id, action, data=None, expected_version=None, idempotency_key=None):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        if idempotency_key:
            hit = self.repository.find_audit_by_idem_key(idempotency_key)
            if hit:
                if hit["entity_id"] != entity_id:
                    raise ConflictError("idempotency key already used for another entity")
                return entity
        expected = int(expected_version) if expected_version is not None else entity["version"]
        next_status, patch = self.rules.validate_transition(
            actor, entity, action, dict(data or {}), self._lookup
        )
        merged = dict(entity["data"])
        merged.update(patch)
        audits = [self.audit.entry(
            entity_id, actor, action, entity["status"], next_status, {"patch": patch},
            idem_key=idempotency_key,
        )]
        cascades, active_ops = [], []
        if entity["kind"] == "telemetry" and action == "revise":
            cascades, extra_audits, active_ops = self._closure_invalidations(
                actor, merged.get("asset_id"), int(merged.get("revision")), entity_id
            )
            audits.extend(extra_audits)
        if entity["kind"] == "incident":
            active_ops.extend(self._incident_slot_ops(entity, merged, next_status))
        result = self.repository.apply(
            update={
                "entity_id": entity_id,
                "expected_version": expected,
                "status": next_status,
                "data": merged,
            },
            cascades=cascades,
            active_ops=active_ops,
            audits=audits,
        )
        if result["outcome"] == "idempotent":
            if result["entity_id"] != entity_id:
                raise ConflictError("idempotency key already used for another entity")
        return self.repository.get_entity(entity_id)

    @staticmethod
    def _incident_slot_ops(entity, merged, next_status):
        """维护 (范围, 故障类型) 活动槽位：进入活动状态占用，收口释放。"""
        was_active = entity["status"] in ACTIVE_INCIDENT_STATUSES
        is_active = next_status in ACTIVE_INCIDENT_STATUSES
        old_slot = (incident_scope(entity["data"]), entity["data"].get("kind"))
        new_slot = (incident_scope(merged), merged.get("kind"))
        ops = []
        if was_active and not is_active:
            ops.append(("release", old_slot[0], old_slot[1], entity["id"]))
        elif not was_active and is_active:
            ops.append(("acquire_strict", new_slot[0], new_slot[1], entity["id"]))
        elif was_active and is_active and old_slot != new_slot:
            ops.append(("release", old_slot[0], old_slot[1], entity["id"]))
            ops.append(("acquire_strict", new_slot[0], new_slot[1], entity["id"]))
        return ops

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
            status = self.rules.initial_status("offline_record", payload)
            result = self.repository.apply(
                create={
                    "entity_id": entity_id,
                    "kind": "offline_record",
                    "status": status,
                    "data": payload,
                    "actor_id": actor.user_id,
                    "active_scope": None,
                },
                audits=[self.audit.entry(
                    entity_id, actor, "merge_offline", None, status,
                    {"source_id": source_id, "record_id": record_id},
                )],
            )
            created.append(self.repository.get_entity(result.get("entity_id") or entity_id))
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
