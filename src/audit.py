from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditTrail:
    def __init__(self, repository):
        self.repository = repository

    def entry(self, entity_id, actor, action, from_status, to_status, detail=None, idem_key=None):
        """构建一条审计载荷，供仓库在事务内与其余写入一起提交。"""
        return {
            "entity_id": entity_id,
            "actor_id": actor.user_id,
            "actor_role": actor.role,
            "action": action,
            "from_status": from_status,
            "to_status": to_status,
            "detail": detail or {},
            "idem_key": idem_key,
        }

    def record(self, entity_id, actor, action, from_status, to_status, detail=None):
        self.repository.append_audit(
            entity_id=entity_id,
            actor_id=actor.user_id,
            actor_role=actor.role,
            action=action,
            from_status=from_status,
            to_status=to_status,
            detail=detail or {},
        )

    def list(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)
