import json
import sqlite3
from datetime import datetime, timezone

from .domain import ConflictError, NotFoundError


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class SQLiteRepository:
    def __init__(self, path):
        self.path = str(path)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS entities (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    data TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_entities_kind_status
                    ON entities(kind, status);
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_entity
                    ON audit_log(entity_id, id);
                CREATE TABLE IF NOT EXISTS idempotency (
                    actor_id TEXT NOT NULL,
                    idem_key TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(actor_id, idem_key)
                );
                CREATE TABLE IF NOT EXISTS incident_active (
                    scope TEXT NOT NULL,
                    fault_kind TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(scope, fault_kind)
                );
            """)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_log)")}
            if "idem_key" not in columns:
                connection.execute("ALTER TABLE audit_log ADD COLUMN idem_key TEXT")
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_idem_key "
                "ON audit_log(idem_key) WHERE idem_key IS NOT NULL"
            )

    @staticmethod
    def _entity_from_row(row):
        return {
            "id": row["id"],
            "kind": row["kind"],
            "status": row["status"],
            "version": int(row["version"]),
            "data": json.loads(row["data"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def create_entity(self, entity_id, kind, status, data, actor_id):
        now = utcnow()
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO entities(id, kind, status, version, data, created_by, created_at, updated_at) "
                "VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
                (entity_id, kind, status, payload, actor_id, now, now),
            )
        return self.get_entity(entity_id)

    def get_entity(self, entity_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
        return self._entity_from_row(row) if row else None

    def list_entities(self, kind=None, status=None):
        clauses = []
        params = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM entities" + where + " ORDER BY created_at, id", params
            ).fetchall()
        return [self._entity_from_row(row) for row in rows]

    def find_entities(self, kind, field, value):
        entities = self.list_entities(kind=kind)
        if field == "*":
            return entities
        return [
            entity
            for entity in entities
            if (entity["id"] == value if field == "id" else entity["data"].get(field) == value)
        ]

    def update_entity(self, entity_id, expected_version, status, data):
        now = utcnow()
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT version FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
            if not row:
                raise NotFoundError("entity not found: " + entity_id)
            current_version = int(row["version"])
            if expected_version is not None and current_version != int(expected_version):
                raise ConflictError(
                    "version conflict: expected %s, found %s"
                    % (expected_version, current_version)
                )
            connection.execute(
                "UPDATE entities SET status = ?, version = version + 1, data = ?, updated_at = ? "
                "WHERE id = ? AND version = ?",
                (status, payload, now, entity_id, current_version),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get_entity(entity_id)

    def apply(self, *, create=None, update=None, cascades=(), active_ops=(), audits=(), idem=None):
        """原子执行一组写入：实体状态、修订号、活动事件槽位和审计一起提交或一起回滚。

        create: {"entity_id", "kind", "status", "data", "actor_id", "active_scope": (scope, fault_kind)|None}
        update: {"entity_id", "expected_version", "status", "data"}
        cascades: [{"entity_id", "expected_version", "status", "data"}]
        active_ops: [("release"|"acquire_strict"|"acquire_ensure", scope, fault_kind, incident_id)]
        audits: [{"entity_id", "actor_id", "actor_role", "action", "from_status", "to_status", "detail", "idem_key"}]
        idem: {"actor_id", "key", "entity_id"} 创建级幂等记录
        返回 {"outcome": "applied"} 或 {"outcome": "idempotent"|"exists"|"deduplicated", "entity_id": ...}。
        """
        now = utcnow()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if idem:
                row = connection.execute(
                    "SELECT entity_id FROM idempotency WHERE actor_id = ? AND idem_key = ?",
                    (idem["actor_id"], idem["key"]),
                ).fetchone()
                if row:
                    connection.rollback()
                    return {"outcome": "idempotent", "entity_id": row["entity_id"]}
            if create:
                row = connection.execute(
                    "SELECT id FROM entities WHERE id = ?", (create["entity_id"],)
                ).fetchone()
                if row:
                    connection.rollback()
                    return {"outcome": "exists", "entity_id": create["entity_id"]}
                scope = create.get("active_scope")
                if scope:
                    row = connection.execute(
                        "SELECT incident_id FROM incident_active WHERE scope = ? AND fault_kind = ?",
                        scope,
                    ).fetchone()
                    if row:
                        connection.rollback()
                        return {"outcome": "deduplicated", "entity_id": row["incident_id"]}
            for entry in audits:
                key = entry.get("idem_key")
                if not key:
                    continue
                row = connection.execute(
                    "SELECT entity_id FROM audit_log WHERE idem_key = ?", (key,)
                ).fetchone()
                if row:
                    connection.rollback()
                    return {"outcome": "idempotent", "entity_id": row["entity_id"]}
            if update:
                row = connection.execute(
                    "SELECT version FROM entities WHERE id = ?", (update["entity_id"],)
                ).fetchone()
                if not row:
                    raise NotFoundError("entity not found: " + update["entity_id"])
                current_version = int(row["version"])
                expected = update.get("expected_version")
                if expected is not None and current_version != int(expected):
                    raise ConflictError(
                        "version conflict: expected %s, found %s"
                            % (expected, current_version)
                    )
                connection.execute(
                    "UPDATE entities SET status = ?, version = version + 1, data = ?, updated_at = ? "
                    "WHERE id = ? AND version = ?",
                    (
                        update["status"],
                        json.dumps(update["data"], ensure_ascii=False, sort_keys=True),
                        now,
                        update["entity_id"],
                        current_version,
                    ),
                )
            for cascade in cascades:
                cursor = connection.execute(
                    "UPDATE entities SET status = ?, version = version + 1, data = ?, updated_at = ? "
                    "WHERE id = ? AND version = ?",
                    (
                        cascade["status"],
                        json.dumps(cascade["data"], ensure_ascii=False, sort_keys=True),
                        now,
                        cascade["entity_id"],
                        int(cascade["expected_version"]),
                    ),
                )
                if cursor.rowcount == 0:
                    row = connection.execute(
                        "SELECT version FROM entities WHERE id = ?", (cascade["entity_id"],)
                    ).fetchone()
                    if not row:
                        raise NotFoundError("entity not found: " + cascade["entity_id"])
                    raise ConflictError(
                        "version conflict: expected %s, found %s"
                        % (cascade["expected_version"], int(row["version"]))
                    )
            for op, scope, fault_kind, incident_id in active_ops:
                if op == "release":
                    connection.execute(
                        "DELETE FROM incident_active WHERE scope = ? AND fault_kind = ? AND incident_id = ?",
                        (scope, fault_kind, incident_id),
                    )
                    continue
                if op == "acquire_strict":
                    row = connection.execute(
                        "SELECT incident_id FROM incident_active WHERE scope = ? AND fault_kind = ?",
                        (scope, fault_kind),
                    ).fetchone()
                    if row and row["incident_id"] != incident_id:
                        raise ConflictError("active incident already exists for asset and kind")
                connection.execute(
                    "INSERT OR IGNORE INTO incident_active(scope, fault_kind, incident_id, created_at) "
                    "VALUES (?, ?, ?, ?)",
                    (scope, fault_kind, incident_id, now),
                )
            if create:
                connection.execute(
                    "INSERT INTO entities(id, kind, status, version, data, created_by, created_at, updated_at) "
                    "VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
                    (
                        create["entity_id"],
                        create["kind"],
                        create["status"],
                        json.dumps(create["data"], ensure_ascii=False, sort_keys=True),
                        create["actor_id"],
                        now,
                        now,
                    ),
                )
                if create.get("active_scope"):
                    connection.execute(
                        "INSERT INTO incident_active(scope, fault_kind, incident_id, created_at) "
                        "VALUES (?, ?, ?, ?)",
                        (create["active_scope"][0], create["active_scope"][1], create["entity_id"], now),
                    )
            if idem:
                connection.execute(
                    "INSERT INTO idempotency(actor_id, idem_key, entity_id, created_at) VALUES (?, ?, ?, ?)",
                    (idem["actor_id"], idem["key"], idem["entity_id"], now),
                )
            for entry in audits:
                connection.execute(
                    "INSERT INTO audit_log(entity_id, actor_id, actor_role, action, from_status, to_status, detail, idem_key, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        entry["entity_id"],
                        entry["actor_id"],
                        entry["actor_role"],
                        entry["action"],
                        entry.get("from_status"),
                        entry["to_status"],
                        json.dumps(entry.get("detail") or {}, ensure_ascii=False, sort_keys=True),
                        entry.get("idem_key"),
                        now,
                    ),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return {"outcome": "applied"}

    def find_audit_by_idem_key(self, idem_key):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT entity_id, action FROM audit_log WHERE idem_key = ?", (idem_key,)
            ).fetchone()
        return {"entity_id": row["entity_id"], "action": row["action"]} if row else None

    def append_audit(self, entity_id, actor_id, actor_role, action, from_status, to_status, detail):
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO audit_log(entity_id, actor_id, actor_role, action, from_status, to_status, detail, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entity_id,
                    actor_id,
                    actor_role,
                    action,
                    from_status,
                    to_status,
                    json.dumps(detail, ensure_ascii=False, sort_keys=True),
                    utcnow(),
                ),
            )

    def list_audit(self, entity_id=None):
        with self._connect() as connection:
            if entity_id:
                rows = connection.execute(
                    "SELECT * FROM audit_log WHERE entity_id = ? ORDER BY id", (entity_id,)
                ).fetchall()
            else:
                rows = connection.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        return [
            {
                "id": row["id"],
                "entity_id": row["entity_id"],
                "actor_id": row["actor_id"],
                "actor_role": row["actor_role"],
                "action": row["action"],
                "from_status": row["from_status"],
                "to_status": row["to_status"],
                "detail": json.loads(row["detail"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def get_idempotency(self, actor_id, idem_key):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT entity_id FROM idempotency WHERE actor_id = ? AND idem_key = ?",
                (actor_id, idem_key),
            ).fetchone()
        return row["entity_id"] if row else None

    def save_idempotency(self, actor_id, idem_key, entity_id):
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO idempotency(actor_id, idem_key, entity_id, created_at) "
                "VALUES (?, ?, ?, ?)",
                (actor_id, idem_key, entity_id, utcnow()),
            )

    def ping(self):
        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()
        return True
