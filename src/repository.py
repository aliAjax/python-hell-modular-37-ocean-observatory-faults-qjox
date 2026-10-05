import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from .domain import ConflictError, NotFoundError


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


ACTIVE_INCIDENT_STATUSES = ("open", "diagnosing", "recovery_planned", "recovering")


class SQLiteRepository:
    def __init__(self, path):
        self.path = str(path)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def transaction(self):
        """Run a write unit under one write lock; commit on success, roll back on failure.

        Every write that belongs to the same business operation (entity state,
        version bump, audit entries, idempotency record) must use this so a
        failure rolls them back together instead of leaving a half-written state.
        """
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

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
            """)
            # Partial unique index: at most one *active* incident per
            # (asset, fault kind). This is the hard guarantee behind the
            # "first writer wins" rule; the service re-checks under the
            # transaction lock and falls back to the active incident instead
            # of inserting a duplicate.
            active_list = ", ".join("'%s'" % s for s in ACTIVE_INCIDENT_STATUSES)
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_incident_active_asset_kind "
                "ON entities(json_extract(data, '$.asset_id'), json_extract(data, '$.kind')) "
                "WHERE kind = 'incident' AND status IN (%s)" % active_list
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

    def _entity_from_conn(self, connection, entity_id):
        row = connection.execute(
            "SELECT * FROM entities WHERE id = ?", (entity_id,)
        ).fetchone()
        return self._entity_from_row(row) if row else None

    def create_entity(self, entity_id, kind, status, data, actor_id, conn=None):
        now = utcnow()
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
        sql = (
            "INSERT INTO entities(id, kind, status, version, data, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, 1, ?, ?, ?, ?)"
        )
        params = (entity_id, kind, status, payload, actor_id, now, now)
        if conn is None:
            with self._connect() as connection:
                connection.execute(sql, params)
            return self.get_entity(entity_id)
        try:
            conn.execute(sql, params)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("entity conflicts with an existing record: " + str(exc))
        return self._entity_from_conn(conn, entity_id)

    def get_entity(self, entity_id, conn=None):
        if conn is None:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM entities WHERE id = ?", (entity_id,)
                ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
        return self._entity_from_row(row) if row else None

    def list_entities(self, kind=None, status=None, conn=None):
        clauses = []
        params = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = "SELECT * FROM entities" + where + " ORDER BY created_at, id"
        if conn is None:
            with self._connect() as connection:
                rows = connection.execute(sql, params).fetchall()
        else:
            rows = conn.execute(sql, params).fetchall()
        return [self._entity_from_row(row) for row in rows]

    def find_entities(self, kind, field, value, conn=None):
        entities = self.list_entities(kind=kind, conn=conn)
        if field == "*":
            return entities
        return [
            entity
            for entity in entities
            if (entity["id"] == value if field == "id" else entity["data"].get(field) == value)
        ]

    def update_entity(self, entity_id, expected_version, status, data, conn=None):
        now = utcnow()
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
        if conn is None:
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
        # Caller owns the transaction; only guard the optimistic version.
        row = conn.execute(
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
        try:
            conn.execute(
                "UPDATE entities SET status = ?, version = version + 1, data = ?, updated_at = ? "
                "WHERE id = ? AND version = ?",
                (status, payload, now, entity_id, current_version),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("update conflicts with an existing record: " + str(exc))
        return self._entity_from_conn(conn, entity_id)

    def append_audit(self, entity_id, actor_id, actor_role, action, from_status, to_status, detail, conn=None):
        sql = (
            "INSERT INTO audit_log(entity_id, actor_id, actor_role, action, from_status, to_status, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        params = (
            entity_id,
            actor_id,
            actor_role,
            action,
            from_status,
            to_status,
            json.dumps(detail, ensure_ascii=False, sort_keys=True),
            utcnow(),
        )
        if conn is None:
            with self._connect() as connection:
                connection.execute(sql, params)
            return
        conn.execute(sql, params)

    def list_audit(self, entity_id=None, conn=None):
        if entity_id:
            sql = "SELECT * FROM audit_log WHERE entity_id = ? ORDER BY id"
            params = (entity_id,)
        else:
            sql = "SELECT * FROM audit_log ORDER BY id"
            params = ()
        if conn is None:
            with self._connect() as connection:
                rows = connection.execute(sql, params).fetchall()
        else:
            rows = conn.execute(sql, params).fetchall()
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

    def get_idempotency(self, actor_id, idem_key, conn=None):
        sql = "SELECT entity_id FROM idempotency WHERE actor_id = ? AND idem_key = ?"
        params = (actor_id, idem_key)
        if conn is None:
            with self._connect() as connection:
                row = connection.execute(sql, params).fetchone()
        else:
            row = conn.execute(sql, params).fetchone()
        return row["entity_id"] if row else None

    def save_idempotency(self, actor_id, idem_key, entity_id, conn=None):
        sql = (
            "INSERT OR REPLACE INTO idempotency(actor_id, idem_key, entity_id, created_at) "
            "VALUES (?, ?, ?, ?)"
        )
        params = (actor_id, idem_key, entity_id, utcnow())
        if conn is None:
            with self._connect() as connection:
                connection.execute(sql, params)
            return
        conn.execute(sql, params)

    def ping(self):
        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()
        return True
