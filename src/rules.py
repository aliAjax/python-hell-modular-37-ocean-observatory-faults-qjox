from datetime import datetime, timedelta, timezone

from .domain import ConflictError, InvalidTransition, PermissionDenied, ValidationError

# 处于这些状态的事件占用 (资产范围, 故障类型) 活动槽位，同一时刻只允许一个。
ACTIVE_INCIDENT_STATUSES = ("open", "diagnosing", "recovery_planned", "recovering", "reconfirm")

# 已收口（resolved/closed）的事件可能被迟到的遥测修订推翻。
CONCLUDED_INCIDENT_STATUSES = ("resolved", "closed")


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def incident_scope(data):
    """事件去重范围：优先资产，其次站点，最后链路。"""
    return data.get("asset_id") or data.get("station_id") or data.get("link_id")


def _require(data, fields):
    for field in fields:
        value = data.get(field)
        if value is None or value == "" or value == [] or value == {}:
            raise ValidationError("missing required field: " + field)


def _ensure_role(actor, allowed):
    if "*" not in allowed and actor.role not in allowed:
        raise PermissionDenied("role %s is not allowed here" % actor.role)


def _all(lookup, kind):
    return lookup(kind, "*", None) or [] if lookup else []


def _find_one(lookup, kind, field, value):
    rows = lookup(kind, field, value) or [] if lookup else []
    return rows[0] if rows else None


def _number(value, field):
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValidationError(field + " must be numeric")
    if number < 0:
        raise ValidationError(field + " must be non-negative")
    return number


def _validate_asset(data, lookup):
    if not _find_one(lookup, "station", "id", data.get("station_id")):
        raise ValidationError("asset requires station")
    if data.get("clock_offset_seconds") not in (None, ""):
        _number(data.get("clock_offset_seconds"), "clock_offset_seconds")


def _validate_link(data, lookup):
    if not _find_one(lookup, "station", "id", data.get("station_id")):
        raise ValidationError("link requires station")
    if not _find_one(lookup, "asset", "id", data.get("asset_id")):
        raise ValidationError("link requires asset")
    _number(data.get("capacity"), "capacity")


def _validate_telemetry(data, lookup):
    asset = _find_one(lookup, "asset", "id", data.get("asset_id"))
    if not asset:
        raise ValidationError("telemetry requires asset")
    _number(data.get("value"), "value")
    try:
        revision = int(data.get("revision"))
    except (TypeError, ValueError):
        raise ValidationError("revision must be an integer")
    if revision < 1:
        raise ValidationError("revision must be positive")
    for item in _all(lookup, "telemetry"):
        if item["data"].get("asset_id") == data.get("asset_id") and item["data"].get("metric") == data.get("metric"):
            if int(item["data"].get("revision", 0)) >= revision:
                raise ConflictError("telemetry revision must increase")


def _validate_incident(data, lookup):
    if not data.get("station_id") and not data.get("asset_id") and not data.get("link_id"):
        raise ValidationError("incident requires station_id, asset_id or link_id")
    if data.get("severity") not in ("low", "medium", "high", "critical"):
        raise ValidationError("invalid incident severity")
    # 同一范围同一故障类型的去重由服务层和 incident_active 唯一键保证：
    # 后到的提交拿到活动事件编号而不是冲突错误。


def _validate_action(data, lookup):
    incident = _find_one(lookup, "incident", "id", data.get("incident_id"))
    if not incident or incident["status"] in ("resolved", "closed"):
        raise ValidationError("recovery action requires an active incident")
    if data.get("action_type") not in ("remote_restart", "switch_backup", "firmware_rollback", "dispatch_mission"):
        raise ValidationError("invalid action_type")
    key = data.get("dedupe_key")
    for item in _all(lookup, "recovery_action"):
        if item["data"].get("dedupe_key") == key and item["status"] not in ("succeeded", "failed", "cancelled"):
            raise ConflictError("active recovery action already exists for dedupe_key")


def _validate_mission(data, lookup):
    if not _find_one(lookup, "station", "id", data.get("station_id")):
        raise ValidationError("mission requires station")
    if not data.get("window_start") or not data.get("window_end"):
        raise ValidationError("mission window is required")


def _validate_gap(data, lookup):
    if not _find_one(lookup, "incident", "id", data.get("incident_id")):
        raise ValidationError("data gap requires incident")
    if not data.get("start_at") or not data.get("end_at"):
        raise ValidationError("gap window is required")


def _revise_telemetry(actor, entity, data, lookup):
    try:
        new_revision = int(data.get("revision"))
    except (TypeError, ValueError):
        raise ValidationError("revision must be an integer")
    if new_revision <= int(entity["data"].get("revision", 0)):
        raise ConflictError("late revision must increase revision number")
    return {"late_revision": True, "revised_by": actor.user_id}


def _closure_basis(lookup, asset_id):
    """收口依据：受影响资产当前各指标的最高遥测修订号。"""
    revision = 0
    if asset_id:
        for item in _all(lookup, "telemetry"):
            if item["data"].get("asset_id") == asset_id:
                revision = max(revision, int(item["data"].get("revision", 0) or 0))
    return {"asset_id": asset_id, "telemetry_revision": revision, "recorded_at": utcnow()}


def _resolve_incident(actor, entity, data, lookup):
    actions = [a for a in _all(lookup, "recovery_action") if a["data"].get("incident_id") == entity["id"] and a["status"] not in ("succeeded", "failed", "cancelled")]
    if actions:
        raise ConflictError("incident cannot resolve while recovery actions are active")
    gaps = [g for g in _all(lookup, "gap") if g["data"].get("incident_id") == entity["id"] and g["status"] not in ("filled", "accepted", "closed")]
    if gaps:
        raise ConflictError("incident cannot resolve while data gaps remain open")
    assets = [a for a in _all(lookup, "asset") if a["status"] in ("faulty", "offline", "rebooting")]
    if entity["data"].get("asset_id") and any(a["id"] == entity["data"].get("asset_id") for a in assets):
        raise ConflictError("affected asset is still unavailable")
    return {
        "resolved_by": actor.user_id,
        "closure_basis": _closure_basis(lookup, entity["data"].get("asset_id")),
        "closure_valid": True,
        "invalidated_by": None,
        "invalidated_at": None,
    }


def _complete_action(actor, entity, data, lookup):
    if not data.get("outcome"):
        raise ValidationError("outcome is required")
    return {"completed_by": actor.user_id}


def _complete_mission(actor, entity, data, lookup):
    if not data.get("report"):
        raise ValidationError("report is required")
    return {"completed_by": actor.user_id}


def incidents_invalidated_by(lookup, asset_id, revision):
    """找出被新遥测修订推翻的已收口事件，返回 (事件, 原依据修订号) 列表。"""
    if not asset_id:
        return []
    invalidated = []
    for item in _all(lookup, "incident"):
        if item["status"] not in CONCLUDED_INCIDENT_STATUSES:
            continue
        if item["data"].get("asset_id") != asset_id:
            continue
        basis = item["data"].get("closure_basis") or {}
        basis_revision = int(basis.get("telemetry_revision") or 0)
        if revision > basis_revision:
            invalidated.append((item, basis_revision))
    return invalidated


class RuleEngine:
    ALIASES = {        "stations": "station", "assets": "asset", "links": "link", "telemetries": "telemetry",
        "incidents": "incident", "recovery_actions": "recovery_action", "missions": "mission",
        "gaps": "gap",
    }
    INITIAL_STATUS = {
        "station": "online", "asset": "healthy", "link": "up", "telemetry": "current",
        "incident": "open", "recovery_action": "proposed", "mission": "planned", "gap": "open",
    }
    TRANSITIONS = {
        "station": {
            "degrade": (("online",), "degraded"),
            "go_offline": (("online", "degraded"), "offline"),
            "resume": (("degraded", "offline"), "online"),
        },
        "asset": {
            "degrade": (("healthy",), "degraded"),
            "fail": (("healthy", "degraded"), "faulty"),
            "start_reboot": (("faulty",), "rebooting"),
            "finish_reboot": (("rebooting",), "healthy"),
            "restore": (("faulty",), "healthy"),
        },
        "link": {
            "degrade": (("up",), "degraded"),
            "fail": (("up", "degraded"), "down"),
            "activate_backup": (("down", "degraded"), "backup_active"),
            "restore": (("down", "backup_active", "degraded"), "up"),
        },
        "telemetry": {
            "mark_stale": (("current",), "stale"),
            "quarantine": (("current", "stale"), "quarantined"),
            "revise": (("current", "stale", "quarantined"), "current"),
            "clear": (("stale",), "current"),
        },
        "incident": {
            "diagnose": (("open",), "diagnosing"),
            "plan_recovery": (("diagnosing",), "recovery_planned"),
            "start_recovery": (("recovery_planned",), "recovering"),
            "resolve": (("recovering",), "resolved"),
            "close": (("resolved",), "closed"),
            "confirm_closure": (("reconfirm",), "resolved"),
            "reopen": (("resolved", "closed", "reconfirm"), "open"),
        },
        "recovery_action": {
            "approve": (("proposed",), "approved"),
            "start": (("approved",), "running"),
            "succeed": (("running",), "succeeded"),
            "fail": (("running",), "failed"),
            "cancel": (("proposed", "approved", "running"), "cancelled"),
        },
        "mission": {
            "approve": (("planned",), "approved"),
            "depart": (("approved",), "underway"),
            "complete": (("underway",), "completed"),
            "cancel": (("planned", "approved", "underway"), "cancelled"),
        },
        "gap": {
            "estimate": (("open",), "estimated"),
            "fill": (("estimated",), "filled"),
            "accept": (("filled", "open"), "accepted"),
        },
    }
    CREATE_REQUIRED = {
        "station": ("name", "region"),
        "asset": ("station_id", "asset_type", "serial_no", "last_seen"),
        "link": ("station_id", "asset_id", "link_type", "capacity"),
        "telemetry": ("asset_id", "metric", "value", "observed_at", "revision"),
        "incident": ("kind", "severity", "summary"),
        "recovery_action": ("incident_id", "action_type", "dedupe_key"),
        "mission": ("station_id", "purpose", "window_start", "window_end"),
        "gap": ("incident_id", "start_at", "end_at"),
    }
    ACTION_REQUIRED = {
        ("station", "degrade"): ("reason",),
        ("link", "fail"): ("reason",),
        ("telemetry", "revise"): ("revision",),
        ("recovery_action", "succeed"): ("outcome",),
        ("mission", "complete"): ("report",),
        ("gap", "fill"): ("estimate",),
        ("incident", "resolve"): ("summary",),
        ("incident", "confirm_closure"): ("summary",),
    }
    CREATE_ROLES = {
        "station": ("admin", "engineer"),
        "asset": ("admin", "engineer"),
        "link": ("admin", "engineer"),
        "telemetry": ("admin", "operator", "engineer"),
        "incident": ("admin", "operator", "engineer"),
        "recovery_action": ("admin", "operator", "engineer"),
        "mission": ("admin", "engineer"),
        "gap": ("admin", "operator", "engineer"),
    }
    ROLE_ACTIONS = {
        "degrade": ("admin", "engineer", "operator"),
        "go_offline": ("admin", "engineer", "operator"),
        "resume": ("admin", "engineer", "operator"),
        "fail": ("admin", "engineer", "operator"),
        "start_reboot": ("admin", "engineer", "operator"),
        "finish_reboot": ("admin", "engineer", "operator"),
        "restore": ("admin", "engineer", "operator"),
        "activate_backup": ("admin", "engineer", "operator"),
        "mark_stale": ("admin", "operator", "engineer"),
        "quarantine": ("admin", "engineer", "operator"),
        "revise": ("admin", "operator", "engineer"),
        "clear": ("admin", "operator", "engineer"),
        "diagnose": ("admin", "operator", "engineer"),
        "plan_recovery": ("admin", "operator", "engineer"),
        "start_recovery": ("admin", "operator", "engineer"),
        "resolve": ("admin", "engineer"),
        "close": ("admin", "engineer"),
        "confirm_closure": ("admin", "engineer"),
        "reopen": ("admin", "engineer", "operator"),
        "approve": ("admin", "engineer"),
        "start": ("admin", "engineer", "operator"),
        "succeed": ("admin", "engineer", "operator"),
        "cancel": ("admin", "engineer", "operator"),
        "depart": ("admin", "engineer", "operator"),
        "estimate": ("admin", "engineer", "operator"),
        "fill": ("admin", "engineer", "operator"),
        "accept": ("admin", "engineer", "operator"),
    }
    CUSTOM_CREATE = {
        "asset": lambda a, d, l: _validate_asset(d, l),
        "link": lambda a, d, l: _validate_link(d, l),
        "telemetry": lambda a, d, l: _validate_telemetry(d, l),
        "incident": lambda a, d, l: _validate_incident(d, l),
        "recovery_action": lambda a, d, l: _validate_action(d, l),
        "mission": lambda a, d, l: _validate_mission(d, l),
        "gap": lambda a, d, l: _validate_gap(d, l),
    }
    CUSTOM_TRANSITIONS = {
        ("telemetry", "revise"): _revise_telemetry,
        ("incident", "resolve"): _resolve_incident,
        ("incident", "confirm_closure"): _resolve_incident,
        ("recovery_action", "succeed"): _complete_action,
        ("mission", "complete"): _complete_mission,
    }

    def normalize_kind(self, kind):
        return self.ALIASES.get(kind, kind)

    def initial_status(self, kind, data=None):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        return self.INITIAL_STATUS[kind]

    def validate_create(self, actor, kind, data, lookup=None):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        _ensure_role(actor, self.CREATE_ROLES.get(kind, ("admin",)))
        _require(data, self.CREATE_REQUIRED.get(kind, ()))
        custom = self.CUSTOM_CREATE.get(kind)
        if custom:
            custom(actor, data, lookup)
        return dict(data)

    def validate_transition(self, actor, entity, action, data, lookup=None):
        kind = self.normalize_kind(entity["kind"])
        transition = self.TRANSITIONS.get(kind, {}).get(action)
        if not transition:
            raise InvalidTransition("unknown action %s for %s" % (action, kind))
        allowed_statuses, next_status = transition
        if entity["status"] not in allowed_statuses:
            raise InvalidTransition("cannot %s from status %s" % (action, entity["status"]))
        allowed = self.ROLE_ACTIONS.get((kind, action), self.ROLE_ACTIONS.get(action, ("admin",)))
        _ensure_role(actor, allowed)
        _require(data, self.ACTION_REQUIRED.get((kind, action), ()))
        custom = self.CUSTOM_TRANSITIONS.get((kind, action))
        extra = custom(actor, entity, data, lookup) if custom else {}
        patch = dict(data)
        if extra:
            patch.update(extra)
        return next_status, patch
