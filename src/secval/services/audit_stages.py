"""Persist factual audit stage progress for UI and report consumers."""

from copy import deepcopy
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat()


def record_stage(store, task_id, stage_id, status, *, scope_id="task", name=None,
                 completed_units=None, total_units=None, model_calls=None,
                 tool_operations=None, new_evidence=None, tokens=None,
                 stop_reason=None, error=None, metadata=None):
    """Upsert one stage/scope record while retaining its original start time."""
    task = store.get(task_id)
    rows = deepcopy(task.get("stage_progress", []))
    key = (stage_id, scope_id)
    row = next((item for item in rows
                if (item.get("stage_id"), item.get("scope_id", "task")) == key), None)
    timestamp = _now()
    if row is None:
        row = {"stage_id": stage_id, "scope_id": scope_id,
               "name": name or stage_id, "status": status,
               "started_at": timestamp if status != "queued" else None,
               "finished_at": None}
        rows.append(row)
    row["status"] = status
    if name:
        row["name"] = name
    if status == "running" and not row.get("started_at"):
        row["started_at"] = timestamp
    if status in {"completed", "failed", "stopped", "cancelled"}:
        row["finished_at"] = timestamp
        if not row.get("started_at"):
            row["started_at"] = timestamp
    values = {
        "completed_units": completed_units, "total_units": total_units,
        "model_calls": model_calls, "tool_operations": tool_operations,
        "new_evidence": new_evidence, "tokens": tokens,
        "stop_reason": stop_reason, "error": error,
    }
    row.update({key: value for key, value in values.items() if value is not None})
    if metadata is not None:
        row["metadata"] = deepcopy(metadata)
    atomic = getattr(store, "upsert_stage", None)
    if callable(atomic):
        return atomic(task_id, row)
    store.update(task_id, stage_progress=rows)
    return deepcopy(row)
