"""解释后台任务的租约状态。"""

from datetime import datetime, timezone


def lease_state(status, lease_expires_at):
    """返回 pending、inactive、missing、healthy 或 expired。"""
    if status not in {"queued", "running", "cancelling"}:
        return "inactive"
    if status == "queued" and not lease_expires_at:
        return "pending"
    if not lease_expires_at:
        return "missing"
    try:
        expires_at = datetime.fromisoformat(lease_expires_at)
    except (TypeError, ValueError):
        return "invalid"
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        return "expired"
    return "healthy"
