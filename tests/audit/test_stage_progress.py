from concurrent.futures import ThreadPoolExecutor

from secval.infrastructure.audit.sqlite_audit_store import AuditStore
from secval.services.audit_stages import record_stage


def test_stage_progress_preserves_start_and_records_units(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    task = store.create({"objective": "stage progress test", "max_steps": 10})

    started = record_stage(store, task["id"], "path_validation", "running",
                           scope_id="packet-1", completed_units=0, total_units=3)
    finished = record_stage(store, task["id"], "path_validation", "completed",
                            scope_id="packet-1", completed_units=3, total_units=3,
                            model_calls=1, tokens=420)

    assert finished["started_at"] == started["started_at"]
    assert finished["finished_at"]
    assert finished["completed_units"] == finished["total_units"] == 3
    assert finished["model_calls"] == 1
    assert finished["tokens"] == 420


def test_parallel_packet_progress_is_not_lost(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    task = store.create({"objective": "parallel stage test", "max_steps": 10})

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda number: record_stage(
            store, task["id"], "path_validation", "completed",
            scope_id=f"packet-{number}", completed_units=1, total_units=1,
        ), range(8)))

    rows = [row for row in store.get(task["id"])["stage_progress"]
            if row["stage_id"] == "path_validation"]
    assert len(rows) == 8
    assert {row["scope_id"] for row in rows} == {f"packet-{number}" for number in range(8)}
