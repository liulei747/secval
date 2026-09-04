"""单进程原型的SQLite任务存储；重启中断不会冒充任务完成。"""

import json
import sqlite3
from pathlib import Path
from threading import Lock
from uuid import uuid4


class AuditStore:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = str(path)
        self.lock = Lock()
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, data TEXT NOT NULL)"
            )
        for task in self.list():
            if task["status"] in ("queued", "running"):
                self.update(
                    task["id"],
                    status="interrupted",
                    error="服务重启中断；可尝试从检查点续跑，未绑定或版本改变时需新建任务",
                )

    def connect(self):
        return sqlite3.connect(self.path)

    def create(self, request):
        task = {
            "id": uuid4().hex,
            **request,
            "status": "queued",
            "events": [],
            "evidence": {},
            "report": None,
            "error": None,
            "coverage": "partial:仅限已索引代码块；不代表完整源文件或项目覆盖",
        }
        with self.connect() as db:
            db.execute(
                "INSERT INTO tasks VALUES (?, ?)", (task["id"], json.dumps(task))
            )
        return task

    def get(self, task_id):
        with self.connect() as db:
            row = db.execute("SELECT data FROM tasks WHERE id=?", (task_id,)).fetchone()
        if row is None:
            raise KeyError(task_id)
        return json.loads(row[0])

    def list(self):
        with self.connect() as db:
            return [
                json.loads(row[0])
                for row in db.execute("SELECT data FROM tasks ORDER BY rowid DESC")
            ]

    def update(self, task_id, **fields):
        with self.lock:
            task = self.get(task_id)
            if task["status"] == "cancelled":
                return task
            task.update(fields)
            with self.connect() as db:
                db.execute(
                    "UPDATE tasks SET data=? WHERE id=?", (json.dumps(task), task_id)
                )
            return task
