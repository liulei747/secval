"""真实 OpenSearch + SQLite 快照取证验证；只写唯一测试索引/临时目录，不调用模型。"""

from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4
import argparse

from opensearchpy import OpenSearch

import secval.infrastructure.audit.index_evidence_tools as evidence_module
from secval.infrastructure.audit.source_snapshot_store import SourceSnapshotStore
from secval.infrastructure.opensearch.code_index import CODE_INDEX_BODY
from secval.models.audit_contracts import CodeEvidence


def expect_refused(action):
    try:
        action()
    except ValueError:
        return
    raise AssertionError("expected refusal")


def main(host="127.0.0.1"):
    client = OpenSearch(hosts=[{"host": host, "port": 9200}])
    index = "secval-audit-snapshot-test-" + uuid4().hex
    views = []
    created = False
    try:
        client.indices.create(index=index, body=CODE_INDEX_BODY)
        created = True
        with TemporaryDirectory(prefix="secval-evidence-check-") as directory:
            root = Path(directory) / "repo"
            (root / "src").mkdir(parents=True)
            (root / "config").mkdir()
            source = "class Login {\n  boolean login() { return false; }\n}\n"
            (root / "src/Login.java").write_bytes(source.encode("utf-8"))
            (root / "config/app.xml").write_text("<auth enabled='true'/>", encoding="utf-8")
            (root / "Outside.java").write_text("class Outside {}", encoding="utf-8")
            store = SourceSnapshotStore(str(Path(directory) / "sources.db"))
            source_id = store.capture(root, "synthetic", "snapshot")
            store.bind(source_id, "synthetic", "snapshot", "run-one")
            document = {"chunk_id": "one", "repository_id": "synthetic", "snapshot_id": "snapshot",
                        "index_run_id": "run-one", "relative_path": "src/Login.java",
                        "content": source, "start_line": 1, "end_line": 3}
            client.index(index=index, id="one", body=document, refresh=True)
            fixed = evidence_module.EvidenceTools(client, "synthetic", "snapshot", store, index_name=index)
            views.append(fixed)
            fixed.call("restrict_scope", {"paths": ["src", "config/app.xml"]})
            fixed.call("approve_config_files", {"paths": ["config/app.xml"]})
            scope = fixed.call("scope_info", {})
            assert scope["source_snapshot_id"] == source_id
            assert {row["path"] for row in scope["_inventory"]} == {"src/Login.java", "config/app.xml"}
            chunk = fixed.call("read_chunk", {"chunk_id": "one"})["rows"][0]
            whole = fixed.call("read_file", {"path": "src/Login.java"})["rows"][0]
            assert chunk["content"] == whole["content"] == source
            assert chunk["content_sha256"] == whole["content_sha256"]
            assert CodeEvidence.from_read(whole).path == "src/Login.java"
            line = fixed.call("read_file", {"path": "src/Login.java", "start_line": 2, "end_line": 2})["rows"][0]
            assert line["content"] == "  boolean login() { return false; }\n"
            assert line["start_line"] == line["end_line"] == 2
            assert fixed.call("read_file", {"path": "config/app.xml"})["rows"]
            assert fixed.call("search_source", {"text": "boolean login()"})["rows"][0]["start_line"] == 2
            assert fixed.call("search_source", {"text": "class Outside"})["rows"] == []
            expect_refused(lambda: fixed.call("read_file", {"path": "Outside.java"}))
            # 外部磁盘和实时索引同时变化，已经固定的两类证据仍来自旧批次。
            (root / "src/Login.java").write_text("class Replaced {}", encoding="utf-8")
            client.index(index=index, id="one", body={**document, "index_run_id": "run-two",
                                                       "content": "class Replaced {}"}, refresh=True)
            assert fixed.call("read_file", {"path": "src/Login.java"})["rows"][0]["content"] == source
            assert fixed.call("read_chunk", {"chunk_id": "one"})["rows"][0]["content"] == source
            assert fixed.call("search_source", {"text": "boolean login()"})["rows"]
            fresh = evidence_module.EvidenceTools(client, "synthetic", "snapshot", store, index_name=index)
            views.append(fresh)
            expect_refused(lambda: fresh.call("read_file", {"path": "src/Login.java"}))
            print("PASS: bound chunk/file identity; scoped inventory; exact lines; approved config; immutable PIT/source; unbound batch refused")
    finally:
        for view in views:
            view.close()
        if created:
            assert index.startswith("secval-audit-snapshot-test-") and len(index.rsplit("-", 1)[1]) == 32
            client.indices.delete(index=index, ignore=[404])
        client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    main(parser.parse_args().host)
