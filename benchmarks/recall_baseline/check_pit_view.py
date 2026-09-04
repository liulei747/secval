"""仅创建/删除唯一测试索引，验证并发更新不改变已有审计视图；不调用模型。"""

from uuid import uuid4

from opensearchpy import OpenSearch

import secval.infrastructure.audit.index_evidence_tools as module


client = OpenSearch(hosts=[{"host": "opensearch", "port": 9200}])
index = "secval-audit-pit-test-" + uuid4().hex
module.CODE_INDEX_NAME = index
tools = module.EvidenceTools(client, "repo", "snap")
try:
    client.indices.create(index=index, body={"mappings": {"properties": {
        key: {"type": "keyword"} for key in ("chunk_id", "repository_id", "snapshot_id")}}})
    original = {"chunk_id": "one", "repository_id": "repo", "snapshot_id": "snap",
                "relative_path": "A.java", "start_line": 1, "end_line": 1, "content": "old-source"}
    client.index(index=index, id="one", body=original, refresh=True)
    before = tools.call("read_chunk", {"chunk_id": "one"})["rows"][0]
    client.index(index=index, id="one", body={**original, "content": "new-source"}, refresh=True)
    after = tools.call("read_chunk", {"chunk_id": "one"})["rows"][0]
    assert before["content"] == after["content"] == "old-source"
    assert client.get(index=index, id="one")["_source"]["content"] == "new-source"
    print("PASS: live index changed; audit PIT retained original content")
finally:
    tools.close()
    assert index.startswith("secval-audit-pit-test-") and len(index.split("test-")[1]) == 32
    client.indices.delete(index=index, ignore=[404])
    client.close()
