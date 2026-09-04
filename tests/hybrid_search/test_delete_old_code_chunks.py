from unittest.mock import MagicMock

from secval.infrastructure.opensearch import (
    CODE_INDEX_NAME,
    delete_old_code_chunks,
)
from secval.models.identifiers import RepositoryId, SnapshotId


def test_delete_only_chunks_from_an_older_index_run() -> None:
    connection = MagicMock()
    connection.delete_by_query.return_value = {"deleted": 4}

    deleted_count = delete_old_code_chunks(
        connection=connection,
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
        current_index_run_id="run-2",
    )

    assert deleted_count == 4

    call_arguments = connection.delete_by_query.call_args.kwargs
    query = call_arguments["body"]["query"]["bool"]

    assert call_arguments["index"] == CODE_INDEX_NAME
    assert {"term": {"repository_id": "repository-1"}} in query["filter"]
    assert {"term": {"snapshot_id": "snapshot-1"}} in query["filter"]
    assert {"term": {"index_run_id": "run-2"}} in query["must_not"]
    assert call_arguments["refresh"] is True
