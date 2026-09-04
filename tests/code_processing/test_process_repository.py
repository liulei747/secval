from pathlib import Path

from secval.code_processing.repository_processing import process_repository
from secval.models.identifiers import RepositoryId, SnapshotId


def test_process_a_java_repository(tmp_path: Path) -> None:
    source_directory = tmp_path / "src"
    source_directory.mkdir()
    java_file = source_directory / "UserService.java"
    java_file.write_text(
        """
        package demo;

        class UserService {
            public Object findUser() {
                return null;
            }
        }
        """,
        encoding="utf-8",
    )

    result = process_repository(
        root_path=str(tmp_path),
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
    )

    assert result.total_files == 1
    assert result.successful_files == 1
    assert result.errors == []
    assert {chunk.chunk_type for chunk in result.chunks} == {
        "file",
        "class",
        "method",
    }
    method_chunk = next(
        chunk for chunk in result.chunks if chunk.chunk_type == "method"
    )
    assert method_chunk.symbol_name == "demo.UserService.findUser()"
    assert "public Object findUser()" in method_chunk.content


def test_continue_after_one_java_file_has_syntax_error(
    tmp_path: Path,
) -> None:
    valid_file = tmp_path / "Valid.java"
    invalid_file = tmp_path / "Invalid.java"
    valid_file.write_text(
        "class Valid { void run() {} }",
        encoding="utf-8",
    )
    invalid_file.write_text(
        "class Invalid { void broken( { }",
        encoding="utf-8",
    )

    result = process_repository(
        root_path=str(tmp_path),
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
    )

    assert result.total_files == 2
    assert result.successful_files == 1
    assert {chunk.chunk_type for chunk in result.chunks} == {
        "file",
        "class",
        "method",
    }
    assert len(result.errors) == 1
    assert result.errors[0].relative_path == "Invalid.java"
    assert "语法错误" in result.errors[0].message
