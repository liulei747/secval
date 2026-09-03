import unittest

from secval.models.code import SourceFile
from secval.shared_types import FileId, RepositoryId, SnapshotId


class SourceFileTest(unittest.TestCase):
    """检查源代码文件模型。"""

    def test_create_source_file(self) -> None:
        source_file = SourceFile(
            file_id=FileId("file-1"),
            repository_id=RepositoryId("repo-1"),
            snapshot_id=SnapshotId("snapshot-1"),
            relative_path="src/main/java/UserService.java",
            language="java",
            content="public class UserService {}",
        )

        self.assertEqual(
            source_file.relative_path,
            "src/main/java/UserService.java",
        )
        self.assertEqual(source_file.language, "java")

    def test_allow_empty_file_content(self) -> None:
        source_file = SourceFile(
            file_id=FileId("file-1"),
            repository_id=RepositoryId("repo-1"),
            snapshot_id=SnapshotId("snapshot-1"),
            relative_path="src/Empty.java",
            language="java",
            content="",
        )

        self.assertEqual(source_file.content, "")

    def test_reject_empty_relative_path(self) -> None:
        with self.assertRaisesRegex(ValueError, "文件相对路径不能为空"):
            SourceFile(
                file_id=FileId("file-1"),
                repository_id=RepositoryId("repo-1"),
                snapshot_id=SnapshotId("snapshot-1"),
                relative_path="   ",
                language="java",
                content="public class UserService {}",
            )


if __name__ == "__main__":
    unittest.main()

