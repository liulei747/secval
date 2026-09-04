import unittest

from secval.models.code import CodeSnapshot
from secval.models.identifiers import RepositoryId, SnapshotId


class CodeSnapshotTest(unittest.TestCase):
    """检查代码版本模型。"""

    def test_create_snapshot(self) -> None:
        snapshot = CodeSnapshot(
            snapshot_id=SnapshotId("snapshot-1"),
            repository_id=RepositoryId("repo-1"),
            version="a1b2c3d4",
        )

        self.assertEqual(snapshot.version, "a1b2c3d4")

    def test_reject_empty_version(self) -> None:
        with self.assertRaisesRegex(ValueError, "代码版本不能为空"):
            CodeSnapshot(
                snapshot_id=SnapshotId("snapshot-1"),
                repository_id=RepositoryId("repo-1"),
                version="   ",
            )


if __name__ == "__main__":
    unittest.main()

