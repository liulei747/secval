import unittest

from secval.models.code import CodeRepository
from secval.shared_types import RepositoryId


class CodeRepositoryTest(unittest.TestCase):
    """检查代码仓库模型。"""

    def test_create_repository(self) -> None:
        repository = CodeRepository(
            repository_id=RepositoryId("repo-1"),
            name="示例仓库",
            root_path="D:/projects/example",
        )

        self.assertEqual(repository.name, "示例仓库")

    def test_reject_empty_repository_name(self) -> None:
        with self.assertRaisesRegex(ValueError, "仓库名称不能为空"):
            CodeRepository(
                repository_id=RepositoryId("repo-1"),
                name="   ",
                root_path="D:/projects/example",
            )


if __name__ == "__main__":
    unittest.main()

