"""查找代码仓库中的 Java 源文件。"""

import os
from pathlib import Path

# 这些目录通常不包含需要建立索引的项目源代码。
IGNORED_DIRECTORIES = {
    ".git",
    ".idea",
    ".venv",
    ".vscode",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "out",
    "target",
    "vendor",
    "venv",
}

# 首版只处理 Java，增加其他语言时在这里加入对应扩展名。
SUPPORTED_FILE_EXTENSIONS = {".java"}


def scan_repository(root_path: str) -> list[str]:
    """返回仓库中所有受支持源文件的相对路径。

    返回路径统一使用正斜杠，例如 ``src/main/java/App.java``。
    统一格式可以避免 Windows 和 Linux 使用不同路径分隔符。
    """

    repository_path = Path(root_path)

    if not repository_path.exists():
        raise ValueError(f"仓库根目录不存在：{root_path}")

    if not repository_path.is_dir():
        raise ValueError(f"仓库根路径不是目录：{root_path}")

    repository_path = repository_path.resolve()
    source_files: list[str] = []

    for current_path, directory_names, file_names in os.walk(repository_path):
        # 从待扫描目录列表中移除忽略目录，os.walk 就不会继续进入它们。
        directories_to_scan: list[str] = []

        for directory_name in directory_names:
            if directory_name not in IGNORED_DIRECTORIES:
                directories_to_scan.append(directory_name)

        directory_names[:] = directories_to_scan

        for file_name in file_names:
            file_path = Path(current_path) / file_name

            if file_path.suffix.lower() not in SUPPORTED_FILE_EXTENSIONS:
                continue

            if file_path.is_symlink():
                continue

            relative_path = file_path.relative_to(repository_path).as_posix()
            source_files.append(relative_path)

    source_files.sort()
    return source_files
