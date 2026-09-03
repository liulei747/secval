"""扫描并处理一个代码仓库。"""

from secval.code_processing.code_splitting.java import split_java_declarations
from secval.code_processing.repository_scan import scan_repository
from secval.code_processing.source_parsing import parse_java
from secval.code_processing.source_reading import read_source_file
from secval.code_processing.source_reading.read_source_file import (
    DEFAULT_MAX_FILE_SIZE,
)
from secval.models.code import (
    CodeChunk,
    FileProcessError,
    RepositoryProcessResult,
)
from secval.shared_types import (
    RepositoryId,
    SnapshotId,
    create_file_id,
)


def process_repository(
    root_path: str,
    repository_id: RepositoryId,
    snapshot_id: SnapshotId,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> RepositoryProcessResult:
    """扫描仓库，并把可以正常处理的 Java 声明转换成代码块。"""

    relative_paths = scan_repository(root_path)
    chunks: list[CodeChunk] = []
    errors: list[FileProcessError] = []
    successful_files = 0

    for relative_path in relative_paths:
        try:
            file_id = create_file_id(
                repository_id=repository_id,
                snapshot_id=snapshot_id,
                relative_path=relative_path,
            )
            source_file = read_source_file(
                root_path=root_path,
                relative_path=relative_path,
                file_id=file_id,
                repository_id=repository_id,
                snapshot_id=snapshot_id,
                max_file_size=max_file_size,
            )
            syntax_tree = parse_java(source_file)
            file_chunks = split_java_declarations(source_file, syntax_tree)
            chunks.extend(file_chunks)
            successful_files += 1

        except (ValueError, OSError) as error:
            errors.append(
                FileProcessError(
                    relative_path=relative_path,
                    message=str(error),
                )
            )

    return RepositoryProcessResult(
        total_files=len(relative_paths),
        successful_files=successful_files,
        chunks=chunks,
        errors=errors,
    )

