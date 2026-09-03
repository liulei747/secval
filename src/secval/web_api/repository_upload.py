"""安全保存从 Web 接口上传的代码仓库目录。"""

import os
import re
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath
from uuid import uuid4

from fastapi import UploadFile
from pydantic import BaseModel

MAX_UPLOAD_FILE_COUNT = 10_000
MAX_UPLOAD_TOTAL_BYTES = 500 * 1024 * 1024
MAX_ZIP_FILE_BYTES = 200 * 1024 * 1024
UPLOAD_COPY_BUFFER_SIZE = 1024 * 1024
SAFE_REPOSITORY_DIRECTORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class UploadRepositoryResponse(BaseModel):
    """代码仓库目录上传完成后的结果。"""

    repository_path: str
    uploaded_files: int
    uploaded_bytes: int
    replaced_existing: bool


def save_uploaded_repository(
    repository_directory: str,
    uploaded_files: list[UploadFile],
    replace_existing: bool,
) -> UploadRepositoryResponse:
    """先完整保存到临时目录，再一次性换成正式仓库目录。"""

    cleaned_directory = validate_repository_directory(repository_directory)

    if len(uploaded_files) > MAX_UPLOAD_FILE_COUNT:
        raise ValueError(f"一次最多上传 {MAX_UPLOAD_FILE_COUNT} 个文件")

    repositories_root = get_repositories_root()
    repositories_root.mkdir(parents=True, exist_ok=True)
    target_directory = repositories_root / cleaned_directory

    ensure_replacement_is_allowed(target_directory, replace_existing)

    upload_id = uuid4().hex
    temporary_directory = repositories_root / f".upload-{upload_id}"
    uploaded_bytes = 0

    try:
        temporary_directory.mkdir()
        saved_paths: set[Path] = set()

        for uploaded_file in uploaded_files:
            relative_path = validate_uploaded_path(uploaded_file.filename)
            destination = temporary_directory.joinpath(*relative_path.parts)

            if destination in saved_paths:
                raise ValueError(f"上传内容包含重复路径：{relative_path}")
            saved_paths.add(destination)

            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("wb") as saved_file:
                while True:
                    file_part = uploaded_file.file.read(UPLOAD_COPY_BUFFER_SIZE)
                    if not file_part:
                        break
                    uploaded_bytes += len(file_part)
                    if uploaded_bytes > MAX_UPLOAD_TOTAL_BYTES:
                        raise ValueError("一次上传的文件总大小不能超过 500 MB")
                    saved_file.write(file_part)

        replaced_existing = replace_repository_directory(
            repositories_root=repositories_root,
            target_directory=target_directory,
            temporary_directory=temporary_directory,
            upload_id=upload_id,
        )

        return UploadRepositoryResponse(
            repository_path=cleaned_directory,
            uploaded_files=len(uploaded_files),
            uploaded_bytes=uploaded_bytes,
            replaced_existing=replaced_existing,
        )
    finally:
        if temporary_directory.exists():
            shutil.rmtree(temporary_directory)


def save_uploaded_zip(
    repository_directory: str,
    uploaded_zip: UploadFile,
    replace_existing: bool,
) -> UploadRepositoryResponse:
    """安全解压 ZIP，并把解压结果保存成正式仓库目录。"""

    cleaned_directory = validate_repository_directory(repository_directory)
    if uploaded_zip.filename is None or not uploaded_zip.filename.lower().endswith(
        ".zip"
    ):
        raise ValueError("压缩包必须是 .zip 文件")

    uploaded_zip.file.seek(0, 2)
    zip_file_bytes = uploaded_zip.file.tell()
    uploaded_zip.file.seek(0)
    if zip_file_bytes > MAX_ZIP_FILE_BYTES:
        raise ValueError("ZIP 文件不能超过 200 MB")

    repositories_root = get_repositories_root()
    repositories_root.mkdir(parents=True, exist_ok=True)
    target_directory = repositories_root / cleaned_directory
    ensure_replacement_is_allowed(target_directory, replace_existing)

    upload_id = uuid4().hex
    temporary_directory = repositories_root / f".upload-{upload_id}"

    try:
        temporary_directory.mkdir()
        try:
            with zipfile.ZipFile(uploaded_zip.file) as archive:
                zip_entries = prepare_zip_entries(archive)
                extracted_bytes = extract_zip_entries(
                    archive,
                    zip_entries,
                    temporary_directory,
                )
        except zipfile.BadZipFile as error:
            raise ValueError("上传的文件不是有效 ZIP 压缩包") from error

        replaced_existing = replace_repository_directory(
            repositories_root=repositories_root,
            target_directory=target_directory,
            temporary_directory=temporary_directory,
            upload_id=upload_id,
        )
        return UploadRepositoryResponse(
            repository_path=cleaned_directory,
            uploaded_files=len(zip_entries),
            uploaded_bytes=extracted_bytes,
            replaced_existing=replaced_existing,
        )
    finally:
        if temporary_directory.exists():
            shutil.rmtree(temporary_directory)


def prepare_zip_entries(
    archive: zipfile.ZipFile,
) -> list[tuple[zipfile.ZipInfo, PurePosixPath]]:
    """检查 ZIP 目录，并生成去掉共同最外层目录后的文件路径。"""

    file_entries = [entry for entry in archive.infolist() if not entry.is_dir()]
    if not file_entries:
        raise ValueError("ZIP 压缩包中没有文件")
    if len(file_entries) > MAX_UPLOAD_FILE_COUNT:
        raise ValueError(f"ZIP 解压后最多允许 {MAX_UPLOAD_FILE_COUNT} 个文件")

    declared_size = sum(entry.file_size for entry in file_entries)
    if declared_size > MAX_UPLOAD_TOTAL_BYTES:
        raise ValueError("ZIP 解压后的总大小不能超过 500 MB")

    checked_entries: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
    checked_paths: list[PurePosixPath] = []
    for entry in file_entries:
        if entry.flag_bits & 0x1:
            raise ValueError(f"不支持加密的 ZIP 文件：{entry.filename}")
        if is_zip_symbolic_link(entry):
            raise ValueError(f"ZIP 中不能包含符号链接：{entry.filename}")

        checked_path = validate_uploaded_path(entry.filename)
        checked_entries.append((entry, checked_path))
        checked_paths.append(checked_path)

    common_root = find_common_zip_root(checked_paths)
    prepared_entries: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
    prepared_paths: set[PurePosixPath] = set()
    for entry, checked_path in checked_entries:
        final_path = checked_path
        if common_root is not None:
            final_path = PurePosixPath(*checked_path.parts[1:])

        if final_path in prepared_paths:
            raise ValueError(f"ZIP 中包含重复路径：{final_path}")
        prepared_paths.add(final_path)
        prepared_entries.append((entry, final_path))

    return prepared_entries


def extract_zip_entries(
    archive: zipfile.ZipFile,
    zip_entries: list[tuple[zipfile.ZipInfo, PurePosixPath]],
    temporary_directory: Path,
) -> int:
    """按检查后的相对路径逐块解压文件。"""

    extracted_bytes = 0
    for entry, relative_path in zip_entries:
        destination = temporary_directory.joinpath(*relative_path.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)

        with (
            archive.open(entry) as source_file,
            destination.open("wb") as saved_file,
        ):
            while True:
                file_part = source_file.read(UPLOAD_COPY_BUFFER_SIZE)
                if not file_part:
                    break
                extracted_bytes += len(file_part)
                if extracted_bytes > MAX_UPLOAD_TOTAL_BYTES:
                    raise ValueError("ZIP 解压后的总大小不能超过 500 MB")
                saved_file.write(file_part)

    return extracted_bytes


def find_common_zip_root(paths: list[PurePosixPath]) -> str | None:
    """所有文件都在同一个顶层目录时，返回这个目录名。"""

    if not paths or any(len(path.parts) < 2 for path in paths):
        return None

    first_root = paths[0].parts[0]
    if all(path.parts[0] == first_root for path in paths):
        return first_root
    return None


def is_zip_symbolic_link(entry: zipfile.ZipInfo) -> bool:
    """根据 ZIP 保存的 Unix 文件类型判断条目是否为符号链接。"""

    unix_file_type = (entry.external_attr >> 16) & 0o170000
    return unix_file_type == stat.S_IFLNK


def validate_uploaded_path(filename: str | None) -> PurePosixPath:
    """验证浏览器提交的相对文件路径，拒绝写到仓库目录以外。"""

    if filename is None or not filename.strip():
        raise ValueError("上传文件缺少名称")

    normalized_name = filename.replace("\\", "/")
    relative_path = PurePosixPath(normalized_name)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError(f"上传文件路径不安全：{filename}")

    safe_parts = [part for part in relative_path.parts if part not in {"", "."}]
    if not safe_parts:
        raise ValueError("上传文件缺少有效路径")
    return PurePosixPath(*safe_parts)


def validate_repository_directory(repository_directory: str) -> str:
    """仓库目录名必须是 repositories 根目录下的一个简单目录名。"""

    cleaned_directory = repository_directory.strip()
    if not SAFE_REPOSITORY_DIRECTORY.fullmatch(cleaned_directory):
        raise ValueError(
            "仓库目录只能包含英文字母、数字、点、下划线和短横线，"
            "并且必须以字母或数字开头"
        )
    return cleaned_directory


def ensure_replacement_is_allowed(
    target_directory: Path,
    replace_existing: bool,
) -> None:
    """已有同名仓库时，要求调用方明确允许替换。"""

    if target_directory.exists() and not replace_existing:
        raise FileExistsError(
            f"仓库目录已经存在：{target_directory.name}；"
            "如需替换请明确允许覆盖"
        )


def replace_repository_directory(
    repositories_root: Path,
    target_directory: Path,
    temporary_directory: Path,
    upload_id: str,
) -> bool:
    """用完整临时目录替换正式目录；切换失败时恢复旧目录。"""

    backup_directory = repositories_root / f".backup-{upload_id}"
    replaced_existing = target_directory.exists()
    if replaced_existing:
        target_directory.rename(backup_directory)

    try:
        try:
            temporary_directory.rename(target_directory)
        except PermissionError:
            # Docker Desktop 的 Windows bind mount 可能拒绝目录改名。
            # 这种情况下逐文件复制，但仍保留旧目录备份用于失败回滚。
            copy_repository_directory(
                source_directory=temporary_directory,
                target_directory=target_directory,
            )
    except Exception:
        if target_directory.exists():
            shutil.rmtree(target_directory)
        if backup_directory.exists():
            backup_directory.rename(target_directory)
        raise

    if backup_directory.exists():
        shutil.rmtree(backup_directory)
    return replaced_existing


def copy_repository_directory(
    source_directory: Path,
    target_directory: Path,
) -> None:
    """逐文件复制仓库，不复制 Windows 挂载不支持的目录元数据。"""

    target_directory.mkdir()
    for source_path in source_directory.rglob("*"):
        relative_path = source_path.relative_to(source_directory)
        target_path = target_directory / relative_path

        if source_path.is_dir():
            target_path.mkdir(exist_ok=True)
        else:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_path, target_path)


def get_repositories_root() -> Path:
    """取得容器或本机配置的仓库保存根目录。"""

    return Path(os.getenv("SECVAL_REPOSITORIES_ROOT", "/repositories")).resolve()
