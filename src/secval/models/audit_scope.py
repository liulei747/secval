"""授权路径按文件或目录边界匹配，不支持通配符或父目录跳转。"""


def validate_scope_paths(paths):
    if not isinstance(paths, list) or len(paths) > 30:
        raise ValueError("scope_paths必须为最多30个仓库相对路径的数组")
    for path in paths:
        if (not isinstance(path, str) or not 1 <= len(path) <= 1000
                or path != path.strip() or any(c in path for c in "\\:*?[]\x00")
                or any(part in {"", ".", ".."} for part in path.split("/"))):
            raise ValueError("范围必须是规范仓库相对路径，不允许通配符、绝对路径或父目录")
    return list(dict.fromkeys(paths))


def in_scope(path, paths):
    return not paths or any(path == prefix or path.startswith(prefix + "/") for prefix in paths)


def is_executable_descriptor(path):
    """Descriptors that are executable program behavior, rather than secrets/config input."""
    normalized = path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    dependency_manifests = {
        "pom.xml", "build.gradle", "build.gradle.kts", "package-lock.json",
        "requirements.txt", "poetry.lock", "cargo.lock", "go.sum", "bom.json",
    }
    return (name in dependency_manifests
            or (normalized.endswith(".xml")
                and ("/mapper/" in normalized or name.endswith("mapper.xml"))))


def validate_config_paths(paths, scope_paths):
    paths = validate_scope_paths(paths)
    for path in paths:
        name = path.rsplit("/", 1)[-1].lower()
        if (name.startswith(".env") or name.rsplit(".", 1)[-1] not in
                {"xml", "properties", "yaml", "yml", "json", "toml"}):
            raise ValueError("只允许明确选择XML/properties/YAML/JSON/TOML配置，禁止.env和密钥文件")
        if not in_scope(path, scope_paths):
            raise ValueError("批准的配置文件必须位于审计路径范围内")
    return paths
