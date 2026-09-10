"""Build behavior-preserving source variants from an explicit, reviewable manifest."""

import argparse
import json
import re
import shutil
from pathlib import Path, PurePosixPath


def _safe_relative(value):
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"mutation路径必须位于样例目录内: {value}")
    return path


def _replace_identifier(content, old, new):
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", old or ""):
        raise ValueError("rename.from必须是标识符")
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", new or ""):
        raise ValueError("rename.to必须是标识符")
    return re.sub(rf"(?<![A-Za-z0-9_$]){re.escape(old)}(?![A-Za-z0-9_$])", new, content)


def apply_manifest(source_root, output_root, manifest):
    """Copy a fixture and apply rename, API substitution, wrapper and move mutations."""
    source_root, output_root = Path(source_root).resolve(), Path(output_root).resolve()
    if output_root == source_root or output_root.is_relative_to(source_root):
        raise ValueError("mutation输出目录必须与输入目录隔离")
    if output_root.exists():
        raise ValueError("mutation输出目录已存在")
    shutil.copytree(source_root, output_root)
    for operation in manifest.get("operations", []):
        kind = operation.get("kind")
        relative = _safe_relative(operation.get("path", ""))
        target = output_root.joinpath(*relative.parts).resolve()
        if not target.is_relative_to(output_root):
            raise ValueError("mutation目标越界")
        if kind == "move":
            destination = _safe_relative(operation.get("to", ""))
            moved = output_root.joinpath(*destination.parts).resolve()
            if not moved.is_relative_to(output_root) or moved.exists():
                raise ValueError("mutation移动目标无效")
            moved.parent.mkdir(parents=True, exist_ok=True)
            target.replace(moved)
            continue
        content = target.read_text(encoding="utf-8")
        if kind == "rename_identifier":
            changed = _replace_identifier(content, operation.get("from"), operation.get("to"))
        elif kind == "replace_api":
            old, new = operation.get("from"), operation.get("to")
            if not isinstance(old, str) or not old or not isinstance(new, str) or old not in content:
                raise ValueError("replace_api必须指定存在的from和非空to")
            changed = content.replace(old, new)
        elif kind == "wrap_text":
            needle = operation.get("text")
            if not isinstance(needle, str) or not needle or content.count(needle) != 1:
                raise ValueError("wrap_text.text必须在目标文件中唯一存在")
            changed = content.replace(
                needle, str(operation.get("before", "")) + needle + str(operation.get("after", "")))
        elif kind == "replace_config_format":
            destination = _safe_relative(operation.get("to", ""))
            moved = output_root.joinpath(*destination.parts).resolve()
            if not moved.is_relative_to(output_root) or moved.exists():
                raise ValueError("配置格式替换目标无效")
            replacement = operation.get("content")
            if not isinstance(replacement, str) or not replacement.strip():
                raise ValueError("配置格式替换正文不能为空")
            moved.parent.mkdir(parents=True, exist_ok=True)
            moved.write_text(replacement, encoding="utf-8")
            target.unlink()
            continue
        else:
            raise ValueError(f"未知mutation操作: {kind}")
        if changed == content:
            raise ValueError(f"mutation没有改变文件: {relative}")
        target.write_text(changed, encoding="utf-8")
    return output_root


def apply_suite(source_root, output_root, suite):
    """Build every independent mutation variant without composing their effects."""
    output_root = Path(output_root).resolve()
    if output_root.exists():
        raise ValueError("mutation suite输出目录已存在")
    output_root.mkdir(parents=True)
    variants = []
    for variant in suite.get("variants", []):
        name = variant.get("name", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name):
            raise ValueError("mutation variant名称不合法")
        destination = output_root / name
        apply_manifest(source_root, destination, {"operations": variant.get("operations", [])})
        variants.append(destination)
    if not variants:
        raise ValueError("mutation suite不能为空")
    return variants


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("output")
    parser.add_argument("manifest")
    parser.add_argument("--suite", action="store_true")
    args = parser.parse_args()
    manifest_path = Path(args.manifest).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if args.suite:
        variants = apply_suite(args.source, args.output, manifest)
        print(json.dumps({"output": str(Path(args.output).resolve()),
                          "variants": [path.name for path in variants]}))
    else:
        result = apply_manifest(args.source, args.output, manifest)
        print(json.dumps({"output": str(result), "operations": len(manifest.get("operations", []))}))


if __name__ == "__main__":
    main()
