"""Python 嵌套函数词法作用域：闭包内调用按外层注解推断接收者。"""

from pathlib import Path

from secval.code_processing.code_splitting.python import split_python_declarations
from secval.code_processing.repository_processing.process_repository import (
    process_repository,
)
from secval.code_processing.source_parsing.python import parse_python
from secval.models.code import SourceFile
from secval.models.identifiers import FileId, RepositoryId, SnapshotId


def _sf(source: str) -> SourceFile:
    return SourceFile(file_id=FileId("f"), repository_id=RepositoryId("r"),
        snapshot_id=SnapshotId("s"), relative_path="main.py", language="python",
        content=source)


def test_nested_function_uses_outer_parameter_annotation(tmp_path):
    source = '''class Item:
    def run(self):
        pass

def setup(items: list[Item]):
    def handler():
        for item in items:
            item.run()
    return handler
'''
    (tmp_path / "closure.py").write_text(source, encoding="utf-8")
    result = process_repository(
        str(tmp_path), RepositoryId("repo-py"), SnapshotId("snapshot-py")
    )
    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}
    handler = next(chunk for chunk in chunks.values()
                   if chunk.symbol_name and "handler" in chunk.symbol_name)
    run_call = next(call for call in handler.code_calls if call.name == "run")
    assert run_call.receiver_type == "Item"


def test_nested_function_receiver_inference_unit(tmp_path):
    source = '''class Item:
    def run(self):
        pass

def setup(items: list[Item]):
    def handler():
        for item in items:
            item.run()
    return handler
'''
    sf = _sf(source)
    chunks = split_python_declarations(sf, parse_python(sf))
    handler = next(chunk for chunk in chunks if chunk.symbol_name == "main.setup.handler")
    assert next(call for call in handler.code_calls if call.name == "run").receiver_type == "Item"
