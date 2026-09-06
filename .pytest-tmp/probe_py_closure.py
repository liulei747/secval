import sys

sys.stdout.reconfigure(encoding="utf-8")

from secval.models.code import SourceFile
from secval.models.identifiers import FileId, RepositoryId, SnapshotId
from secval.code_processing.source_parsing.python import parse_python
from secval.code_processing.code_splitting.python import split_python_declarations

source = '''class Item:
    def run(self):
        pass

def setup(items: list[Item]):
    def handler():
        for item in items:
            item.run()
    return handler
'''
sf = SourceFile(file_id=FileId("f"), repository_id=RepositoryId("r"),
    snapshot_id=SnapshotId("s"), relative_path="main.py", language="python",
    content=source)
chunks = split_python_declarations(sf, parse_python(sf))
for chunk in chunks:
    print("chunk:", chunk.chunk_type, chunk.symbol_name)
    for call in chunk.code_calls:
        print("  ", call.name, "| receiver:", call.receiver_type)
from secval.code_processing.code_splitting.python.split_python_declarations import (
    _python_for_variable_type, _declared_python_variable_type,
)
tree = parse_python(sf)
code = sf.content.encode()
handler = next(n for n in tree.root_node.named_children if False) if False else None
def find_fn(node, name):
    if node.type == "function_definition":
        nm = node.child_by_field_name("name")
        if nm is not None and code[nm.start_byte:nm.end_byte].decode() == name:
            return node
    for c in node.named_children:
        r = find_fn(c, name)
        if r is not None:
            return r
    return None
handler_fn = find_fn(tree.root_node, "handler")
print("for var type:", _python_for_variable_type("item", handler_fn, code))
print("declared items in setup:", _declared_python_variable_type(
    "items", find_fn(tree.root_node, "setup"), code))
for_node = None
def find_for(node):
    global for_node
    if node.type == "for_statement":
        for_node = node
    for c in node.named_children:
        find_for(c)
find_for(handler_fn)
left = for_node.child_by_field_name("left")
print("left:", left.type, code[left.start_byte:left.end_byte].decode())
