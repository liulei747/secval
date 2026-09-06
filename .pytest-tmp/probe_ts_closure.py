import sys

sys.stdout.reconfigure(encoding="utf-8")

from secval.models.code import SourceFile
from secval.models.identifiers import FileId, RepositoryId, SnapshotId
from secval.code_processing.source_parsing.typescript import parse_typescript
from secval.code_processing.code_splitting.typescript import split_typescript_declarations

source = '''class Item { run(): void {} }
export function setup(items: Item[]) {
  const handler = () => {
    const first = items[0];
    first.run();
  };
  return handler;
}'''
sf = SourceFile(file_id=FileId("f"), repository_id=RepositoryId("r"),
    snapshot_id=SnapshotId("s"), relative_path="main.ts", language="typescript",
    content=source)
chunks = split_typescript_declarations(sf, parse_typescript(sf))
for chunk in chunks:
    print("chunk:", chunk.chunk_type, chunk.symbol_name)
    for call in chunk.code_calls:
        print("  ", call.name, "| receiver:", call.receiver_type)
