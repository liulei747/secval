import sys

sys.stdout.reconfigure(encoding="utf-8")

from secval.models.code import SourceFile
from secval.models.identifiers import FileId, RepositoryId, SnapshotId
from secval.code_processing.source_parsing.typescript import parse_typescript
from secval.code_processing.code_splitting.typescript import split_typescript_declarations

source = '''class Service {
    stop(): void {}
    setup() {
        const plain = () => { stop(); };
        stop();
        const legacy = function() { stop(); };
        return plain;
    }
}'''
sf = SourceFile(file_id=FileId("f"), repository_id=RepositoryId("r"),
    snapshot_id=SnapshotId("s"), relative_path="main.ts", language="typescript",
    content=source)
chunks = split_typescript_declarations(sf, parse_typescript(sf))
for chunk in chunks:
    print(chunk.chunk_type, chunk.symbol_name)
    for call in chunk.code_calls:
        print("  ", call.name, "| receiver:", call.receiver_type)
source2 = '''class Processor {
    process(): void {}
}
class Main {
    pick(): Processor { return new Processor(); }
    use(): void {
        const p = this.pick();
        p.process();
    }
}'''
chunks2 = split_typescript_declarations(
    SourceFile(file_id=FileId("f2"), repository_id=RepositoryId("r"),
        snapshot_id=SnapshotId("s"), relative_path="m2.ts", language="typescript",
        content=source2),
    None if False else __import__('secval.code_processing.source_parsing.typescript', fromlist=['parse_typescript']).parse_typescript(
        SourceFile(file_id=FileId("f2"), repository_id=RepositoryId("r"),
            snapshot_id=SnapshotId("s"), relative_path="m2.ts", language="typescript",
            content=source2)),
)
for chunk in chunks2:
    if chunk.symbol_name and "use" in chunk.symbol_name:
        for call in chunk.code_calls:
            print("case2:", call.name, "| receiver:", call.receiver_type)
