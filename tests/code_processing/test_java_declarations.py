from secval.code_processing.code_splitting.java import split_java_declarations
from secval.code_processing.source_parsing.java import (
    extract_java_symbols,
    parse_java,
)
from secval.models.code import SourceFile
from secval.shared_types import FileId, RepositoryId, SnapshotId

JAVA_SOURCE = """package demo;

import java.util.List;

@Deprecated
@interface Audit {
    String value() default "x";
    int LEVEL = 1;
}

interface Worker {
    int LIMIT = 3;
    void work(String id);
    default void stop() {}
    static void help() {}
}

enum Status {
    READY(1) { @Override public String toString() { return "ready"; } },
    STOPPED(2);
    private final int code;
    Status(int code) { this.code = code; }
    static { System.out.println("loaded"); }
}

record User(String name, int age) {
    User { if (age < 0) throw new IllegalArgumentException(); }
}

@Audit
class Service {
    static final String PREFIX = "x";
    private int count, total = 1;
    static { System.loadLibrary("x"); }
    { count++; }
    Service() {}

    /** Finds one user. */
    <T> T findUser(List<T> values, String... tags) {
        return values.get(0);
    }

    void arrays(String values[], int... numbers) {}

    Runnable task = new Runnable() {
        @Override public void run() {}
    };

    class Inner { int value; }
}
"""


def _create_source_file(content: str = JAVA_SOURCE) -> SourceFile:
    return SourceFile(
        file_id=FileId("file-1"),
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
        relative_path="src/Declarations.java",
        language="java",
        content=content,
    )


def test_extract_all_searchable_java_symbols() -> None:
    source_file = _create_source_file()
    symbols = extract_java_symbols(source_file, parse_java(source_file))
    symbol_keys = {(symbol.symbol_type, symbol.full_name) for symbol in symbols}

    expected_keys = {
        ("file", "src/Declarations.java"),
        ("annotation", "demo.Audit"),
        ("annotation_element", "demo.Audit.value()"),
        ("field", "demo.Audit.LEVEL"),
        ("interface", "demo.Worker"),
        ("field", "demo.Worker.LIMIT"),
        ("method", "demo.Worker.work(String)"),
        ("method", "demo.Worker.stop()"),
        ("method", "demo.Worker.help()"),
        ("enum", "demo.Status"),
        ("enum_constant", "demo.Status.READY"),
        ("enum_constant", "demo.Status.STOPPED"),
        ("method", "demo.Status.READY.toString()"),
        ("field", "demo.Status.code"),
        ("constructor", "demo.Status.Status(int)"),
        ("record", "demo.User"),
        ("record_component", "demo.User.name"),
        ("record_component", "demo.User.age"),
        ("constructor", "demo.User.User(String,int)"),
        ("class", "demo.Service"),
        ("field", "demo.Service.PREFIX"),
        ("field", "demo.Service.count"),
        ("field", "demo.Service.total"),
        ("constructor", "demo.Service.Service()"),
        ("method", "demo.Service.findUser(List<T>,String...)"),
        ("method", "demo.Service.arrays(String[],int...)"),
        ("field", "demo.Service.task"),
        ("class", "demo.Service.Inner"),
        ("field", "demo.Service.Inner.value"),
    }
    assert expected_keys <= symbol_keys
    assert len(symbol_keys) == len(symbols)
    assert len({symbol.symbol_id for symbol in symbols}) == len(symbols)

    anonymous_symbol = next(
        symbol for symbol in symbols if symbol.symbol_type == "anonymous_class"
    )
    assert anonymous_symbol.full_name.startswith(
        "demo.Service.task.<anonymous>@"
    )
    assert any(
        symbol.symbol_type == "method"
        and symbol.full_name == f"{anonymous_symbol.full_name}.run()"
        for symbol in symbols
    )
    assert ("method", "demo.Service.run()") not in symbol_keys

    symbols_by_name = {symbol.full_name: symbol for symbol in symbols}
    file_symbol = symbols_by_name["src/Declarations.java"]
    assert file_symbol.parent_symbol_id is None
    assert symbols_by_name["demo.Service"].parent_symbol_id == (
        file_symbol.symbol_id
    )
    assert symbols_by_name["demo.Worker.work(String)"].parent_symbol_id == (
        symbols_by_name["demo.Worker"].symbol_id
    )
    assert symbols_by_name["demo.User.age"].parent_symbol_id == (
        symbols_by_name["demo.User"].symbol_id
    )
    assert symbols_by_name[f"{anonymous_symbol.full_name}.run()"].parent_symbol_id == (
        anonymous_symbol.symbol_id
    )

    initializer_types = [
        symbol.symbol_type
        for symbol in symbols
        if symbol.full_name.startswith("demo.Service.<")
    ]
    assert initializer_types == ["static_initializer", "initializer"]
    assert any(
        symbol.symbol_type == "static_initializer"
        and symbol.full_name.startswith("demo.Status.<clinit>@")
        for symbol in symbols
    )


def test_split_java_declarations_without_large_duplicate_class_chunks() -> None:
    source_file = _create_source_file()
    chunks = split_java_declarations(source_file, parse_java(source_file))
    chunk_types = {chunk.chunk_type for chunk in chunks}

    assert {
        "file",
        "class",
        "interface",
        "enum",
        "annotation",
        "record",
        "method",
        "constructor",
        "field",
        "static_initializer",
        "initializer",
        "enum_constant",
        "annotation_element",
        "record_component",
        "anonymous_class",
    } <= chunk_types

    file_chunk = next(chunk for chunk in chunks if chunk.chunk_type == "file")
    assert "package demo;" in file_chunk.content
    assert "import java.util.List;" in file_chunk.content
    assert "class Service" not in file_chunk.content

    class_chunk = next(
        chunk
        for chunk in chunks
        if chunk.symbol_name == "demo.Service"
    )
    assert "@Audit" in class_chunk.content
    assert "class Service" in class_chunk.content
    assert "findUser" not in class_chunk.content

    method_chunk = next(
        chunk
        for chunk in chunks
        if chunk.symbol_name == "demo.Service.findUser(List<T>,String...)"
    )
    assert "/** Finds one user. */" in method_chunk.content
    assert "return values.get(0);" in method_chunk.content

    combined_field_chunk = next(
        chunk
        for chunk in chunks
        if chunk.chunk_type == "field" and "count" in chunk.content
    )
    assert combined_field_chunk.symbol_id is None
    assert combined_field_chunk.symbol_name == (
        "demo.Service.count, demo.Service.total"
    )
    assert len(combined_field_chunk.symbol_ids) == 2
    assert combined_field_chunk.symbol_names == [
        "demo.Service.count",
        "demo.Service.total",
    ]


def test_extract_module_declaration() -> None:
    source_file = _create_source_file(
        "module demo.app { requires java.base; exports demo.api; }"
    )
    symbols = extract_java_symbols(source_file, parse_java(source_file))
    chunks = split_java_declarations(source_file, parse_java(source_file))

    assert ("module", "demo.app") in {
        (symbol.symbol_type, symbol.full_name) for symbol in symbols
    }
    assert any(chunk.chunk_type == "module" for chunk in chunks)
    file_chunk = next(chunk for chunk in chunks if chunk.chunk_type == "file")
    module_chunk = next(
        chunk for chunk in chunks if chunk.chunk_type == "module"
    )
    assert file_chunk.content == "module demo.app"
    assert "requires java.base" in module_chunk.content


def test_annotated_package_name_is_not_confused_with_annotation() -> None:
    source_file = _create_source_file(
        "@Deprecated package demo.annotated;\n"
        "class PackageType { void run() {} }"
    )
    symbols = extract_java_symbols(source_file, parse_java(source_file))

    assert ("class", "demo.annotated.PackageType") in {
        (symbol.symbol_type, symbol.full_name) for symbol in symbols
    }


def test_same_line_declarations_have_unique_symbol_and_chunk_ids() -> None:
    source_file = _create_source_file(
        "class A { class X { int v; void run(){} } "
        "class Y { int v; void run(){} } "
        "void local(){ {class L{}} {class L{}} } "
        "static {} static {} }"
    )
    syntax_tree = parse_java(source_file)
    symbols = extract_java_symbols(source_file, syntax_tree)
    chunks = split_java_declarations(source_file, syntax_tree)

    assert len({symbol.symbol_id for symbol in symbols}) == len(symbols)
    assert len({chunk.chunk_id for chunk in chunks}) == len(chunks)
    local_names = [
        symbol.full_name
        for symbol in symbols
        if symbol.symbol_type == "class"
        and symbol.full_name.startswith("A.local().L@")
    ]
    assert len(local_names) == 2
    assert len(set(local_names)) == 2


def test_anonymous_class_arguments_keep_their_lexical_owner() -> None:
    source_file = _create_source_file(
        "class C { void f() { Object value = "
        "new Outer(new Inner(){ void inner(){} })"
        "{ void outer(){} }; } }"
    )
    symbols = extract_java_symbols(source_file, parse_java(source_file))
    symbols_by_id = {symbol.symbol_id: symbol for symbol in symbols}
    method_symbol = next(
        symbol for symbol in symbols if symbol.full_name == "C.f()"
    )
    inner_method = next(symbol for symbol in symbols if symbol.name == "inner")
    outer_method = next(symbol for symbol in symbols if symbol.name == "outer")
    inner_anonymous = symbols_by_id[inner_method.parent_symbol_id]
    outer_anonymous = symbols_by_id[outer_method.parent_symbol_id]

    assert inner_anonymous.symbol_type == "anonymous_class"
    assert outer_anonymous.symbol_type == "anonymous_class"
    assert inner_anonymous.parent_symbol_id == method_symbol.symbol_id
    assert outer_anonymous.parent_symbol_id == method_symbol.symbol_id


def test_deep_expression_does_not_use_python_recursion() -> None:
    depth = 1_200
    source_file = _create_source_file(
        "class Deep { int value() { return "
        + "(" * depth
        + "1"
        + ")" * depth
        + "; } }"
    )

    symbols = extract_java_symbols(source_file, parse_java(source_file))

    assert any(symbol.full_name == "Deep.value()" for symbol in symbols)


def test_large_array_initializers_can_be_split() -> None:
    """大型 Java 数组语法树不能让 Tree-sitter 原生绑定崩溃。"""

    rows = ",".join(
        "{" + ",".join(str(number) for number in range(32)) + "}"
        for _ in range(8)
    )
    methods = "\n".join(
        f"int[][] table{method_number}() {{ return new int[][] {{{rows}}}; }}"
        for method_number in range(30)
    )
    source_file = _create_source_file(f"class LargeTables {{ {methods} }}")

    chunks = split_java_declarations(source_file, parse_java(source_file))

    method_chunks = [chunk for chunk in chunks if chunk.chunk_type == "method"]
    assert len(method_chunks) == 30


def test_default_package_file_still_has_a_file_chunk() -> None:
    source_file = _create_source_file("class A {}")
    chunks = split_java_declarations(source_file, parse_java(source_file))

    assert [chunk.chunk_type for chunk in chunks] == ["file", "class"]
    assert chunks[0].content == "class A"


def test_unattached_tail_comment_remains_searchable_as_file_content() -> None:
    source_file = _create_source_file(
        "class A {}\n\n/* deployment-tail-marker */"
    )
    chunks = split_java_declarations(source_file, parse_java(source_file))
    file_contents = [
        chunk.content for chunk in chunks if chunk.chunk_type == "file"
    ]

    assert "/* deployment-tail-marker */" in file_contents


def test_multiline_parameter_types_have_stable_canonical_names() -> None:
    source_file = _create_source_file(
        "class Types { void read(Map<\n String, /* key */\n Integer\n> value) {} }"
    )
    symbols = extract_java_symbols(source_file, parse_java(source_file))

    assert any(
        symbol.full_name == "Types.read(Map<String,Integer>)"
        for symbol in symbols
    )


def test_type_annotation_strings_are_not_mistaken_for_comments() -> None:
    source_file = _create_source_file(
        "@interface A { String value(); } "
        "@interface B {} "
        "@interface C { String value(); } "
        "class AnnotatedTypes { void read("
        'java.util.@A("//") List<@B String> first, '
        'String @C("/*x*/") [] second) {} }'
    )
    symbols = extract_java_symbols(source_file, parse_java(source_file))

    assert any(
        symbol.full_name
        == (
            'AnnotatedTypes.read(java.util.@A("//") '
            'List<@B String>,String @C("/*x*/")[])'
        )
        for symbol in symbols
    )


def test_multiline_fields_keep_each_declarator_location() -> None:
    source_file = _create_source_file("class Fields {\n int\n first,\n second;\n}")
    symbols = extract_java_symbols(source_file, parse_java(source_file))
    fields = {
        symbol.name: symbol
        for symbol in symbols
        if symbol.symbol_type == "field"
    }

    assert fields["first"].start_line == 3
    assert fields["second"].start_line == 4
