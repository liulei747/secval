from secval.code_processing.code_splitting.java import split_java_declarations
from secval.code_processing.source_parsing.java import (
    extract_java_symbols,
    parse_java,
)
from secval.models.code import SourceFile
from secval.models.identifiers import FileId, RepositoryId, SnapshotId

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
    assert symbols_by_name["demo.Service"].parent_symbol_id == file_symbol.symbol_id
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


def test_java_chunks_carry_static_call_references() -> None:
    source = '''
package demo;

class Caller {
    private Service service;

    void submit() {
        new Service().run();
        log.warn("order rejected");
    }
}

class Service {
    void run() {}
}
'''
    source_file = _create_source_file(source)
    chunks = split_java_declarations(source_file, parse_java(source_file))

    submit = next(chunk for chunk in chunks if chunk.symbol_name == "demo.Caller.submit()")
    assert "run" in submit.called_symbol_names
    assert "warn" in submit.called_symbol_names
    run_call = next(call for call in submit.code_calls if call.name == "run")
    assert run_call.receiver_type == "Service"
    assert run_call.argument_count == 0
    run_chunk = next(chunk for chunk in chunks if chunk.symbol_name == "demo.Service.run()")
    assert run_chunk.called_symbol_names == []


def test_java_overloaded_methods_keep_calls_on_the_right_chunk() -> None:
    source = '''
package demo;
class Service {
    void run() { noArgs(); }
    void run(String id) { withId(); }
    void noArgs() {}
    void withId() {}
}
'''
    source_file = _create_source_file(source)
    chunks = split_java_declarations(source_file, parse_java(source_file))

    no_args = next(chunk for chunk in chunks if chunk.symbol_name == "demo.Service.run()")
    with_id = next(chunk for chunk in chunks if chunk.symbol_name == "demo.Service.run(String)")
    assert no_args.called_symbol_names == ["noArgs"]
    assert with_id.called_symbol_names == ["withId"]
    assert no_args.code_calls[0].receiver_type == "Service"
    assert no_args.code_calls[0].argument_count == 0


def test_java_variable_receivers_use_field_parameter_and_local_types() -> None:
    source = '''
package demo;
class WrongService { void run() {} }
class RightService { void run() {} }
class Controller {
    private WrongService service;

    void fieldCall() { service.run(); }
    void parameterCall(RightService service) { service.run(); }
    void localCall() {
        RightService service = new RightService();
        service.run();
    }
    void unknownVar() {
        var service = new RightService();
        service.run();
    }
}
'''
    source_file = _create_source_file(source)
    chunks = split_java_declarations(source_file, parse_java(source_file))
    chunks_by_name = {chunk.symbol_name: chunk for chunk in chunks}

    assert chunks_by_name["demo.Controller.fieldCall()"].code_calls[0].receiver_type == (
        "WrongService"
    )
    assert chunks_by_name[
        "demo.Controller.parameterCall(RightService)"
    ].code_calls[0].receiver_type == "RightService"
    local_calls = chunks_by_name["demo.Controller.localCall()"].code_calls
    assert next(call for call in local_calls if call.name == "run").receiver_type == (
        "RightService"
    )
    # var + new 现在能直接从 object_creation_expression 读出类型；
    # 真正保持未知的是没有任何声明信息的变量。
    var_calls = chunks_by_name["demo.Controller.unknownVar()"].code_calls
    assert next(call for call in var_calls if call.name == "run").receiver_type == (
        "RightService"
    )


def test_var_new_and_lambda_captured_variable_infer_receiver_type() -> None:
    source = '''
package demo;
class Service { void handle(int v) {} }
class Main {
    void viaVar(int v) { var s = new Service(); s.handle(v); }
    void inLambda(int v) {
        Service s = new Service();
        Runnable task = () -> s.handle(v);
        task.run();
    }
}
'''
    source_file = _create_source_file(source)
    chunks = split_java_declarations(source_file, parse_java(source_file))
    chunks_by_name = {chunk.symbol_name: chunk for chunk in chunks}

    var_calls = chunks_by_name["demo.Main.viaVar(int)"].code_calls
    assert next(call for call in var_calls if call.name == "handle").receiver_type == (
        "Service"
    )
    lambda_calls = chunks_by_name["demo.Main.inLambda(int)"].code_calls
    assert next(call for call in lambda_calls if call.name == "handle").receiver_type == (
        "Service"
    )
    assert next(call for call in lambda_calls if call.name == "run").receiver_type == (
        "Runnable"
    )


def test_generic_overloads_do_not_share_type_variable_bounds() -> None:
    source_file = _create_source_file('''
package demo;
interface First { void process(); }
interface Second { void process(); }
class Main {
    <T extends First> T pick(String value) { return null; }
    <T extends Second> T pick(int value) { return null; }
    void use() {
        var value = pick("x");
        value.process();
    }
}
''')
    chunks = split_java_declarations(source_file, parse_java(source_file))
    use_chunk = next(chunk for chunk in chunks if chunk.symbol_name == "demo.Main.use()")
    # 当前解析器只按参数个数匹配，不能把最后一个重载的上界当作确定类型。
    call = next(call for call in use_chunk.code_calls if call.name == "process")
    assert call.receiver_type is None


def test_enhanced_for_var_reads_parameter_and_scoped_local_types() -> None:
    source_file = _create_source_file('''
package demo;
class First { void run() {} }
class Second { void run() {} }
class Main {
    void list(java.util.List<First> items) { for (var item : items) item.run(); }
    void array(First[] items) { for (var item : items) item.run(); }
    void nested(First[][] items) { for (var item : items) item.clone(); }
    void local() {
        { java.util.List<Second> items = null; }
        java.util.List<First> items = null;
        for (var item : items) item.run();
    }
}
''')
    chunks = split_java_declarations(source_file, parse_java(source_file))
    methods = {chunk.symbol_name: chunk for chunk in chunks}
    for name in ["demo.Main.list(java.util.List<First>)", "demo.Main.array(First[])",
                 "demo.Main.local()"]:
        assert methods[name].code_calls[0].receiver_type == "First"
    assert methods["demo.Main.nested(First[][])"].code_calls[0].receiver_type is None


def test_enhanced_for_field_and_loop_shadowing() -> None:
    source_file = _create_source_file('''
package demo;
class First { void run() {} }
class Second { void run() {} }
class Main {
    java.util.List<First> items;
    void field() { for (var item : items) item.run(); }
    void loops(java.util.List<java.util.List<Second>> groups) {
        for (java.util.List<Second> items : groups) {
            for (var item : items) item.run();
        }
        for (var item : items) item.run();
    }
}
''')
    chunks = split_java_declarations(source_file, parse_java(source_file))
    methods = {chunk.symbol_name: chunk for chunk in chunks}
    assert methods["demo.Main.field()"].code_calls[0].receiver_type == "First"
    calls = methods["demo.Main.loops(java.util.List<java.util.List<Second>>)"].code_calls
    assert [call.receiver_type for call in calls] == ["Second", "First"]


def test_var_self_reference_does_not_recurse_forever() -> None:
    source_file = _create_source_file('''
class Main {
    void incomplete() {
        var value = value.load();
        value.run();
    }
}
''')
    # 审计对象可能是尚未通过编译的代码，解析器仍应返回线索而不是崩溃。
    chunks = split_java_declarations(source_file, parse_java(source_file))
    method = next(chunk for chunk in chunks if chunk.symbol_name == "Main.incomplete()")
    assert [call.receiver_type for call in method.code_calls] == [None, None]


def test_enhanced_for_explicit_import_and_type_shadowing() -> None:
    for declaration, expected in [("class Main", "Item"), ("class Main<List>", None)]:
        source_file = _create_source_file(
            "import java.util.List;\nclass Item { void run() {} }\n"
            + declaration
            + " { void use(List<Item> items) { for (var item : items) item.run(); } }"
        )
        chunks = split_java_declarations(source_file, parse_java(source_file))
        method = next(chunk for chunk in chunks if chunk.symbol_name == "Main.use(List<Item>)")
        assert method.code_calls[0].receiver_type == expected


def test_enhanced_for_wildcards_and_array_elements() -> None:
    cases = [("Item[]", None), ("? extends Item", "Item"), ("? super Item", None),
             ("?", None), ("java.util.List<Item>", "List")]
    for element, expected in cases:
        source_file = _create_source_file(
            "class Item {} class Main { void use(java.util.List<" + element
            + "> items) { for (var item : items) item.toString(); } }"
        )
        chunks = split_java_declarations(source_file, parse_java(source_file))
        method = next(chunk for chunk in chunks if chunk.chunk_type == "method")
        assert method.code_calls[0].receiver_type == expected


def test_enhanced_for_reads_dimensions_after_parameter_name() -> None:
    source_file = _create_source_file('''
class Item {}
class Main {
    void single(Item items[]) { for (var item : items) item.toString(); }
    void matrix(Item[] items[]) { for (var item : items) item.toString(); }
}
''')
    chunks = split_java_declarations(source_file, parse_java(source_file))
    methods = {chunk.symbol_name: chunk for chunk in chunks}
    assert methods["Main.single(Item[])"].code_calls[0].receiver_type == "Item"
    assert methods["Main.matrix(Item[][])"].code_calls[0].receiver_type is None


def test_enhanced_for_directly_iterable_container() -> None:
    source_file = _create_source_file('''
import java.util.Iterator;
class Item { void run() {} }
class Inventory implements Iterable<Item>, AutoCloseable {
    public Iterator<Item> iterator() { return null; }
}
class Main { void use(Inventory items) { for (var item : items) item.run(); } }
''')
    chunks = split_java_declarations(source_file, parse_java(source_file))
    use = next(chunk for chunk in chunks if chunk.symbol_name == "Main.use(Inventory)")
    assert use.code_calls[0].receiver_type == "Item"
    source_file = _create_source_file('''
import java.util.Iterator;
class Item { void run() {} }
class Wrapper<T> implements Iterable<T> { public Iterator<T> iterator() { return null; } }
class Main { void use(Wrapper<Item> items) { for (var item : items) item.run(); } }
''')
    chunks = split_java_declarations(source_file, parse_java(source_file))
    use = next(chunk for chunk in chunks if chunk.symbol_name == "Main.use(Wrapper<Item>)")
    # 泛型转发容器不推断，避免把类型变量的方法误连到实际元素。
    assert use.code_calls[0].receiver_type is None


def test_enhanced_for_inheritance_chain_iterable() -> None:
    source_file = _create_source_file('''
import java.util.Iterator;
class Animal { void feed() {} }
class Kennel implements Iterable<Animal> { public Iterator<Animal> iterator() { return null; } }
class Shelter extends Kennel {}
class Main { void use(Shelter shelter) { for (var animal : shelter) animal.feed(); } }
'''
    )
    chunks = split_java_declarations(source_file, parse_java(source_file))
    use = next(chunk for chunk in chunks if chunk.symbol_name == "Main.use(Shelter)")
    assert use.code_calls[0].receiver_type == "Animal"
    source_file = _create_source_file('''
import java.util.Iterator;
class Item { void run() {} }
class Box<T> implements Iterable<T> { public Iterator<T> iterator() { return null; } }
class ItemBox extends Box<Item> {}
class Main { void use(ItemBox box) { for (var item : box) item.run(); } }
'''
    )
    chunks = split_java_declarations(source_file, parse_java(source_file))
    use = next(chunk for chunk in chunks if chunk.symbol_name == "Main.use(ItemBox)")
    # 父类用类型变量实现 Iterable，需要类型实参替换才能确定元素，这里不猜。
    assert use.code_calls[0].receiver_type is None


def test_generic_method_bound_infers_receiver_type() -> None:
    source = '''
package demo;
interface Processor { void process(); }
class Main {
    <T extends Processor> T pick() { return null; }
    void viaGeneric() {
        var p = pick();
        p.process();
    }
}
'''
    source_file = _create_source_file(source)
    chunks = split_java_declarations(source_file, parse_java(source_file))
    chunks_by_name = {chunk.symbol_name: chunk for chunk in chunks}

    generic_calls = chunks_by_name["demo.Main.viaGeneric()"].code_calls
    assert next(call for call in generic_calls if call.name == "process").receiver_type == (
        "Processor"
    )


def test_var_cast_lambda_and_method_reference_infer_receiver_type() -> None:
    source = '''
package demo;
interface Runner { void run(); }
class Main {
    static void run() {}
    void lambdaCall() {
        var runner = (Runner)() -> run();
        runner.run();
    }
    void methodReferenceCall() {
        var runner = (Runner) Main::run;
        runner.run();
    }
    void stringCastCall() {
        var text = (String) "x";
        text.length();
    }
}
'''
    source_file = _create_source_file(source)
    chunks = split_java_declarations(source_file, parse_java(source_file))
    chunks_by_name = {chunk.symbol_name: chunk for chunk in chunks}

    lambda_calls = chunks_by_name["demo.Main.lambdaCall()"].code_calls
    # 同名调用必须逐个核对：lambda 体内 run() 属于 Main，runner.run() 属于接口。
    assert [call.receiver_type for call in lambda_calls if call.name == "run"] == [
        "Main", "Runner",
    ]
    reference_calls = chunks_by_name["demo.Main.methodReferenceCall()"].code_calls
    assert next(call for call in reference_calls if call.name == "run").receiver_type == (
        "Runner"
    )
    string_calls = chunks_by_name["demo.Main.stringCastCall()"].code_calls
    assert next(call for call in string_calls if call.name == "length").receiver_type is None


def test_java_interface_extends_is_not_dropped() -> None:
    source = '''
package demo;
interface Parent {}
interface Child extends Parent {}
class Impl implements Child {}
'''
    source_file = _create_source_file(source)
    chunks = split_java_declarations(source_file, parse_java(source_file))
    child = next(chunk for chunk in chunks if chunk.symbol_name == "demo.Child")
    impl = next(chunk for chunk in chunks if chunk.symbol_name == "demo.Impl")
    assert child.extends_types == ["Parent"]
    assert child.implements_types == []
    assert impl.extends_types == []
    assert impl.implements_types == ["Child"]


def test_java_loop_resource_and_catch_types_do_not_escape_their_scope() -> None:
    source = '''
package demo;
class Controller {
    WrongService service;
    WrongResource resource;
    WrongProblem error;

    void check(Iterable<RightService> services) {
        for (RightService service : services) {
            service.run();
        }
        service.run();
        try (RightResource resource = open()) {
            resource.use();
        } catch (RightProblem error) {
            error.report();
        }
        resource.use();
        error.report();
    }
    RightResource open() { return null; }
}
'''
    source_file = _create_source_file(source)
    chunks = split_java_declarations(source_file, parse_java(source_file))
    check = next(chunk for chunk in chunks if chunk.symbol_name == "demo.Controller.check(Iterable<RightService>)")

    run_types = [call.receiver_type for call in check.code_calls if call.name == "run"]
    use_types = [call.receiver_type for call in check.code_calls if call.name == "use"]
    report_types = [call.receiver_type for call in check.code_calls if call.name == "report"]
    assert run_types == ["RightService", "WrongService"]
    assert use_types == ["RightResource", "WrongResource"]
    assert report_types == ["RightProblem", "WrongProblem"]


def test_java_method_return_chain_uses_declared_receiver_and_argument_count() -> None:
    source = '''
package demo;
class RightService { void run() {} }
class WrongService { void run() {} }
class Factory {
    RightService service() { return new RightService(); }
    WrongService service(String name) { return new WrongService(); }
}
class Controller {
    Factory factory;
    void submit() { factory.service().run(); }
}
'''
    source_file = _create_source_file(source)
    chunks = split_java_declarations(source_file, parse_java(source_file))
    submit = next(chunk for chunk in chunks if chunk.symbol_name == "demo.Controller.submit()")

    service_call = next(call for call in submit.code_calls if call.name == "service")
    run_call = next(call for call in submit.code_calls if call.name == "run")
    assert service_call.receiver_type == "Factory"
    assert service_call.argument_count == 0
    assert run_call.receiver_type == "RightService"


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
