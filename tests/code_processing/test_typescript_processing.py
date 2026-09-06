"""验证 TypeScript 和 TSX 的完整文件处理入口。"""

from pathlib import Path

from secval.code_processing.repository_processing import process_repository
from secval.models.identifiers import RepositoryId, SnapshotId


def test_bare_function_call_does_not_inherit_class_receiver(tmp_path):
    source = '''function helper() {}
class Service {
    helper() {}
    run() {
        helper();
        this.helper();
    }
}
'''
    for extension in ("ts", "js"):
        (tmp_path / f"sample.{extension}").write_text(source, encoding="utf-8")
    result = process_repository(
        str(tmp_path), RepositoryId("repo-bare"), SnapshotId("snapshot-bare")
    )
    methods = [chunk for chunk in result.chunks if chunk.symbol_name.endswith("Service.run")]
    assert len(methods) == 2
    for method in methods:
        calls = sorted(method.code_calls, key=lambda call: call.line)
        assert len(calls) == 2
        assert calls[0].receiver_type is None
        assert calls[1].receiver_type == "Service"


def test_typescript_repository_creates_types_functions_and_calls(tmp_path):
    source = '''interface Order {
    id: string;
}

type OrderId = string;

class OrderService {
    find(orderId: OrderId): Order {
        return loadOrder(orderId);
    }
}

export const handle = (service: OrderService, orderId: OrderId) => {
    return service.find(orderId);
};
'''
    (tmp_path / "orders.ts").write_text(source, encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repo-ts"), SnapshotId("snapshot-ts")
    )

    assert result.total_files == 1
    assert result.successful_files == 1
    assert result.errors == []
    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}
    assert "orders.Order" in chunks
    assert chunks["orders.Order"].chunk_type == "interface"
    assert "orders.OrderId" in chunks
    assert chunks["orders.OrderId"].chunk_type == "type_alias"
    assert "orders.OrderService.find" in chunks
    assert "orders.handle" in chunks
    assert chunks["orders.OrderService.find"].code_calls[0].name == "loadOrder"
    handle_call = chunks["orders.handle"].code_calls[0]
    assert handle_call.name == "find"
    assert handle_call.argument_count == 1
    assert handle_call.receiver_type == "OrderService"


def test_tsx_file_uses_tsx_parser(tmp_path):
    source = '''type Props = { title: string };

export const Header = (props: Props) => (
    <header onClick={() => trackClick(props.title)}>{props.title}</header>
);
'''
    (tmp_path / "Header.tsx").write_text(source, encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repo-tsx"), SnapshotId("snapshot-tsx")
    )

    assert result.successful_files == 1
    assert result.errors == []
    assert any(chunk.symbol_name == "Header.Props" for chunk in result.chunks)
    assert any(chunk.symbol_name == "Header.Header" for chunk in result.chunks)


def test_nestjs_demo_decorated_class_and_method_are_chunked():
    demo = Path(__file__).parents[1] / "demo_projects" / "orders_ts"

    result = process_repository(
        str(demo), RepositoryId("repo-ts"), SnapshotId("snapshot-ts")
    )

    assert result.successful_files == 1
    assert result.errors == []
    names = {chunk.symbol_name for chunk in result.chunks}
    assert "orders.controller.OrderController" in names
    assert "orders.controller.OrderController.getOrder" in names
    get_order = next(
        chunk for chunk in result.chunks
        if chunk.symbol_name == "orders.controller.OrderController.getOrder"
    )
    find_call = next(call for call in get_order.code_calls if call.name == "find")
    assert find_call.receiver_type == "OrderService"


def test_plain_constructor_parameter_is_not_a_typescript_property(tmp_path):
    source = '''class Service {
    run(): void {}
}

class Controller {
    constructor(service: Service) {}

    handle(): void {
        this.service.run();
    }
}
'''
    (tmp_path / "controller.ts").write_text(source, encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repo-ts"), SnapshotId("snapshot-ts")
    )

    handle = next(
        chunk for chunk in result.chunks
        if chunk.symbol_name == "controller.Controller.handle"
    )
    run_call = next(call for call in handle.code_calls if call.name == "run")
    assert run_call.receiver_type is None


def test_typescript_local_annotation_and_constructor_set_receiver_type(tmp_path):
    source = '''class Service {
    run(): void {}
}

function annotated(): void {
    const service: Service = makeService();
    service.run();
}

function constructed(): void {
    const service = new Service();
    service.run();
}
'''
    (tmp_path / "service.ts").write_text(source, encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repo-ts"), SnapshotId("snapshot-ts")
    )
    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}

    annotated_call = next(
        call for call in chunks["service.annotated"].code_calls
        if call.name == "run"
    )
    constructed_call = next(
        call for call in chunks["service.constructed"].code_calls
        if call.name == "run"
    )
    assert annotated_call.receiver_type == "Service"
    assert constructed_call.receiver_type == "Service"


def test_typescript_this_method_return_chain_infers_receiver(tmp_path):
    source = '''class Processor {
    process(): void {}
}
class Main {
    pick(): Processor { return new Processor(); }
    use(): void {
        const p = this.pick();
        p.process();
    }
}'''
    (tmp_path / "main.ts").write_text(source, encoding="utf-8")
    result = process_repository(
        str(tmp_path), RepositoryId("repo-ts2"), SnapshotId("snapshot-ts2")
    )
    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}
    use = next(chunk for chunk in chunks.values() if "use" in chunk.symbol_name)
    process_call = next(call for call in use.code_calls if call.name == "process")
    assert process_call.receiver_type == "Processor"


def test_typescript_array_subscript_infers_element_receiver(tmp_path):
    source = '''class Item {
    run(): void {}
}
function use(items: Item[]) {
    const first = items[0];
    first.run();
}'''
    (tmp_path / "array.ts").write_text(source, encoding="utf-8")
    result = process_repository(
        str(tmp_path), RepositoryId("repo-ts3"), SnapshotId("snapshot-ts3")
    )
    chunks = result.chunks
    use = next(chunk for chunk in chunks if chunk.symbol_name and "use" in chunk.symbol_name)
    run_call = next(call for call in use.code_calls if call.name == "run")
    assert run_call.receiver_type == "Item"
    # 数组对象自身的方法（push）不能记到元素类型上。
    push_calls = [call for call in use.code_calls if call.name == "push"]
    for push_call in push_calls:
        assert push_call.receiver_type != "Item"


def test_typescript_return_chain_filters_overloads_by_argument_count(tmp_path):
    source = '''class First {
    run(): void {}
}
class Second {
    run(): void {}
}
class Main {
    pick(v: string): First { return new First(); }
    pick(): Second { return new Second(); }
    useString(): void {
        const p = this.pick('x');
        p.run();
    }
    useZero(): void {
        const q = this.pick();
        q.run();
    }
}'''
    (tmp_path / "overload.ts").write_text(source, encoding="utf-8")
    result = process_repository(
        str(tmp_path), RepositoryId("repo-ts4"), SnapshotId("snapshot-ts4")
    )
    chunks = result.chunks
    use_string = next(chunk for chunk in chunks if "useString" in chunk.symbol_name)
    assert next(call for call in use_string.code_calls if call.name == "run").receiver_type == "First"
    use_zero = next(chunk for chunk in chunks if "useZero" in chunk.symbol_name)
    assert next(call for call in use_zero.code_calls if call.name == "run").receiver_type == "Second"


def test_typescript_closure_calls_are_collected_with_element_types(tmp_path):
    source = '''class Item {
    run(): void {}
}
export function setup(items: Item[]) {
    const handler = () => {
        const first = items[0];
        first.run();
    };
    return handler;
}'''
    (tmp_path / "closure.ts").write_text(source, encoding="utf-8")
    result = process_repository(
        str(tmp_path), RepositoryId("repo-ts5"), SnapshotId("snapshot-ts5")
    )
    chunks = result.chunks
    setup = next(chunk for chunk in chunks if "setup" in chunk.symbol_name)
    run_calls = [call for call in setup.code_calls if call.name == "run"]
    assert run_calls and run_calls[0].receiver_type == "Item"


def test_typescript_named_import_alias_resolves_full_receiver_type(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "service.ts").write_text(
        "export class OrderService { find(id: string): void {} }",
        encoding="utf-8",
    )
    (second / "service.ts").write_text(
        "export class OrderService { find(id: string): void {} }",
        encoding="utf-8",
    )
    (tmp_path / "controller.ts").write_text(
        '''import { OrderService as FirstService } from "./first/service";
import { OrderService as SecondService } from "./second/service";

export function first(service: FirstService): void {
    service.find("first");
}

export function second(service: SecondService): void {
    service.find("second");
}
''',
        encoding="utf-8",
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repo-ts"), SnapshotId("snapshot-ts")
    )
    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}

    first_call = chunks["controller.first"].code_calls[0]
    second_call = chunks["controller.second"].code_calls[0]
    assert first_call.receiver_type_full_name == "first.service.OrderService"
    assert second_call.receiver_type_full_name == "second.service.OrderService"


def test_typescript_keeps_extends_and_implements_in_the_right_direction(tmp_path):
    source = '''interface Root {}
interface Auditable {}
interface Child extends Root, Auditable {}
class Base {}
class Service extends Base implements Child, Auditable {}
type Conditional<T> = T extends Root ? true : false;
class Plain { text = "implements Child"; }
'''
    (tmp_path / "types.ts").write_text(source, encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repo-ts"), SnapshotId("snapshot-ts")
    )
    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}

    child = chunks["types.Child"]
    service = chunks["types.Service"]
    assert child.extends_types == ["Root", "Auditable"]
    assert child.implements_types == []
    assert service.extends_types == ["Base"]
    assert service.implements_types == ["Child", "Auditable"]
    assert chunks["types.Conditional"].extends_types == []
    assert chunks["types.Plain"].implements_types == []


def test_typescript_relations_resolve_import_alias_and_ancestor_chain(tmp_path):
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    (contracts / "base.ts").write_text(
        "export interface Root {}", encoding="utf-8"
    )
    (contracts / "child.ts").write_text(
        '''import { Root as Parent } from "./base";
export interface Child extends Parent {}
''',
        encoding="utf-8",
    )
    (tmp_path / "service.ts").write_text(
        '''import { Child } from "./contracts/child";
export class Service implements Child {
    check(value: string): boolean { return value.length > 0; }
}
''',
        encoding="utf-8",
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repo-ts"), SnapshotId("snapshot-ts")
    )
    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}

    child = chunks["contracts.child.Child"]
    service = chunks["service.Service"]
    assert child.extends_full_names == ["contracts.base.Root"]
    assert child.supertype_full_names == ["contracts.base.Root"]
    assert service.extends_full_names == []
    assert service.supertype_full_names == ["contracts.child.Child"]
    assert service.ancestor_type_full_names == [
        "contracts.base.Root", "contracts.child.Child"
    ]
    assert chunks["service.Service.check"].ancestor_type_full_names == [
        "contracts.base.Root", "contracts.child.Child"
    ]


def test_typescript_duplicate_unimported_interface_stays_unknown(tmp_path):
    (tmp_path / "first.ts").write_text(
        "export interface Contract {}", encoding="utf-8"
    )
    (tmp_path / "second.ts").write_text(
        "export interface Contract {}", encoding="utf-8"
    )
    (tmp_path / "service.ts").write_text(
        "export class Service implements Contract {}", encoding="utf-8"
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repo-ts"), SnapshotId("snapshot-ts")
    )
    service = next(
        chunk for chunk in result.chunks
        if chunk.symbol_name == "service.Service"
    )

    assert service.implements_types == ["Contract"]
    assert service.supertype_full_names == []
    assert service.ancestor_type_full_names == []


def test_typescript_interface_methods_are_saved_with_parameter_count(tmp_path):
    (tmp_path / "contract.ts").write_text(
        '''export interface Contract {
    find(id: string): string;
    save(id: string, value: string): void;
}
''',
        encoding="utf-8",
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repo-ts"), SnapshotId("snapshot-ts")
    )
    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}

    assert chunks["contract.Contract.find"].chunk_type == "method"
    assert chunks["contract.Contract.find"].parameter_count == 1
    assert chunks["contract.Contract.save"].parameter_count == 2


def test_typescript_optional_default_and_rest_parameters_are_separated(tmp_path):
    (tmp_path / "handler.ts").write_text(
        '''export function handle(
    required: string,
    optional?: string,
    fallback: string = "default",
    ...extra: string[]
): void {}
''',
        encoding="utf-8",
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repo-ts"), SnapshotId("snapshot-ts")
    )
    handle = next(
        chunk for chunk in result.chunks
        if chunk.symbol_name == "handler.handle"
    )

    assert handle.parameter_count == 3
    assert handle.required_parameter_count == 1
    assert handle.accepts_extra_arguments is True
