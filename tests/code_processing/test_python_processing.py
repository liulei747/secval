"""Python 源码使用自己的解析器和切块器。"""

from secval.code_processing.repository_processing import process_repository
from secval.models.identifiers import RepositoryId, SnapshotId


def test_process_python_file_into_clear_declaration_chunks(tmp_path):
    source = '''"""订单服务。"""
from store import load_order

@service
class OrderService:
    @checked
    async def fetch(self, order_id):
        return load_order(order_id)

def health():
    return "ok"
'''
    (tmp_path / "orders.py").write_text(source, encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repo-python"), SnapshotId("snapshot-python")
    )

    assert result.errors == []
    assert result.successful_files == 1
    assert [(chunk.chunk_type, chunk.symbol_name) for chunk in result.chunks] == [
        ("file", None),
        ("class", "orders.OrderService"),
        ("function", "orders.OrderService.fetch"),
        ("function", "orders.health"),
    ]
    assert result.chunks[0].content.startswith('"""订单服务。"""')
    assert result.chunks[1].content.startswith("@service")
    assert "return load_order(order_id)" in result.chunks[2].content


def test_python_syntax_error_does_not_hide_other_file_result(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "good.py").write_text("def ready():\n    return True\n", encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repo-python"), SnapshotId("snapshot-python")
    )

    assert result.total_files == 2
    assert result.successful_files == 1
    assert len(result.errors) == 1
    assert result.errors[0].relative_path == "bad.py"
    assert [chunk.symbol_name for chunk in result.chunks] == ["good.ready"]


def test_python_chunks_carry_direct_and_attribute_call_names(tmp_path):
    source = '''class OrderService:
    def fetch(self):
        raise PermissionError("denied")

def handle_order(service):
    return service.fetch()

def build_order():
    return OrderService().fetch()
'''
    (tmp_path / "orders.py").write_text(source, encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repo-python"), SnapshotId("snapshot-python")
    )

    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}
    assert chunks["orders.OrderService"].called_symbol_names == []
    assert chunks["orders.OrderService.fetch"].called_symbol_names == ["PermissionError"]
    assert chunks["orders.handle_order"].called_symbol_names == ["fetch"]
    fetch_call = chunks["orders.handle_order"].code_calls[0]
    assert fetch_call.receiver_type is None
    assert fetch_call.argument_count == 0
    typed_fetch = next(call for call in chunks["orders.build_order"].code_calls
                       if call.name == "fetch")
    assert typed_fetch.receiver_type == "OrderService"


def test_python_self_attribute_and_typed_variable_receivers(tmp_path):
    source = '''from models import OrderService
class Controller:
    def __init__(self, service: OrderService):
        self.service = service

    def submit(self):
        self.service.fetch()

def handle(service: OrderService):
    local: OrderService = service
    local.fetch()
'''
    (tmp_path / "controller.py").write_text(source, encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repo-python"), SnapshotId("snapshot-python")
    )

    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}
    submit = chunks["controller.Controller.submit"]
    fetch_call = next(call for call in submit.code_calls if call.name == "fetch")
    assert fetch_call.receiver_type == "OrderService"
    handle = chunks["controller.handle"]
    local_fetch = next(call for call in handle.code_calls if call.name == "fetch")
    assert local_fetch.receiver_type == "OrderService"


def test_python_return_annotation_enables_chained_call_receiver(tmp_path):
    """工厂方法带返回注解时，链式调用的接收者应解析为注解类型。"""

    source = '''class Service:
    def fetch(self):
        return "data"

class Factory:
    def create(self) -> Service:
        return Service()

def build():
    return Factory().create().fetch()
'''
    (tmp_path / "factory.py").write_text(source, encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repo-python"), SnapshotId("snapshot-python")
    )

    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}
    build = chunks["factory.build"]
    fetch_calls = [call for call in build.code_calls if call.name == "fetch"]
    assert len(fetch_calls) == 1
    assert fetch_calls[0].receiver_type == "Service"
    # 内层create调用也应记录。
    create_calls = [call for call in build.code_calls if call.name == "create"]
    assert len(create_calls) == 1


def test_python_return_annotation_follows_simple_assigned_variable(tmp_path):
    """工厂返回值先保存到变量时，后续调用仍应得到明确接收者类型。"""

    source = '''class Service:
    def fetch(self):
        return "data"

class Factory:
    def create(self) -> Service:
        return Service()

def build():
    service = Factory().create()
    return service.fetch()
'''
    (tmp_path / "factory.py").write_text(source, encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repo-python"), SnapshotId("snapshot-python")
    )

    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}
    build = chunks["factory.build"]
    fetch_call = next(call for call in build.code_calls if call.name == "fetch")
    assert fetch_call.receiver_type == "Service"


def test_python_branch_reassignment_keeps_receiver_unknown(tmp_path):
    """变量可能在分支中改成其他值时，不应猜测后续调用的接收者类型。"""

    source = '''class Service:
    def fetch(self):
        return "data"

class Factory:
    def create(self) -> Service:
        return Service()

def build(change, other):
    service = Factory().create()
    if change:
        service = other
    return service.fetch()
'''
    (tmp_path / "factory.py").write_text(source, encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repo-python"), SnapshotId("snapshot-python")
    )

    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}
    build = chunks["factory.build"]
    fetch_call = next(call for call in build.code_calls if call.name == "fetch")
    assert fetch_call.receiver_type is None


def test_python_for_loop_list_annotation_infers_element_receiver(tmp_path):
    source = '''class Item:
    def run(self):
        pass

def use(items: list[Item]):
    for item in items:
        item.run()
'''
    (tmp_path / "loop.py").write_text(source, encoding="utf-8")
    result = process_repository(
        str(tmp_path), RepositoryId("repo-py"), SnapshotId("snapshot-py")
    )
    chunks = result.chunks
    use = next(chunk for chunk in chunks if "use" in chunk.symbol_name)
    run_call = next(call for call in use.code_calls if call.name == "run")
    assert run_call.receiver_type == "Item"


def test_python_chunks_record_allowed_argument_counts(tmp_path):
    source = '''class Service:
    def fetch(self, order_id, detail=False):
        return order_id

def collect(first, *others, **options):
    return first

def self(value):
    return value

def configure(path, /, mode="safe", *, enabled, retries=2, **options):
    return configure(path, enabled=True)
'''
    (tmp_path / "arguments.py").write_text(source, encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repo-python"), SnapshotId("snapshot-python")
    )

    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}
    fetch = chunks["arguments.Service.fetch"]
    assert fetch.required_parameter_count == 1
    assert fetch.parameter_count == 2
    assert fetch.accepts_extra_arguments is False

    collect = chunks["arguments.collect"]
    assert collect.required_parameter_count == 1
    assert collect.parameter_count == 1
    assert collect.accepts_extra_arguments is True

    top_level_self = chunks["arguments.self"]
    assert top_level_self.required_parameter_count == 1
    assert top_level_self.parameter_count == 1

    configure = chunks["arguments.configure"]
    assert configure.positional_parameter_count == 2
    assert configure.keyword_parameter_names == ["mode", "enabled", "retries"]
    assert configure.required_keyword_only_parameters == ["enabled"]
    assert configure.accepts_extra_keywords is True
    recursive_call = configure.code_calls[0]
    assert recursive_call.positional_argument_count == 1
    assert recursive_call.keyword_argument_names == ["enabled"]
    assert recursive_call.has_argument_unpacking is False
