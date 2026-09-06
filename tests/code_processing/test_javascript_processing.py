"""验证 JavaScript 扫描、解析、切块和调用提取。"""

from secval.code_processing.repository_processing import process_repository
from secval.models.identifiers import RepositoryId, SnapshotId


def test_javascript_repository_creates_declaration_chunks(tmp_path):
    source = '''import express from "express";

class OrderService {
    find(orderId) {
        return loadOrder(orderId);
    }

    list() {
        return this.find("first");
    }
}

function build(service) {
    return service.find("second");
}

const health = () => checkHealth();
'''
    (tmp_path / "orders.js").write_text(source, encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repo-js"), SnapshotId("snapshot-js")
    )

    assert result.total_files == 1
    assert result.successful_files == 1
    assert result.errors == []
    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}
    assert "orders.OrderService" in chunks
    assert "orders.OrderService.find" in chunks
    assert "orders.OrderService.list" in chunks
    assert "orders.build" in chunks
    assert "orders.health" in chunks

    find_call = chunks["orders.OrderService.find"].code_calls[0]
    assert find_call.name == "loadOrder"
    assert find_call.argument_count == 1

    list_call = chunks["orders.OrderService.list"].code_calls[0]
    assert list_call.name == "find"
    assert list_call.receiver_type == "OrderService"

    build_call = chunks["orders.build"].code_calls[0]
    assert build_call.name == "find"
    assert build_call.receiver_type is None

    health_call = chunks["orders.health"].code_calls[0]
    assert health_call.name == "checkHealth"


def test_javascript_syntax_error_does_not_stop_other_files(tmp_path):
    (tmp_path / "broken.js").write_text("function broken( {", encoding="utf-8")
    (tmp_path / "good.js").write_text(
        "function good() { return ready(); }", encoding="utf-8"
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repo-js"), SnapshotId("snapshot-js")
    )

    assert result.total_files == 2
    assert result.successful_files == 1
    assert len(result.errors) == 1
    assert result.errors[0].relative_path == "broken.js"
    assert any(chunk.symbol_name == "good.good" for chunk in result.chunks)


def test_commonjs_require_resolves_receiver_type(tmp_path):
    (tmp_path / "orders.js").write_text(
        '''class OrderService {
    find(orderId) { return orderId; }
}

module.exports = { OrderService };
''',
        encoding="utf-8",
    )
    (tmp_path / "controller.js").write_text(
        '''const { OrderService } = require("./orders");

function handle(orderId) {
    return new OrderService().find(orderId);
}
''',
        encoding="utf-8",
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repo-cjs"), SnapshotId("snapshot-cjs")
    )
    handle = next(
        chunk for chunk in result.chunks
        if chunk.symbol_name == "controller.handle"
    )
    find_call = next(call for call in handle.code_calls if call.name == "find")

    assert find_call.receiver_type == "OrderService"
    assert find_call.receiver_type_full_name == "orders.OrderService"


def test_default_import_resolves_unique_type_and_ambiguity_stays_unknown(tmp_path):
    (tmp_path / "unique").mkdir()
    (tmp_path / "ambiguous").mkdir()
    (tmp_path / "unique" / "orders.js").write_text(
        '''class OrderService {}
module.exports = OrderService;
''',
        encoding="utf-8",
    )
    (tmp_path / "ambiguous" / "orders.js").write_text(
        '''class OrderService {}
class OtherService {}
module.exports = { OrderService, OtherService };
''',
        encoding="utf-8",
    )
    (tmp_path / "controller.js").write_text(
        '''import UniqueService from "./unique/orders";
import AmbiguousService from "./ambiguous/orders";

export function unique(orderId) {
    return new UniqueService().find(orderId);
}

export function ambiguous(orderId) {
    return new AmbiguousService().find(orderId);
}
''',
        encoding="utf-8",
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repo-default"), SnapshotId("snapshot-default")
    )
    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}

    unique_call = next(
        call for call in chunks["controller.unique"].code_calls
        if call.name == "find"
    )
    ambiguous_call = next(
        call for call in chunks["controller.ambiguous"].code_calls
        if call.name == "find"
    )
    assert unique_call.receiver_type_full_name == "unique.orders.OrderService"
    assert ambiguous_call.receiver_type_full_name is None


def test_namespace_require_resolves_unique_member(tmp_path):
    (tmp_path / "orders.js").write_text(
        '''class OrderService {}
module.exports = { OrderService };
''',
        encoding="utf-8",
    )
    (tmp_path / "controller.js").write_text(
        '''const orders = require("./orders");

function handle(orderId) {
    return new orders.OrderService().find(orderId);
}
''',
        encoding="utf-8",
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repo-ns"), SnapshotId("snapshot-ns")
    )
    handle = next(
        chunk for chunk in result.chunks
        if chunk.symbol_name == "controller.handle"
    )
    find_call = next(call for call in handle.code_calls if call.name == "find")

    assert find_call.receiver_type_full_name == "orders.OrderService"
