from pathlib import Path

from secval.code_processing.repository_processing import process_repository
from secval.models.identifiers import RepositoryId, SnapshotId


def test_process_a_java_repository(tmp_path: Path) -> None:
    source_directory = tmp_path / "src"
    source_directory.mkdir()
    java_file = source_directory / "UserService.java"
    java_file.write_text(
        """
        package demo;

        class UserService {
            public Object findUser() {
                return null;
            }
        }
        """,
        encoding="utf-8",
    )

    result = process_repository(
        root_path=str(tmp_path),
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
    )

    assert result.total_files == 1
    assert result.successful_files == 1
    assert result.errors == []
    assert {chunk.chunk_type for chunk in result.chunks} == {
        "file",
        "class",
        "method",
    }
    method_chunk = next(
        chunk for chunk in result.chunks if chunk.chunk_type == "method"
    )
    assert method_chunk.symbol_name == "demo.UserService.findUser()"
    assert "public Object findUser()" in method_chunk.content


def test_continue_after_one_java_file_has_syntax_error(
    tmp_path: Path,
) -> None:
    valid_file = tmp_path / "Valid.java"
    invalid_file = tmp_path / "Invalid.java"
    valid_file.write_text(
        "class Valid { void run() {} }",
        encoding="utf-8",
    )
    invalid_file.write_text(
        "class Invalid { void broken( { }",
        encoding="utf-8",
    )

    result = process_repository(
        root_path=str(tmp_path),
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
    )

    assert result.total_files == 2
    assert result.successful_files == 1
    assert {chunk.chunk_type for chunk in result.chunks} == {
        "file",
        "class",
        "method",
    }
    assert len(result.errors) == 1
    assert result.errors[0].relative_path == "Invalid.java"
    assert "语法错误" in result.errors[0].message


def test_resolve_java_method_return_chain_across_files(tmp_path: Path) -> None:
    (tmp_path / "Controller.java").write_text(
        '''package demo;
class Controller {
    Factory factory;
    void submit() { factory.service().run(); }
}
''',
        encoding="utf-8",
    )
    (tmp_path / "Factory.java").write_text(
        '''package demo;
class Factory {
    RightService service() { return new RightService(); }
}
class RightService { void run() {} }
class WrongService { void run() {} }
''',
        encoding="utf-8",
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    submit = next(chunk for chunk in result.chunks
                  if chunk.symbol_name == "demo.Controller.submit()")
    run_call = next(call for call in submit.code_calls if call.name == "run")
    assert run_call.receiver_method_owner_type == "Factory"
    assert run_call.receiver_method_name == "service"
    assert run_call.receiver_method_argument_count == 0
    assert run_call.receiver_type == "RightService"
    assert run_call.receiver_type_full_name == "demo.RightService"


def test_cross_file_return_chain_stays_unknown_when_short_names_conflict(
    tmp_path: Path,
) -> None:
    (tmp_path / "Controller.java").write_text(
        '''package app;
class Controller {
    Factory factory;
    void submit() { factory.service().run(); }
}
''', encoding="utf-8")
    (tmp_path / "FirstFactory.java").write_text(
        '''package first;
class Factory { RightService service() { return null; } }
class RightService { void run() {} }
''', encoding="utf-8")
    (tmp_path / "SecondFactory.java").write_text(
        '''package second;
class Factory { WrongService service() { return null; } }
class WrongService { void run() {} }
''', encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    submit = next(chunk for chunk in result.chunks
                  if chunk.symbol_name == "app.Controller.submit()")
    run_call = next(call for call in submit.code_calls if call.name == "run")
    assert run_call.receiver_type is None
    assert run_call.receiver_type_full_name is None


def test_explicit_import_resolves_same_short_type_names(tmp_path: Path) -> None:
    (tmp_path / "Controller.java").write_text(
        '''package app;
import first.Factory;
class Controller {
    Factory factory;
    void submit() { factory.service().run(); }
}
''', encoding="utf-8")
    (tmp_path / "FirstFactory.java").write_text(
        '''package first;
class Factory { RightService service() { return null; } }
class RightService { void run() {} }
''', encoding="utf-8")
    (tmp_path / "SecondFactory.java").write_text(
        '''package second;
class Factory { WrongService service() { return null; } }
class WrongService { void run() {} }
''', encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    submit = next(chunk for chunk in result.chunks
                  if chunk.symbol_name == "app.Controller.submit()")
    service_call = next(call for call in submit.code_calls if call.name == "service")
    run_call = next(call for call in submit.code_calls if call.name == "run")
    assert service_call.receiver_type_full_name == "first.Factory"
    assert run_call.receiver_type == "RightService"
    assert run_call.receiver_type_full_name == "first.RightService"


def test_java_type_relations_and_overrides_across_files(tmp_path: Path) -> None:
    (tmp_path / "Types.java").write_text(
        '''package demo;
interface Greeter { void greet(); }
class Base { void greet() {} }
''', encoding="utf-8")
    (tmp_path / "Service.java").write_text(
        '''package demo;
class Service extends Base implements Greeter {
    public void greet() {}
}
''', encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}
    service = chunks["demo.Service"]
    assert service.supertype_full_names == ["demo.Base", "demo.Greeter"]
    assert service.ancestor_type_full_names == ["demo.Base", "demo.Greeter"]
    greet = chunks["demo.Service.greet()"]
    assert greet.ancestor_type_full_names == ["demo.Base", "demo.Greeter"]

    inherited = chunks["demo.Base.greet()"]
    assert inherited.declared_return_type == "void"


def test_inherited_method_without_override_does_not_fake_a_declaration(
    tmp_path: Path,
) -> None:
    (tmp_path / "Base.java").write_text(
        '''package demo;
public class Base { public RightService service() { return null; } }
''', encoding="utf-8")
    (tmp_path / "Mid.java").write_text(
        '''package demo;
public class Mid extends Base {
}
''', encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    symbol_names = [chunk.symbol_name for chunk in result.chunks]
    assert "demo.Mid.service()" not in symbol_names


def test_return_chain_through_inherited_method_across_types(tmp_path: Path) -> None:
    (tmp_path / "Controller.java").write_text(
        '''package demo;
class Controller {
    Mid mid;
    void submit() { mid.service().run(); }
}
''', encoding="utf-8")
    (tmp_path / "Base.java").write_text(
        '''package demo;
public class Base { public RightService service() { return null; } }
''', encoding="utf-8")
    (tmp_path / "Mid.java").write_text(
        '''package demo;
public class Mid extends Base {
}
''', encoding="utf-8")
    (tmp_path / "Right.java").write_text(
        '''package demo;
public class RightService { void run() {} }
''', encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    submit = next(chunk for chunk in result.chunks
                  if chunk.symbol_name == "demo.Controller.submit()")
    run_call = next(call for call in submit.code_calls if call.name == "run")
    assert run_call.receiver_type == "RightService"
    assert run_call.receiver_type_full_name == "demo.RightService"


def test_python_class_extends_resolves_unique_short_names(tmp_path: Path) -> None:
    (tmp_path / "base.py").write_text(
        '''class Base:
    def greet(self):
        pass
''', encoding="utf-8")
    (tmp_path / "service.py").write_text(
        '''from base import Base
class Service(Base):
    def greet(self):
        pass
''', encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}
    service = chunks["service.Service"]
    assert service.extends_types == ["Base"]
    assert service.supertype_full_names == ["base.Base"]
    assert service.ancestor_type_full_names == ["base.Base"]
    override = chunks["service.Service.greet"]
    assert override.ancestor_type_full_names == ["base.Base"]


def test_python_explicit_import_resolves_conflicting_base_names(tmp_path: Path) -> None:
    (tmp_path / "first.py").write_text(
        '''class Base:
    def greet(self):
        pass
''', encoding="utf-8")
    (tmp_path / "second.py").write_text(
        '''class Base:
    def greet(self):
        pass
''', encoding="utf-8")
    (tmp_path / "service.py").write_text(
        '''from second import Base
class Service(Base):
    pass
''', encoding="utf-8")

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    service = next(
        chunk for chunk in result.chunks
        if chunk.symbol_name == "service.Service"
    )
    assert service.supertype_full_names == ["second.Base"]
    assert service.ancestor_type_full_names == ["second.Base"]


def test_python_import_aliases_resolve_receiver_full_names(tmp_path: Path) -> None:
    (tmp_path / "first").mkdir()
    (tmp_path / "second").mkdir()
    (tmp_path / "first" / "service.py").write_text(
        "class OrderService:\n    def fetch(self):\n        pass\n",
        encoding="utf-8",
    )
    (tmp_path / "second" / "service.py").write_text(
        "class OrderService:\n    def fetch(self):\n        pass\n",
        encoding="utf-8",
    )
    (tmp_path / "controller.py").write_text(
        '''import first.service as service_module
from second.service import OrderService as SecondService

def first_call(service: service_module.OrderService):
    service.fetch()

def second_call(service: SecondService):
    service.fetch()

def build():
    service_module.OrderService().fetch()
''',
        encoding="utf-8",
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}
    first_call = chunks["controller.first_call"].code_calls[0]
    second_call = chunks["controller.second_call"].code_calls[0]
    build_call = next(
        call for call in chunks["controller.build"].code_calls
        if call.name == "fetch"
    )
    assert first_call.receiver_type_full_name == "first.service.OrderService"
    assert second_call.receiver_type_full_name == "second.service.OrderService"
    assert build_call.receiver_type_full_name == "first.service.OrderService"


def test_python_relative_import_resolves_package_base(tmp_path: Path) -> None:
    package = tmp_path / "orders"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "base.py").write_text(
        "class Base:\n    pass\n", encoding="utf-8"
    )
    (package / "service.py").write_text(
        "from .base import Base\nclass Service(Base):\n    pass\n",
        encoding="utf-8",
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    service = next(
        chunk for chunk in result.chunks
        if chunk.symbol_name == "orders.service.Service"
    )
    assert service.supertype_full_names == ["orders.base.Base"]


def test_python_unimported_duplicate_type_stays_unknown(tmp_path: Path) -> None:
    (tmp_path / "first.py").write_text("class Base:\n    pass\n", encoding="utf-8")
    (tmp_path / "second.py").write_text("class Base:\n    pass\n", encoding="utf-8")
    (tmp_path / "service.py").write_text(
        "class Service(Base):\n    pass\n", encoding="utf-8"
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    service = next(
        chunk for chunk in result.chunks
        if chunk.symbol_name == "service.Service"
    )
    assert service.supertype_full_names == []


def test_python_cross_file_return_type_chain_is_resolved(tmp_path: Path) -> None:
    (tmp_path / "services.py").write_text(
        "class OrderService:\n    def fetch(self):\n        pass\n",
        encoding="utf-8",
    )
    (tmp_path / "factory.py").write_text(
        '''from services import OrderService
class Factory:
    def create_service(self, kind="default") -> OrderService:
        return OrderService()
''',
        encoding="utf-8",
    )
    (tmp_path / "controller.py").write_text(
        '''from factory import Factory
def handle(factory: Factory):
    factory.create_service().fetch()
''',
        encoding="utf-8",
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    chunks = {chunk.symbol_name: chunk for chunk in result.chunks}
    factory_method = chunks["factory.Factory.create_service"]
    assert factory_method.declared_return_full_name == "services.OrderService"
    fetch_call = next(
        call for call in chunks["controller.handle"].code_calls
        if call.name == "fetch"
    )
    assert fetch_call.receiver_type == "OrderService"
    assert fetch_call.receiver_type_full_name == "services.OrderService"


def test_python_ambiguous_return_type_chain_stays_unknown(tmp_path: Path) -> None:
    (tmp_path / "first.py").write_text("class Service:\n    pass\n", encoding="utf-8")
    (tmp_path / "second.py").write_text("class Service:\n    pass\n", encoding="utf-8")
    (tmp_path / "factory.py").write_text(
        '''class Factory:
    def create(self) -> Service:
        raise NotImplementedError
''',
        encoding="utf-8",
    )
    (tmp_path / "controller.py").write_text(
        '''from factory import Factory
def handle(factory: Factory):
    factory.create().run()
''',
        encoding="utf-8",
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    handle = next(
        chunk for chunk in result.chunks
        if chunk.symbol_name == "controller.handle"
    )
    run_call = next(call for call in handle.code_calls if call.name == "run")
    assert run_call.receiver_type_full_name is None


def test_python_inherited_method_return_type_chain_is_resolved(tmp_path: Path) -> None:
    (tmp_path / "services.py").write_text(
        "class Service:\n    def run(self):\n        pass\n",
        encoding="utf-8",
    )
    (tmp_path / "base.py").write_text(
        '''from services import Service
class BaseFactory:
    def create(self) -> Service:
        return Service()
''',
        encoding="utf-8",
    )
    (tmp_path / "child.py").write_text(
        "from base import BaseFactory\nclass ChildFactory(BaseFactory):\n    pass\n",
        encoding="utf-8",
    )
    (tmp_path / "controller.py").write_text(
        '''from child import ChildFactory
def handle(factory: ChildFactory):
    factory.create().run()
''',
        encoding="utf-8",
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    handle = next(
        chunk for chunk in result.chunks
        if chunk.symbol_name == "controller.handle"
    )
    run_call = next(call for call in handle.code_calls if call.name == "run")
    assert run_call.receiver_type_full_name == "services.Service"


def test_python_child_return_annotation_overrides_parent(tmp_path: Path) -> None:
    (tmp_path / "services.py").write_text(
        "class ParentService:\n    pass\nclass ChildService:\n    pass\n",
        encoding="utf-8",
    )
    (tmp_path / "base.py").write_text(
        '''from services import ParentService
class BaseFactory:
    def create(self) -> ParentService:
        return ParentService()
''',
        encoding="utf-8",
    )
    (tmp_path / "child.py").write_text(
        '''from base import BaseFactory
from services import ChildService
class ChildFactory(BaseFactory):
    def create(self) -> ChildService:
        return ChildService()
''',
        encoding="utf-8",
    )
    (tmp_path / "controller.py").write_text(
        '''from child import ChildFactory
def handle(factory: ChildFactory):
    factory.create().run()
''',
        encoding="utf-8",
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    handle = next(
        chunk for chunk in result.chunks
        if chunk.symbol_name == "controller.handle"
    )
    run_call = next(call for call in handle.code_calls if call.name == "run")
    assert run_call.receiver_type_full_name == "services.ChildService"


def test_python_conflicting_inherited_return_types_stay_unknown(tmp_path: Path) -> None:
    (tmp_path / "services.py").write_text(
        "class FirstService:\n    pass\nclass SecondService:\n    pass\n",
        encoding="utf-8",
    )
    (tmp_path / "parents.py").write_text(
        '''from services import FirstService, SecondService
class FirstFactory:
    def create(self) -> FirstService:
        return FirstService()
class SecondFactory:
    def create(self) -> SecondService:
        return SecondService()
''',
        encoding="utf-8",
    )
    (tmp_path / "child.py").write_text(
        '''from parents import FirstFactory, SecondFactory
class ChildFactory(FirstFactory, SecondFactory):
    pass
''',
        encoding="utf-8",
    )
    (tmp_path / "controller.py").write_text(
        '''from child import ChildFactory
def handle(factory: ChildFactory):
    factory.create().run()
''',
        encoding="utf-8",
    )

    result = process_repository(
        str(tmp_path), RepositoryId("repository-1"), SnapshotId("snapshot-1")
    )

    handle = next(
        chunk for chunk in result.chunks
        if chunk.symbol_name == "controller.handle"
    )
    run_call = next(call for call in handle.code_calls if call.name == "run")
    assert run_call.receiver_type_full_name is None
