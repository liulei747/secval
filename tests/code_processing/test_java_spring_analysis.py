from secval.code_processing.repository_processing.analyze_java_spring import (
    analyze_java_spring,
)
from secval.models.code import CodeChunk
from secval.models.identifiers import (
    ChunkId,
    FileId,
    RepositoryId,
    SnapshotId,
    SymbolId,
)


def chunk(identifier, kind, name, content, line=1, supertypes=None):
    return CodeChunk(
        ChunkId("chunk-" + identifier), FileId("file-1"), RepositoryId("repo"),
        SnapshotId("snap"), "src/Demo.java", "java", kind, content, line, line + 5,
        symbol_id=SymbolId(identifier), symbol_names=[name],
        supertype_full_names=supertypes or [],
    )


def test_spring_beans_injection_entries_and_constant_reflection():
    chunks = [
        chunk("bean", "class", "demo.UserServiceImpl",
              '@Service("users") @Primary class UserServiceImpl {}',
              supertypes=["demo.UserService"]),
        chunk("field", "field", "demo.Controller.service",
              '@Autowired @Qualifier("users") private UserService service;'),
        chunk("entry", "method", "demo.Controller.get()",
              '@GetMapping("/users") public void get() {}'),
        chunk("target", "method", "demo.UserServiceImpl.run()", "void run() {}"),
        chunk("caller", "method", "demo.Controller.reflect()",
              'void reflect() { Class.forName("demo.UserServiceImpl")'
              '.getDeclaredMethod("run").invoke(target); }', 20),
    ]

    model = analyze_java_spring(chunks)

    assert model["beans"][0]["bean_name"] == "users"
    assert model["injections"][0]["status"] == "RESOLVED"
    assert model["injections"][0]["bean_symbol_ids"] == ["bean"]
    assert model["entries"][0]["kind"] == "HTTP_ROUTE"
    assert model["entries"][0]["value"] == "/users"
    assert model["reflections"][0]["status"] == "RESOLVED"
    assert model["reflections"][0]["callee_symbol_ids"] == ["target"]


def test_ambiguous_injection_is_not_promoted_to_unique_target():
    model = analyze_java_spring([
        chunk("a", "class", "demo.A", "@Service class A {}", supertypes=["demo.Api"]),
        chunk("b", "class", "demo.B", "@Service class B {}", supertypes=["demo.Api"]),
        chunk("field", "field", "demo.Controller.api", "@Autowired private Api api;"),
    ])

    assert model["injections"][0]["status"] == "AMBIGUOUS"
    assert set(model["injections"][0]["bean_symbol_ids"]) == {"a", "b"}


def test_autowired_setter_parameter_resolves_and_links_assigned_field():
    model = analyze_java_spring([
        chunk("controller", "class", "demo.Controller", "@Controller class Controller {}"),
        chunk("service", "class", "demo.UserService", "@Service class UserService {}"),
        chunk("field", "field", "demo.Controller.userService",
              "private UserService userService;"),
        chunk("setter", "method", "demo.Controller.setUserService(UserService)",
              "@Autowired public void setUserService(UserService userService) {\n"
              "  this.userService = userService;\n}"),
    ])

    injection = next(item for item in model["injections"]
                     if item["point_kind"] == "METHOD_PARAMETER")
    assert injection["injection_point_symbol_id"] == "setter"
    assert injection["parameter_index"] == 0
    assert injection["parameter_name"] == "userService"
    assert injection["assigned_field_symbol_id"] == "field"
    assert injection["bean_symbol_ids"] == ["service"]
    assert injection["status"] == "RESOLVED"


def test_single_component_constructor_is_implicit_injection():
    model = analyze_java_spring([
        chunk("controller", "class", "demo.Controller", "@Controller class Controller {}"),
        chunk("service", "class", "demo.UserService", "@Service class UserService {}"),
        chunk("field", "field", "demo.Controller.userService",
              "private final UserService userService;"),
        chunk("ctor", "constructor", "demo.Controller.Controller(UserService)",
              "public Controller(@Qualifier(\"userService\") UserService service) {\n"
              "  this.userService = service;\n}"),
    ])

    injection = next(item for item in model["injections"]
                     if item["point_kind"] == "CONSTRUCTOR_PARAMETER")
    assert injection["qualifier"] == "userService"
    assert injection["assigned_field_symbol_id"] == "field"
    assert injection["bean_symbol_ids"] == ["service"]


def test_multiple_unannotated_constructors_are_not_implicit_injection():
    model = analyze_java_spring([
        chunk("controller", "class", "demo.Controller", "@Controller class Controller {}"),
        chunk("service", "class", "demo.UserService", "@Service class UserService {}"),
        chunk("ctor1", "constructor", "demo.Controller.Controller()",
              "public Controller() {}"),
        chunk("ctor2", "constructor", "demo.Controller.Controller(UserService)",
              "public Controller(UserService service) {}"),
    ])

    assert model["injections"] == []
