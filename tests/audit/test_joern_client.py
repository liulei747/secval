"""Joern客户端只接受安全参数，并把输出转换成简单位置。"""

import base64
from threading import Event, Thread
from unittest.mock import MagicMock

import pytest

from secval.bootstrap import joern_runtime
from secval.infrastructure.joern import JoernClient


def test_import_code_saves_generated_dataflow_overlay():
    client = JoernClient("http://joern:8080")
    client._query = MagicMock(side_effect=["", '"SECVAL:1"', "", "", ""])

    project = client.import_code("/joern-inputs/demo", "run-1")

    assert project == "secval-run-1"
    assert [call.args[0] for call in client._query.call_args_list] == [
        'importCode(inputPath="/joern-inputs/demo", projectName="secval-run-1")',
        'open("secval-run-1"); "SECVAL:" + cpg.metaData.size',
        "run.ossdataflow",
        "save",
        'close("secval-run-1")',
    ]


def test_find_calls_builds_fixed_query_and_parses_rows():
    client = JoernClient("http://joern:8080")
    project = base64.b64encode(b"secval-run-1-java").decode()
    client._query = MagicMock(side_effect=[
        f'val res: String = "SECVAL:{project}"',
        'val res: String = "SECVAL:ZmV0Y2gJc3JjL09yZGVyLmphdmEJMTI="',
    ])

    rows = client.find_calls("run-1", "fetch", 5)

    assert rows == [{"method": "fetch", "path": "src/Order.java", "line": 12}]
    query = client._query.call_args_list[-1].args[0]
    assert 'open("secval-run-1-java")' in query
    assert 'nameExact("fetch")' in query
    assert 'close("secval-run-1-java")' in query


@pytest.mark.parametrize("method", ['fetch\")', "a.b", "name with space"])
def test_find_calls_rejects_query_injection(method):
    with pytest.raises(ValueError):
        JoernClient("http://joern:8080").find_calls("run-1", method)


def test_find_data_paths_returns_locations_without_source_code():
    encoded = base64.b64encode(
        b"METHOD_PARAMETER_IN\tsrc/Order.java\t3\nCALL\tsrc/Order.java\t8"
    ).decode()
    client = JoernClient("http://joern:8080")
    project = base64.b64encode(b"secval-run-1-java").decode()
    client._query = MagicMock(side_effect=[
        f'val res: String = "SECVAL:{project}"',
        f'val res: String = "SECVAL:{encoded}"',
    ])

    paths = client.find_data_paths("run-1", "fetch", "execute", 4)

    assert paths == [{"steps": [
        {"node_type": "METHOD_PARAMETER_IN", "path": "src/Order.java", "line": 3},
        {"node_type": "CALL", "path": "src/Order.java", "line": 8},
    ]}]
    assert "reachableByFlows" in client._query.call_args_list[-1].args[0]
    assert 'close("secval-run-1-java")' in client._query.call_args_list[-1].args[0]


def test_find_calls_combines_language_projects():
    java_project = base64.b64encode(b"secval-run-1-java").decode()
    python_project = base64.b64encode(b"secval-run-1-python").decode()
    java_call = base64.b64encode(b"fetch\tSafe.java\t4").decode()
    python_call = base64.b64encode(b"fetch\tservice.py\t9").decode()
    client = JoernClient("http://joern:8080")
    client._query = MagicMock(side_effect=[
        f'"SECVAL:{python_project},{java_project}"',
        f'"SECVAL:{java_call}"',
        f'"SECVAL:{python_call}"',
    ])

    rows = client.find_calls("run-1", "fetch", 5)

    assert {(row["path"], row["line"]) for row in rows} == {
        ("Safe.java", 4), ("service.py", 9)
    }


def test_export_call_sites_keeps_joern_resolution_metadata():
    project = base64.b64encode(b"secval-run-1-java").decode()
    separator = "\0"
    fields = separator.join((
        "demo.Controller.submit:void()", "demo.Service.run:void()", "run",
        "/joern-inputs/demo/src/Controller.java", "12", "9",
        "DYNAMIC_DISPATCH", "void()", "service.run()",
    ))
    row = base64.b64encode(fields.encode()).decode()
    client = JoernClient("http://joern:8080")
    client._query = MagicMock(side_effect=[f'"SECVAL:{project}"', f'"SECVAL:{row}"'])

    assert client.export_call_sites("run-1") == [{
        "caller_full_name": "demo.Controller.submit:void()",
        "callee_full_name": "demo.Service.run:void()", "name": "run",
        "path": "/joern-inputs/demo/src/Controller.java", "line": 12,
        "column": 9, "dispatch_type": "DYNAMIC_DISPATCH",
        "signature": "void()", "code": "service.run()",
        "project": "secval-run-1-java",
    }]
    query = client._query.call_args_list[-1].args[0]
    assert 'Option(call.name).getOrElse("")' in query
    assert ".take(1000)" in query


def test_javascript_uses_its_own_joern_project():
    assert JoernClient._project_name("run-1", "javascript") == (
        "secval-run-1-javascript"
    )


def test_health_check_uses_its_own_short_timeout():
    client = JoernClient("http://joern:8080", timeout_seconds=600)
    client._query = MagicMock(return_value='"SECVAL:1"')

    client.verify(timeout_seconds=5)

    client._query.assert_called_once_with('"SECVAL:1"', timeout_seconds=5)


def test_query_timeout_also_limits_waiting_for_the_client_lock():
    client = JoernClient("http://joern:8080")
    client.lock = MagicMock()
    client.lock.acquire.return_value = False

    with pytest.raises(RuntimeError, match="等待已超时"):
        client._query('"SECVAL:1"', timeout_seconds=0.01)

    client.lock.acquire.assert_called_once_with(timeout=0.01)
    client.lock.release.assert_not_called()


def test_health_check_cannot_interrupt_a_multi_step_import(monkeypatch):
    """导入步骤之间仍持锁时，短健康检查应超时而不是切换活动项目。"""

    class Response:
        def __init__(self, stdout):
            self.payload = ('{"stdout": ' + repr(stdout).replace("'", '"') + '}').encode()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, *args):
            return self.payload

    def fake_urlopen(request, timeout):
        query = request.data.decode("utf-8")
        if "metaData.size" in query:
            return Response("SECVAL:1")
        return Response("")

    monkeypatch.setattr(
        "secval.infrastructure.joern.joern_client.urlopen", fake_urlopen
    )
    client = JoernClient("http://joern:8080", timeout_seconds=1)
    original_query = client._query
    between_steps = Event()
    allow_import_to_continue = Event()

    def pause_after_first_step(query, timeout_seconds=None):
        output = original_query(query, timeout_seconds)
        if query.startswith("importCode"):
            between_steps.set()
            allow_import_to_continue.wait(timeout=1)
        return output

    client._query = pause_after_first_step
    import_errors = []

    def run_import():
        try:
            client.import_code("/code", "run-1")
        except Exception as error:
            import_errors.append(error)

    worker = Thread(target=run_import)
    worker.start()
    assert between_steps.wait(timeout=1)

    with pytest.raises(RuntimeError, match="等待已超时"):
        client.verify(timeout_seconds=0.01)

    allow_import_to_continue.set()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert import_errors == []


def test_runtime_creation_does_not_block_on_joern_health(monkeypatch):
    fake_client = MagicMock()
    monkeypatch.setenv("SECVAL_JOERN_URL", "http://joern:8080")
    monkeypatch.setenv("SECVAL_JOERN_PASSWORD", "test-password")
    monkeypatch.delenv("SECVAL_JOERN_PASSWORD_FILE", raising=False)
    monkeypatch.setattr(joern_runtime, "JoernClient", MagicMock(return_value=fake_client))

    created = joern_runtime.create_optional_joern_client()

    assert created is fake_client
    fake_client.verify.assert_not_called()
