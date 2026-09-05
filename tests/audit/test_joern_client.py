"""Joern客户端只接受安全参数，并把输出转换成简单位置。"""

from unittest.mock import MagicMock
import base64

import pytest

from secval.infrastructure.joern import JoernClient


def test_import_code_saves_generated_dataflow_overlay():
    client = JoernClient("http://joern:8080")
    client._query = MagicMock(side_effect=["", '"SECVAL:1"', "", ""])

    project = client.import_code("/joern-inputs/demo", "run-1")

    assert project == "secval-run-1"
    assert [call.args[0] for call in client._query.call_args_list] == [
        'importCode(inputPath="/joern-inputs/demo", projectName="secval-run-1")',
        'open("secval-run-1"); "SECVAL:" + cpg.metaData.size',
        "run.ossdataflow",
        "save",
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
