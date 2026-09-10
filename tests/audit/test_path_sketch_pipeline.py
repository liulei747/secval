"""Prefill path sketches are compact, evidence-bound, durable pipeline records."""

import pytest

from secval.models.agent_work import parse_work_result
from secval.models.audit_contracts import ModelOutputError
from secval.services.agent_team import (
    AgentTeam,
    bounded_path_groups,
    deterministic_sink_sketches,
    packet_security_signals,
)
from secval.services.path_validation_pipeline import (
    _continuation_operations,
    _dependency_terms,
    _need_operations,
    build_validation_packets,
    deterministic_config_result,
    model_evidence_view,
    parse_validation_result,
)


def test_symbol_need_prioritizes_exact_member_and_owner():
    operations = _need_operations({"kind": "symbol_definition",
                                   "target": "com.example.service.DocumentService#loadDocument"})
    assert operations[:2] == [
        {"tool": "find_symbol", "arguments": {"text": "DocumentService", "offset": 0}},
        {"tool": "find_symbol", "arguments": {"text": "loadDocument", "offset": 0}},
    ]
    assert all(row["arguments"]["text"] not in {"com", "example", "service"}
               for row in operations)


def test_symbol_need_expands_compact_member_group():
    operations = _need_operations({"kind": "symbol_definition",
                                   "target": "DocumentService.loadDocument/storeDocument"})
    assert [row["arguments"]["text"] for row in operations] == [
        "DocumentService", "loadDocument", "storeDocument",
        "DocumentService",
    ]


def test_wildcard_mapper_read_is_resolved_by_source_search():
    assert _need_operations({"kind": "file_read", "target": "classpath:mapper/*.xml"}) == [
        {"tool": "search_source", "arguments": {"text": "${", "offset": 0}}
    ]


def test_dependency_frontier_follows_project_types_without_generic_method_fanout():
    evidence = {"e": {"content": """
        import com.demo.dao.ProductMapper;
        import com.demo.validation.ProductValidator;
        import java.util.List;
        class ProductService {
          void search(Criteria c) { validator.validateSearchCriteria(c); mapper.searchProducts(c); }
        }
    """}}
    terms = _dependency_terms({"sketches": []}, evidence)
    assert "ProductMapper" in terms
    assert "ProductValidator" in terms
    assert "validateSearchCriteria" not in terms
    assert "searchProducts" not in terms
    assert "List" not in terms


def test_dependency_frontier_follows_only_wrappers_of_current_sink():
    evidence = {"e": {"content": """
      public void executeShellCommand(String value) { executeCommand("sh -c " + value); }
      private void executeCommand(String command) { Runtime.getRuntime().exec(command); }
      public void unrelated() { helper(); }
    """}}
    packet = {"sketches": [{"source": "input", "sink": "Runtime.exec", "control": "escaping",
                             "hops": ["executeCommand"], "needs": []}]}
    terms = _dependency_terms(packet, evidence)
    assert "executeShellCommand" in terms
    assert "unrelated" not in terms
    assert "helper" not in terms


def test_model_evidence_view_keeps_later_dependency_files_visible():
    evidence = {
        "controller": {"evidence_id": "controller", "content": "a" * 7000},
        "service": {"evidence_id": "service", "content": "b" * 7000},
        "validator": {"evidence_id": "validator", "content": "c" * 7000},
        "mapper": {"evidence_id": "mapper", "content": "d" * 7000},
    }
    rows = model_evidence_view(evidence)
    assert [row["evidence_id"] for row in rows] == list(evidence)
    assert all(not row["packet_truncated"] for row in rows)


def test_model_evidence_view_reserves_space_for_each_path_role():
    evidence = {
        "controller-1": {"evidence_id": "controller-1", "relative_path": "PageController.java",
                         "content": "a" * 12000},
        "controller-2": {"evidence_id": "controller-2", "relative_path": "PageController.java",
                         "content": "b" * 12000},
        "dto": {"evidence_id": "dto", "relative_path": "PageRequest.java", "content": "c" * 12000},
        "service": {"evidence_id": "service", "relative_path": "PageService.java", "content": "d" * 12000},
        "repository": {"evidence_id": "repository", "relative_path": "PageRepository.java",
                       "content": "e" * 12000},
    }
    rows = model_evidence_view(evidence)
    assert {row["evidence_id"] for row in rows} >= {"controller-1", "dto", "service", "repository"}
    assert "controller-2" not in {row["evidence_id"] for row in rows}


def test_truncated_batch_file_is_continued_from_returned_offset():
    result = {"items": [{"tool": "read_file", "arguments": {"path": "PageController.java"},
                         "result": {"rows": [{"next_char_offset": 12000}]}}]}
    assert _continuation_operations(result) == [{
        "tool": "read_file", "arguments": {"path": "PageController.java", "char_offset": 12000}}]


def test_config_channel_supports_exact_static_values_without_http_path():
    config = {"e-1": {"content": "server:\n  error:\n    include-stacktrace: always\n"}}
    path = {**sketch(), "id": "cfg", "entry": "application.yml",
            "surface": "configuration", "candidate_type": "security_misconfiguration",
            "deterministic_anchor": "include-stacktrace",
            "control": "生产响应禁用堆栈信息"}
    packet = {"id": "validation:cfg", "surface": "configuration"}
    result = deterministic_config_result(packet, [path], config)
    assert result["outcomes"][0]["outcome"] == "inconclusive"
    assert result["outcomes"][0]["resolved_sink"] == "server.error.include-stacktrace=always"


def result(sketch):
    return {"summary": "one-shot probe", "questions": [], "unknowns": ["validation pending"],
            "reviewed_files": [], "findings": [], "path_sketches": [sketch]}


def sketch(evidence_id="e-1"):
    return {"surface": "authorization", "candidate_type": "object_level_authorization",
            "entry": "Controller.get", "source": "request.id",
            "hops": ["Service.get"], "sink": "DAO lookup", "control": "method permission",
            "hypothesis": "object ownership may be missing", "needs": ["DAO data scope"],
            "evidence_ids": [evidence_id]}


def test_path_sketch_is_validated_and_materialized_once():
    parsed = parse_work_result(result(sketch()), {"e-1": {}})
    rows = AgentTeam._merge_path_sketches([], parsed, "agent-2")
    normalized = sketch()
    normalized["needs"] = [{"kind": "source_search", "target": "DAO data scope",
                            "reason": "DAO data scope", "required_for": "validation"}]
    assert rows == [{**normalized, "id": "agent-2:path-1", "status": "queued_for_validation",
                     "source_id": "agent-2", "origins": [{
                         "kind": "model", "producer": "agent-2", "role": "primary",
                         "capability": "bootstrap_hint",
                     }]}]
    assert AgentTeam._merge_path_sketches(rows, parsed, "agent-2") == rows


def test_model_path_enriches_matching_deterministic_sink_instead_of_duplication():
    deterministic = {
        **sketch(), "id": "system:path-1", "source_id": "legacy_sink_bootstrap",
        "status": "queued_for_validation", "candidate_type": "command_injection",
        "surface": "command_execution", "entry": "待由调用者闭包解析的入口",
        "source": "外部可控输入候选", "hops": ["executeCommand"],
        "sink": "NativeProcessHandler.java 中的 Runtime.exec",
        "deterministic_anchor": "Runtime.exec",
        "origins": [{"kind": "heuristic", "producer": "legacy_sink_bootstrap",
                     "role": "primary", "capability": "bootstrap_hint"}],
    }
    model = {**sketch(), "candidate_type": "command_injection",
             "surface": "command_execution", "entry": "POST /api/system/backup",
             "source": "request.backupPath",
             "hops": ["createBackup", "executeCommand"], "sink": "Runtime.exec"}
    rows = AgentTeam._merge_path_sketches([deterministic], result(model), "agent-2")
    assert len(rows) == 1
    assert rows[0]["entry"] == "POST /api/system/backup"
    assert rows[0]["source"] == "request.backupPath"
    assert rows[0]["hops"] == ["executeCommand", "createBackup"]
    assert rows[0]["merged_source_ids"] == ["legacy_sink_bootstrap", "agent-2"]
    assert [origin["kind"] for origin in rows[0]["origins"]] == ["heuristic", "model"]


def test_validation_accepts_evidence_bound_resolved_path_fields():
    path = {**sketch(), "id": "path-1"}
    packet = {"id": "validation-1", "path_ids": ["path-1"]}
    raw = {"packet_id": "validation-1", "outcomes": [{
        "path_id": "path-1", "outcome": "supported", "assessment": "路径成立",
        "counterevidence": "未发现有效控制", "limitations": [], "evidence_ids": ["e-1"],
        "resolved_entry": "POST /orders", "resolved_source": "body.name",
        "resolved_hops": ["Controller.save", "Service.save"],
        "resolved_sink": "Mapper.insert", "resolved_controls": [],
    }]}
    parsed = parse_validation_result(raw, packet, [path], {"e-1": {}})
    assert parsed["outcomes"][0]["resolved_entry"] == "POST /orders"


def test_path_sketch_cannot_reference_unread_evidence():
    with pytest.raises(ModelOutputError):
        parse_work_result(result(sketch("invented")), {"e-1": {}})


def test_one_shot_probe_normalizes_unambiguous_list_variants():
    raw = sketch()
    raw.update(hops="Service.get", needs=None)
    parsed = parse_work_result(result(raw), {"e-1": {}})
    assert parsed["path_sketches"][0]["hops"] == ["Service.get"]
    assert parsed["path_sketches"][0]["needs"] == []


def test_structured_need_is_preserved():
    raw = sketch()
    need = {"kind": "symbol_definition", "target": "OrderService.fetch",
            "reason": "inspect owner check", "required_for": "authorization"}
    raw["needs"] = [need]
    parsed = parse_work_result(result(raw), {"e-1": {}})
    assert parsed["path_sketches"][0]["needs"] == [need]


def test_unambiguous_security_enum_aliases_are_normalized():
    raw = sketch()
    raw.update(surface="access_control", candidate_type="idor")
    parsed = parse_work_result(result(raw), {"e-1": {}})["path_sketches"][0]
    assert (parsed["surface"], parsed["candidate_type"]) == (
        "authorization", "object_level_authorization")


def test_descriptive_surface_is_derived_from_controlled_candidate_type():
    raw = sketch()
    raw.update(surface="HTTP_ENTRY", candidate_type="command_injection")
    parsed = parse_work_result(result(raw), {"e-1": {}})["path_sketches"][0]
    assert parsed["surface"] == "command_execution"


def test_information_disclosure_alias_is_normalized():
    raw = sketch()
    raw.update(surface="response details", candidate_type="information_disclosure")
    parsed = parse_work_result(result(raw), {"e-1": {}})["path_sketches"][0]
    assert (parsed["surface"], parsed["candidate_type"]) == (
        "data_exposure", "sensitive_data_exposure")


def test_unrecognized_candidate_type_is_preserved_as_unknown_for_validation():
    raw = sketch()
    raw.update(surface="HTTP /diagnostics", candidate_type="任意文件读取")
    parsed = parse_work_result(result(raw), {"e-1": {}})["path_sketches"][0]
    assert (parsed["surface"], parsed["candidate_type"]) == ("other", "unknown")


def test_related_paths_share_one_bounded_validation_packet():
    rows = []
    for number in range(2):
        rows.append({**sketch(), "id": f"probe:path-{number}",
                     "status": "queued_for_validation", "source_id": "probe"})
    packets = build_validation_packets(rows)
    assert len(packets) == 1
    assert packets[0]["path_ids"] == ["probe:path-0", "probe:path-1"]
    assert packets[0]["evidence_ids"] == ["e-1"]


def test_entry_packet_grouping_has_no_recall_cutoff():
    paths = [f"Controller{number}.java" for number in range(35)]
    groups = bounded_path_groups(paths, size=3)
    assert len(groups) == 12
    assert [path for group in groups for path in group] == paths
    assert max(map(len, groups)) == 3


def test_entry_packet_grouping_deduplicates_without_reordering():
    assert bounded_path_groups(["A.java", "B.java", "A.java"]) == [["A.java", "B.java"]]


def test_packet_security_signals_anchor_dangerous_syntax_without_inference():
    signals = packet_security_signals({"e": {"content": (
        'return ResponseEntity.location(uri); JWT.decode(token); '
        'jdbc.executeQuery(sql); produces = MediaType.TEXT_HTML_VALUE;')}})
    assert signals == ["executeQuery", "JWT.decode", "ResponseEntity.location", "MediaType.TEXT_HTML"]


def test_deterministic_sink_inventory_creates_durable_candidates():
    packets = [{"evidence": {"mapper": {
        "relative_path": "src/main/resources/mapper/ProductMapper.xml",
        "content": ('<select id="searchProducts"> ORDER BY ${sortField} </select>'
                    '<select id="listProducts"> ORDER BY ${sortField} </select>'),
    }, "controller": {
        "relative_path": "src/main/java/demo/PageController.java",
        "content": ("produces = MediaType.TEXT_HTML_VALUE\n"
                    "@GetMapping(\"/{accountId}\")\n"
                    "public Object get(@PathVariable String accountId) { return null; }"),
    }, "config": {
        "relative_path": "src/main/resources/application.yml",
        "content": 'management:\n  endpoints:\n    web:\n      exposure:\n        include: "*"\n'
                   'spring:\n  h2:\n    console:\n      enabled: true\n',
    }}}]
    rows = deterministic_sink_sketches(packets)
    assert {(row["candidate_type"], row["deterministic_anchor"]) for row in rows} >= {
        ("sql_injection", "${"), ("xss", "MediaType.TEXT_HTML")}
    assert all(row["status"] == "queued_for_validation" for row in rows)
    assert all(row["origins"] == [{"kind": "heuristic", "producer": "legacy_sink_bootstrap",
                                   "role": "primary", "capability": "bootstrap_hint"}]
               for row in rows)
    assert {row["hops"][0] for row in rows if row["candidate_type"] == "sql_injection"} == {
        "searchProducts", "listProducts"}
    assert any(row["candidate_type"] == "object_level_authorization" for row in rows)
    assert {row["deterministic_anchor"] for row in rows} >= {
        "management-exposure-wildcard", "h2-console-enabled"}
