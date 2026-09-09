"""Formal findings are merged after every candidate source passes review."""

from secval.services.finding_report import _deduplicate_findings


def finding(entry, candidate):
    return {
        "ruleId": "ssrf", "title": f"ssrf：{entry}",
        "attackPath": {"reachability": {"entrypoint": entry},
                       "dataflow": {"sink": "ResourceSyncService httpClient.send"}},
        "rootControlLocation": {"path": "ResourceSyncService.java"},
        "provenance": {"candidateId": candidate},
        "codeEvidence": [{"id": "e-" + candidate}],
    }


def test_same_route_and_sink_merge_across_candidate_sources():
    rows = _deduplicate_findings([
        finding("GET /api/integrations/preview", "deterministic"),
        finding("GET /api/integrations/preview", "worker"),
    ])
    assert len(rows) == 1
    assert rows[0]["provenance"]["candidateIds"] == ["deterministic", "worker"]
    assert rows[0]["mergedOccurrences"] == 2
    assert len(rows[0]["codeEvidence"]) == 2


def test_query_examples_and_different_chain_hops_still_merge_by_endpoint():
    first = finding("GET /api/navigation/continue?next=<external>", "controller")
    first["attackPath"]["dataflow"]["sink"] = "ResponseEntity.location"
    second = finding("GET /api/navigation/continue?next=", "service")
    second["attackPath"]["dataflow"]["sink"] = "HTTP 302 Location header"
    assert len(_deduplicate_findings([first, second])) == 1


def test_consolidated_route_merges_transitively_with_individual_routes():
    rows = _deduplicate_findings([
        finding("GET /one", "one"),
        finding("GET /one、POST /two", "both"),
        finding("POST /two", "two"),
    ])
    assert len(rows) == 1
    assert rows[0]["mergedOccurrences"] == 3


def test_different_routes_remain_separate():
    assert len(_deduplicate_findings([
        finding("GET /one", "one"), finding("POST /two", "two")])) == 2
