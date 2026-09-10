import pytest

from secval.models.candidate_provenance import (
    append_candidate_origin,
    can_confirm_from_origins,
    candidate_origin,
)


def test_heuristic_and_model_sources_are_bootstrap_only():
    heuristic = candidate_origin("heuristic", "legacy", capability="bootstrap_hint")
    model = candidate_origin("model", "probe", capability="bootstrap_hint")
    candidate = append_candidate_origin(append_candidate_origin({}, heuristic), model)
    assert not can_confirm_from_origins(candidate)


def test_graph_evidence_can_support_adjudication():
    candidate = append_candidate_origin({}, candidate_origin("graph", "joern-cpg"))
    assert can_confirm_from_origins(candidate)


@pytest.mark.parametrize("kind", ["heuristic", "model"])
def test_inference_sources_cannot_claim_evidence_capability(kind):
    with pytest.raises(ValueError):
        candidate_origin(kind, "producer")


def test_duplicate_origin_is_stable():
    origin = candidate_origin("external", "scanner")
    candidate = append_candidate_origin(append_candidate_origin({}, origin), origin)
    assert candidate["origins"] == [origin]
