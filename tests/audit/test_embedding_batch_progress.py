"""Embedding 批次进度回调与 WAF 403 降级重试。"""

from secval.infrastructure.embedding.api_embedding_model import (
    ApiEmbeddingModel,
    EmbeddingApiHttpError,
)


class FlakyApi(ApiEmbeddingModel):
    """遇到WAF特征文本返回403；记录每次请求的输入。"""

    def __init__(self):
        super().__init__("https://example.test/v1/", "k", "m", 2)
        self.calls = []

    def _request_vectors(self, texts):
        self.calls.append(list(texts))
        joined = chr(10).join(texts)
        if "etc-passwd-marker" in joined:
            raise EmbeddingApiHttpError(403, "waf")
        return [[1.0, 0.0] for _ in texts]


TRIGGER = "path etc-passwd-marker leak"


def test_403_stops_without_modifying_or_resending_source():
    import pytest
    model = FlakyApi()
    texts = ["safe code one", TRIGGER, "safe code two"]
    with pytest.raises(EmbeddingApiHttpError):
        model.embed_code(texts)
    assert model.calls == [texts]


def test_cancellation_before_request():
    import pytest
    model = FlakyApi()
    def cancel(done, total):
        raise RuntimeError("cancelled")
    with pytest.raises(RuntimeError, match="cancelled"):
        model.embed_code(["safe"], progress=cancel)
    assert model.calls == []


def test_progress_reports_each_batch():
    model = FlakyApi()
    progress = []
    model.embed_code(
        ["a", "b", "c", "d", "e"],
        progress=lambda d, t: progress.append((d, t)),
    )
    assert progress[-1] == (5, 5)
    assert all(done <= total for done, total in progress)


def test_preflight_has_short_timeout_and_single_attempt(monkeypatch):
    from urllib.error import URLError
    import pytest
    import secval.infrastructure.embedding.api_embedding_model as module
    calls = []
    def unavailable(request, timeout):
        calls.append(timeout)
        raise URLError("offline")
    monkeypatch.setattr(module, "urlopen", unavailable)
    model = ApiEmbeddingModel("https://example.test/v1", "key", "model", 2)
    with pytest.raises(ValueError, match="请求失败"):
        model.preflight()
    assert calls == [8]
