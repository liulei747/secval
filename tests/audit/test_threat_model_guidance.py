"""纠错提示指出具体字段，并提供能通过同一解析器的JSON结构示例。"""

import json
import pytest

from secval.models.audit_contracts import ModelOutputError
from secval.models.threat_model import ThreatModel
from secval.services.audit_runner import SYSTEM


def example():
    line = next(line for line in SYSTEM.splitlines() if line.startswith("record_threat_model参数结构示例："))
    return json.loads(line.split("：", 1)[1].removesuffix("。"))


def test_complete_example_matches_parser():
    parsed = ThreatModel.parse(example(), [], {})
    assert parsed.summary["origin"] == "unknown"


@pytest.mark.parametrize("field", ["summary", "assets"])
def test_error_names_field_without_echoing_model_text(field):
    data = example()
    data[field] = "private text" if field == "summary" else ["private text"]
    with pytest.raises(ModelOutputError) as caught:
        ThreatModel.parse(data, [], {})
    assert field in str(caught.value)
    assert "private text" not in str(caught.value)
