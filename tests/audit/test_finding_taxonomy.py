"""分类编号严格校验，纠错只返回固定格式说明。"""

import pytest

from secval.models.audit_contracts import ModelOutputError
from secval.models.finding_detail import parse_finding_detail


@pytest.mark.parametrize("value", [[20], [{"id": "CWE-20"}], ["20"], "CWE-20", ["CWE-20", "CWE-20"]])
def test_taxonomy_error_explains_string_format(value):
    from secval.models.finding_detail import FIELDS

    detail = dict.fromkeys(FIELDS, "placeholder")
    detail.update(investigation_id="investigation-1", ruleId="test-rule",
                  taxonomy={"category": "test", "cwe": value})
    with pytest.raises(ModelOutputError, match="taxonomy.cwe") as caught:
        parse_finding_detail(detail, [{"id": "investigation-1"}], {})
    assert '"CWE-20"' in str(caught.value)
    assert "不是数字或对象" in str(caught.value)
