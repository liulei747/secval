"""正式Web验收包只能包含合成代码，不能夹带预期答案。"""

import io
import zipfile

import pytest

from benchmarks.audit_quality.cases import CASES, model_input
from benchmarks.audit_quality.run_web_check import archive_bytes, collect


@pytest.mark.parametrize("case", CASES)
def test_archive_only_contains_fixture_source(case):
    with zipfile.ZipFile(io.BytesIO(archive_bytes(case))) as archive:
        sources = model_input(case)["files"]
        assert set(archive.namelist()) == set(sources)
        for path, content in sources.items():
            assert archive.read(path).decode("utf-8") == content


def test_collector_rejects_arbitrary_directory():
    with pytest.raises(ValueError):
        collect("src")
