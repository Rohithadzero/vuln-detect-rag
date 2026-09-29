import pytest

from scanners.base import ScannerAdapter
from services.orchestrator import SCANNER_MAP


@pytest.mark.parametrize("name", sorted(SCANNER_MAP))
def test_adapters_have_no_mock_generators(name):
    assert not hasattr(SCANNER_MAP[name], "_mock_scan")


def test_no_result_note_is_info_and_not_simulated():
    class Dummy(ScannerAdapter):
        name = "dummy"

        def scan(self, target):
            return self._no_result(target)

        def is_available(self):
            return False

    findings = Dummy().scan("example.com")
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].cve_id is None
    assert findings[0].raw_output["type"] == "not_installed"
