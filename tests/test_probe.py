import pytest
from pqblocks_jwe_audit.probe import run_probe

def test_probe_execution():
    """Test that the probe runs successfully and passes all test cases."""
    result = run_probe()
    assert result is True, "Probe should return True when all tests pass"

if __name__ == "__main__":
    pytest.main([__file__])