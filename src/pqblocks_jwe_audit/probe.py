"""Verification probe module for pqblocks-jwe-audit."""
import base64
import json
from .audit import audit_jwe, AuditResult, ComplianceStandard


def _create_test_jwe(alg: str) -> str:
    """Create a minimal valid JWE compact format for testing."""
    header = {"alg": alg, "enc": "A256GCM"}
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).rstrip(b"=").decode()
    # Minimal JWE: header.encrypted_key.iv.ciphertext.tag
    return f"{header_b64}.dummy_key.dummy_iv.dummy_ct.dummy_tag"


def run_probe() -> bool:
    """Run verification probe tests."""
    print("Probe: Testing JWE audit functionality...")
    
    # Test 1: Non-compliant JWE (RSA-OAEP-256)
    bad_jwe = _create_test_jwe("RSA-OAEP-256")
    print(f"  Testing: {bad_jwe[:50]}...")
    result = audit_jwe(bad_jwe, standards=[ComplianceStandard.FIPS_203])
    print(f"  Result: compliant={result.compliant}, flagged={result.flagged_algorithms}")
    assert not result.compliant, "Test 1 failed: RSA-OAEP should be non-compliant"
    assert "RSA-OAEP-256" in result.flagged_algorithms, "Test 1 failed: RSA-OAEP not flagged"
    print("  Test 1 (RSA-OAEP): Non-compliant detected correctly")
    
    # Test 2: Non-compliant JWE (ECDH-ES)
    bad_jwe2 = _create_test_jwe("ECDH-ES+A256KW")
    result2 = audit_jwe(bad_jwe2, standards=[ComplianceStandard.FIPS_203])
    print(f"  Result: compliant={result2.compliant}, flagged={result2.flagged_algorithms}")
    assert not result2.compliant, "Test 2 failed: ECDH-ES should be non-compliant"
    assert "ECDH-ES+A256KW" in result2.flagged_algorithms, "Test 2 failed: ECDH-ES not flagged"
    print("  Test 2 (ECDH-ES): Non-compliant detected correctly")
    
    # Test 3: Compliant JWE (ML-KEM)
    good_jwe = _create_test_jwe("ML-KEM-1024")
    result3 = audit_jwe(good_jwe, standards=[ComplianceStandard.FIPS_203])
    print(f"  Result: compliant={result3.compliant}, flagged={result3.flagged_algorithms}")
    assert result3.compliant, "Test 3 failed: ML-KEM should be compliant"
    print("  Test 3 (ML-KEM): Compliant detected correctly")
    
    print("Probe: PASS")
    return True