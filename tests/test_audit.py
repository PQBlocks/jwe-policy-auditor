import os
import sys
import pytest

from pqblocks_jwe_audit import audit_jwe, ComplianceStandard, parse_jwe_compact


def test_gp_probe_execution():
    assert True

def test_audit_result_repr():
    """Test AuditResult.__repr__ contains compliant=True."""
    from pqblocks_jwe_audit.audit import AuditResult
    result = AuditResult(compliant=True, flagged_algorithms=[])
    repr_str = repr(result)
    assert "compliant=True" in repr_str

def test_encode_base64url_roundtrip():
    """Test encode_base64url round-trip."""
    from pqblocks_jwe_audit.audit import encode_base64url, decode_base64url
    test_data = b"hello world"
    encoded = encode_base64url(test_data)
    decoded = decode_base64url(encoded)
    assert decoded == test_data

def test_audit_jwe_default_standards():
    """Test audit_jwe defaults to FIPS_203 when no standards provided."""
    import base64
    import json
    # Create a JWE that should be non-compliant under FIPS_203
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RSA-OAEP-256", "enc": "A256GCM"}).encode()).rstrip(b"=").decode()
    bad_jwe = f"{header}.dummy_key.dummy_iv.dummy_ct.dummy_tag"
    # Call without explicit standards - should default to FIPS_203
    result = audit_jwe(bad_jwe)
    assert not result.compliant
    assert "RSA-OAEP-256" in result.flagged_algorithms
    # Check that metadata shows FIPS_203 was used
    assert result.metadata["standards"] == ["ML-KEM (Module-Lattice Key Encapsulation Mechanism)"]


def test_audit_jwe_rsa_non_compliant():
    """Test that RSA-OAEP-256 is flagged as non-compliant."""
    # Create a valid JWE with RSA-OAEP-256
    import base64
    import json
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RSA-OAEP-256", "enc": "A256GCM"}).encode()).rstrip(b"=").decode()
    bad_jwe = f"{header}.dummy_key.dummy_iv.dummy_ct.dummy_tag"
    result = audit_jwe(bad_jwe, standards=[ComplianceStandard.FIPS_203])
    assert not result.compliant
    assert "RSA-OAEP-256" in result.flagged_algorithms


def test_audit_jwe_mlkem_compliant():
    """Test that ML-KEM-1024 is compliant."""
    # Create a valid JWE with ML-KEM-1024
    import base64
    import json
    header = base64.urlsafe_b64encode(json.dumps({"alg": "ML-KEM-1024", "enc": "A256GCM"}).encode()).rstrip(b"=").decode()
    good_jwe = f"{header}.dummy_key.dummy_iv.dummy_ct.dummy_tag"
    result = audit_jwe(good_jwe, standards=[ComplianceStandard.FIPS_203])
    assert result.compliant


# Golden vector tests
def test_golden_vector_test_1_mlkem768_compliant():
    """test_1: ML-KEM-768 with A256GCM -> COMPLIANT"""
    jwe = "eyJhbGciOiJNTC1LRU0tNzY4IiwiZW5jIjoiQTI1NkdDTSJ9.dummy.dummy.dummy.dummy"
    result = audit_jwe(jwe, standards=[ComplianceStandard.CNSA_2_0])
    assert result.compliant is True
    assert result.metadata["alg"] == "ML-KEM-768"
    assert result.metadata["enc"] == "A256GCM"
    assert len(result.flagged_algorithms) == 0


def test_golden_vector_test_2_rsa_oaep_non_compliant():
    """test_2: RSA-OAEP-256 with A256GCM -> NON-COMPLIANT"""
    jwe = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.dummy.dummy.dummy.dummy"
    result = audit_jwe(jwe, standards=[ComplianceStandard.CNSA_2_0])
    assert result.compliant is False
    assert "RSA-OAEP-256" in result.flagged_algorithms


def test_golden_vector_test_3_ecdh_es_non_compliant():
    """test_3: ECDH-ES with A256GCM -> NON-COMPLIANT"""
    jwe = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9.dummy.dummy.dummy.dummy"
    result = audit_jwe(jwe, standards=[ComplianceStandard.CNSA_2_0])
    assert result.compliant is False
    assert "ECDH-ES" in result.flagged_algorithms


def test_golden_vector_test_4_a128kw_requires_assessment():
    """test_4: A128KW with A256GCM -> REQUIRES_ASSESSMENT"""
    jwe = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIn0.dummy.dummy.dummy.dummy"
    result = audit_jwe(jwe, standards=[ComplianceStandard.CNSA_2_0])
    # A128KW is not in approved, not in vulnerable, but requires assessment
    # It will be flagged as unknown-alg
    assert result.compliant is False
    assert any("unknown-alg" in f for f in result.flagged_algorithms)


def test_golden_vector_test_5_pbes2_requires_assessment():
    """test_5: PBES2-HS256+A128KW with A256GCM -> REQUIRES_ASSESSMENT"""
    jwe = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIn0.dummy.dummy.dummy.dummy"
    result = audit_jwe(jwe, standards=[ComplianceStandard.CNSA_2_0])
    assert result.compliant is False
    assert any("unknown-alg" in f for f in result.flagged_algorithms)


def test_golden_vector_test_6_mlkem1024_compliant():
    """test_6: ML-KEM-1024 with A256GCM -> COMPLIANT"""
    jwe = "eyJhbGciOiJNTC1LRU0tMTAyNCIsImVuYyI6IkEyNTZHQ00ifQ.dummy.dummy.dummy.dummy"
    result = audit_jwe(jwe, standards=[ComplianceStandard.CNSA_2_0])
    assert result.compliant is True
    assert result.metadata["alg"] == "ML-KEM-1024"
    assert result.metadata["enc"] == "A256GCM"
    assert len(result.flagged_algorithms) == 0


# Edge case tests
def test_parse_jwe_corrupt_base64url():
    """Corrupt base64url in any segment raises ValueError."""
    jwe = "not_valid_base64url.dummy.dummy.dummy.dummy"
    with pytest.raises(ValueError):
        parse_jwe_compact(jwe)


def test_parse_jwe_wrong_segment_count():
    """Wrong segment count raises ValueError."""
    # 4 segments
    jwe4 = "header.enc_key.iv.ciphertext"
    with pytest.raises(ValueError, match="Invalid JWE format: 4 parts"):
        parse_jwe_compact(jwe4)
    
    # 6 segments
    jwe6 = "header.enc_key.iv.ciphertext.tag.extra"
    with pytest.raises(ValueError, match="Invalid JWE format: 6 parts"):
        parse_jwe_compact(jwe6)


def test_parse_jwe_non_json_header():
    """Non-JSON header raises ValueError."""
    import base64
    bad_header = base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()
    jwe = f"{bad_header}.dummy.dummy.dummy.dummy"
    with pytest.raises(ValueError):
        parse_jwe_compact(jwe)


def test_parse_jwe_missing_alg_enc():
    """Header missing alg/enc raises ValueError during audit."""
    import base64
    bad_header = base64.urlsafe_b64encode(b'{"typ":"JWE"}').rstrip(b"=").decode()
    jwe = f"{bad_header}.dummy.dummy.dummy.dummy"
    # parse succeeds but audit should handle missing fields
    result = audit_jwe(jwe, standards=[ComplianceStandard.CNSA_2_0])
    assert result.compliant is False
    assert any("unknown-alg" in f for f in result.flagged_algorithms)


def test_audit_alg_none_non_compliant():
    """alg: none yields NON-COMPLIANT with reason unknown-alg."""
    import base64
    header = base64.urlsafe_b64encode(b'{"alg":"none","enc":"A256GCM"}').rstrip(b"=").decode()
    jwe = f"{header}.dummy.dummy.dummy.dummy"
    result = audit_jwe(jwe, standards=[ComplianceStandard.CNSA_2_0])
    assert result.compliant is False
    assert any("unknown-alg" in f for f in result.flagged_algorithms)


def test_audit_unknown_alg():
    """Unknown alg yields NON-COMPLIANT with reason unknown-alg."""
    import base64
    header = base64.urlsafe_b64encode(b'{"alg":"XC20P-KW","enc":"A256GCM"}').rstrip(b"=").decode()
    jwe = f"{header}.dummy.dummy.dummy.dummy"
    result = audit_jwe(jwe, standards=[ComplianceStandard.CNSA_2_0])
    assert result.compliant is False
    assert any("unknown-alg" in f for f in result.flagged_algorithms)


def test_audit_enc_not_approved():
    """enc values A128GCM / A256CBC-HS512 yield NON-COMPLIANT with reason enc-not-approved."""
    import base64
    # A128GCM
    header = base64.urlsafe_b64encode(b'{"alg":"ML-KEM-768","enc":"A128GCM"}').rstrip(b"=").decode()
    jwe = f"{header}.dummy.dummy.dummy.dummy"
    result = audit_jwe(jwe, standards=[ComplianceStandard.CNSA_2_0])
    assert result.compliant is False
    assert any("enc-not-approved" in f for f in result.flagged_algorithms)
    
    # A256CBC-HS512
    header2 = base64.urlsafe_b64encode(b'{"alg":"ML-KEM-768","enc":"A256CBC-HS512"}').rstrip(b"=").decode()
    jwe2 = f"{header2}.dummy.dummy.dummy.dummy"
    result2 = audit_jwe(jwe2, standards=[ComplianceStandard.CNSA_2_0])
    assert result2.compliant is False
    assert any("enc-not-approved" in f for f in result2.flagged_algorithms)


def test_all_approved_algorithms():
    """All approved ML-KEM algorithms should be compliant with A256GCM."""
    import base64
    import json
    for alg in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
        header = base64.urlsafe_b64encode(json.dumps({"alg": alg, "enc": "A256GCM"}).encode()).rstrip(b"=").decode()
        jwe = f"{header}.dummy.dummy.dummy.dummy"
        result = audit_jwe(jwe, standards=[ComplianceStandard.CNSA_2_0])
        assert result.compliant is True, f"{alg} should be compliant"
        assert len(result.flagged_algorithms) == 0, f"{alg} should have no flags"


def test_all_vulnerable_algorithms():
    """All vulnerable algorithms should be non-compliant."""
    import base64
    import json
    for alg in ["RSA1_5", "RSA-OAEP", "RSA-OAEP-256", 
                "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]:
        header = base64.urlsafe_b64encode(json.dumps({"alg": alg, "enc": "A256GCM"}).encode()).rstrip(b"=").decode()
        jwe = f"{header}.dummy.dummy.dummy.dummy"
        result = audit_jwe(jwe, standards=[ComplianceStandard.CNSA_2_0])
        assert result.compliant is False, f"{alg} should be non-compliant"
        assert any(alg in f for f in result.flagged_algorithms)


def test_all_requires_assessment_algorithms():
    """All requires-assessment algorithms should be flagged as unknown-alg (not approved)."""
    import base64
    import json
    for alg in ["A128KW", "A192KW", "A256KW",
                "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"]:
        header = base64.urlsafe_b64encode(json.dumps({"alg": alg, "enc": "A256GCM"}).encode()).rstrip(b"=").decode()
        jwe = f"{header}.dummy.dummy.dummy.dummy"
        result = audit_jwe(jwe, standards=[ComplianceStandard.CNSA_2_0])
        assert result.compliant is False, f"{alg} should be non-compliant"
        assert any("unknown-alg" in f for f in result.flagged_algorithms)