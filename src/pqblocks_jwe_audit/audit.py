"""
Audit module for pqblocks-jwe-audit.

This module contains the audit logic for JWE PQC compliance.
"""

from typing import List, Dict, Any, Optional
import base64
import json

from .compliance import (
    QUANTUM_VULNERABLE_ALGORITHMS,
    APPROVED_ALGORITHMS,
    ComplianceStandard,
    get_compliance_standard,
)

class AuditResult:
    """Result of JWE audit."""

    def __init__(
        self,
        compliant: bool,
        flagged_algorithms: List[str],
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.compliant = compliant
        self.flagged_algorithms = flagged_algorithms
        self.metadata = metadata or {}

    def __repr__(self):
        return f"AuditResult(compliant={self.compliant}, flagged={self.flagged_algorithms})"

def decode_base64url(data: str) -> bytes:
    """Decode base64url encoded string."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def encode_base64url(data: bytes) -> str:
    """Encode to base64url string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def parse_jwe_compact(jwe_compact: str) -> Dict[str, Any]:
    """
    Parse JWE compact serialization format.

    Format: base64url(header).base64url(encrypted_key).base64url(iv).base64url(ciphertext).base64url(tag)
    """
    parts = jwe_compact.split(".")
    if len(parts) != 5:
        raise ValueError(f"Invalid JWE format: {len(parts)} parts, expected 5")

    header = json.loads(decode_base64url(parts[0]).decode("utf-8"))

    return {
        "header": header,
        "encrypted_key": parts[1],
        "iv": parts[2],
        "ciphertext": parts[3],
        "tag": parts[4],
    }

def audit_jwe(jwe_compact: str, standards: Optional[List[ComplianceStandard]] = None) -> AuditResult:
    """
    Audit a JWE payload for compliance with CNSA 2.0 and FIPS 203.

    Args:
        jwe_compact: JWE compact serialization string
        standards: List of compliance standards to check against

    Returns:
        AuditResult with compliance status and flagged algorithms
    """
    if standards is None:
        standards = [ComplianceStandard.FIPS_203]

    # Parse JWE
    parsed = parse_jwe_compact(jwe_compact)
    header = parsed["header"]

    alg = header.get("alg", "")
    enc = header.get("enc", "")

    # Check if algorithm is in quantum-vulnerable set
    flagged_algorithms = []
    compliant = True

    # Check alg header (key exchange algorithm)
    if alg:
        alg_upper = alg.upper()
        # Check for RSA-OAEP variants (quantum-vulnerable)
        if "RSA-OAEP" in alg_upper:
            flagged_algorithms.append(alg)
            compliant = False
        # Check for ECDH-ES variants (quantum-vulnerable)
        elif alg.startswith("ECDH-ES"):
            flagged_algorithms.append(alg)
            compliant = False

    # Check against compliance standards
    for standard in standards:
        std_info = get_compliance_standard(standard)
        for alg_flagged in flagged_algorithms:
            if alg_flagged in std_info["quantum_vulnerable_algorithms"]:
                compliant = False

    # Check enc header (content encryption algorithm)
    if enc != "A256GCM":
        compliant = False
        flagged_algorithms.append(f"enc-not-approved: {enc}")

    # Check if alg is in approved algorithms
    if alg not in APPROVED_ALGORITHMS:
        compliant = False
        flagged_algorithms.append(f"unknown-alg: {alg}")

    return AuditResult(
        compliant=compliant,
        flagged_algorithms=flagged_algorithms,
        metadata={
            "alg": alg,
            "enc": enc,
            "standards": [s.value for s in standards],
        },
    )