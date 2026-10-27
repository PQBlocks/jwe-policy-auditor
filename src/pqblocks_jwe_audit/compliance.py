"""
Compliance standards for JWE PQC audit tools.
"""

from enum import Enum
from typing import List, Dict, Any, Set


class ComplianceStandard(Enum):
    """FIPS 203/204/205 compliance standards."""

    FIPS_203 = "ML-KEM (Module-Lattice Key Encapsulation Mechanism)"
    FIPS_204 = "ML-DSA (Module-Lattice Digital Signature Algorithm)"
    FIPS_205 = "SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)"
    CNSA_2_0 = "CNSA 2.0 (Commercial National Security Algorithm Suite 2.0)"


# Quantum-vulnerable algorithms (must be flagged under CNSA 2.0)
QUANTUM_VULNERABLE_ALGORITHMS: Set[str] = {
    "RSA1_5",
    "RSA-OAEP",
    "RSA-OAEP-256",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
}

# Approved algorithms (post-quantum) for CNSA 2.0
APPROVED_ALGORITHMS: Set[str] = {
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
}

# Algorithms requiring assessment (symmetric / password-based wrap)
REQUIRES_ASSESSMENT_ALGORITHMS: Set[str] = {
    "A128KW",
    "A192KW",
    "A256KW",
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW",
}


def get_compliance_standard(
    standard: ComplianceStandard,
) -> Dict[str, Any]:
    """Get compliance standard definition."""
    return {
        "name": standard.value,
        "quantum_vulnerable_algorithms": QUANTUM_VULNERABLE_ALGORITHMS,
        "approved_algorithms": APPROVED_ALGORITHMS,
        "requires_assessment_algorithms": REQUIRES_ASSESSMENT_ALGORITHMS,
    }


__all__ = [
    "ComplianceStandard",
    "get_compliance_standard",
]