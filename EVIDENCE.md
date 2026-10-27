# Cryptographic Evidence: pqblocks-jwe-audit

## Normative References

1. **RFC 7516**: JSON Web Encryption (JWE)
   - Section 3: JWE Serialization (Compact & Flattened/General JSON).
   - Section 4: JWE Header Parameters (`alg`, `enc`, `crit`, `zip`).
2. **RFC 7518**: JSON Web Algorithms (JWA)
   - Section 4: Cryptographic Algorithms for Key Management.
3. **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard
   - Parameter sets: ML-KEM-512, ML-KEM-768, ML-KEM-1024.
4. **NSA CNSA 2.0**: Cybersecurity Advisory: Commercial National Security Algorithm Suite 2.0
   - Requires ML-KEM-1024 for National Security Systems (NSS) encryption.

## Classification Policy Matrix

| Algorithm (`alg`) | Vulnerability Classification | FIPS 203 | CNSA 2.0 | Action |
|---|---|---|---|---|
| `RSA1_5` | Broken / Quantum-Vulnerable | Non-Compliant | Prohibited | Flag & Reject |
| `RSA-OAEP` | Quantum-Vulnerable | Non-Compliant | Prohibited | Flag & Reject |
| `RSA-OAEP-256` | Quantum-Vulnerable | Non-Compliant | Prohibited | Flag & Reject |
| `ECDH-ES` | Quantum-Vulnerable | Non-Compliant | Prohibited | Flag & Reject |
| `ECDH-ES+A128KW` | Quantum-Vulnerable | Non-Compliant | Prohibited | Flag & Reject |
| `ECDH-ES+A256KW` | Quantum-Vulnerable | Non-Compliant | Prohibited | Flag & Reject |
| `ML-KEM-768` | Post-Quantum Secure | Compliant | Transitional | Approve |
| `ML-KEM-1024` | Post-Quantum Secure | Compliant | Approved | Approve |
| `X25519-ML-KEM-768` | Hybrid Post-Quantum | Compliant | Transition Only | Approve |
