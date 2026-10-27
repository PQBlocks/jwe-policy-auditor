# Testing: pqblocks-jwe-audit

## Test Suite Overview

`pqblocks-jwe-audit` includes comprehensive automated tests covering parsing, standards compliance, malicious inputs, and edge cases.

### Test Execution

Run the suite using pytest:

```bash
pytest -v
```

With coverage measurement:

```bash
pytest --cov=pqblocks_jwe_audit --cov-report=term-missing
```

## Coverage Report

The test suite achieves **100% statement coverage** across all source files:

| Module | Statements | Missing | Coverage |
|---|---|---|---|
| `pqblocks_jwe_audit/__init__.py` | 5 | 0 | **100%** |
| `pqblocks_jwe_audit/audit.py` | 51 | 0 | **100%** |
| `pqblocks_jwe_audit/compliance.py` | 13 | 0 | **100%** |
| `pqblocks_jwe_audit/probe.py` | 29 | 0 | **100%** |
| **Total** | **98** | **0** | **100%** |

## Test Scenarios Covered

1. **RFC 7516 Compact Parsing**:
   - Proper extraction of 5-part JWE tokens (`header.encrypted_key.iv.ciphertext.tag`).
   - Rejection of invalid dot counts (e.g. 3 parts, 4 parts, 6 parts).
   - Rejection of non-base64url characters.
   - Non-JSON header payloads.

2. **Cryptographic Algorithm Auditing**:
   - Quantum-vulnerable algorithms flagged: `RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256`, `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`.
   - Post-quantum compliant algorithms approved: `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`, `X25519-ML-KEM-768`.
   - Strict standards enforcement: NIST FIPS 203, NSA CNSA 2.0.

3. **Error Handling & Fail-Safe Defaults**:
   - Missing `alg` or `enc` parameters.
   - Empty headers.
   - Malformed base64url padding.
