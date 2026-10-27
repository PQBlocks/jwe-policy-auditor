# pqblocks-jwe-audit

> High-throughput JSON Web Encryption (JWE) cryptographic policy auditor enforcing CNSA 2.0 and NIST FIPS 203 PQC standards.

[![CI](https://github.com/PQBlocks/jwe-policy-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/PQBlocks/jwe-policy-auditor/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## Overview

`pqblocks-jwe-audit` is an ultra-fast, zero-dependency policy enforcement tool for auditing JSON Web Encryption (JWE) structures (RFC 7516) against post-quantum cryptography standards.

It enables API gateways, security proxies, identity providers, and compliance pipelines to inspect incoming and outgoing JWE tokens in microseconds, flagging quantum-vulnerable key exchange algorithms and validating post-quantum compliance.

### Standards Alignment

- **RFC 7516**: JSON Web Encryption (JWE) Compact & JSON Serialization.
- **RFC 7518**: JSON Web Algorithms (JWA).
- **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM-768, ML-KEM-1024).
- **NSA CNSA 2.0**: Commercial National Security Algorithm Suite 2.0 quantum migration timeline and requirements.

> [!WARNING]
> **Non-FIPS Notice**: This library is an independent open-source verification tool. It is not evaluated under FIPS 140-3 and has not undergone CMVP validation. It audits cryptographic headers and does not perform decryption.

---

## Installation

```bash
pip install pqblocks-jwe-audit
```

### Dependencies

Requires Python 3.11+. Pure Python with **zero external dependencies** (`dependencies = []`).

---

## Quickstart

```python
from pqblocks_jwe_audit import audit_jwe, ComplianceStandard

# Inspect an incoming JWE compact token
jwe_token = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.dummy_key.dummy_iv.dummy_ct.dummy_tag"

result = audit_jwe(jwe_token, standards=[ComplianceStandard.CNSA_2_0])

print(f"Compliant: {result.compliant}")
print(f"Flagged Algorithms: {result.flagged_algorithms}")
# Compliant: False
# Flagged Algorithms: ['RSA-OAEP-256']
```

---

## Features

- **Microsecond Policy Auditing**: Audits headers in ~4.15 microseconds (>240,000 evaluations/second).
- **Zero Runtime Dependencies**: Uses Python standard library (`json`, `base64`, `enum`, `typing`).
- **Comprehensive Policy Profiles**: Built-in support for NIST FIPS 203, NSA CNSA 2.0, and strict post-quantum requirements.
- **Fail-Secure Validation**: Rejects malformed headers, unapproved algorithms, and legacy RSA/ECC schemes.

---

## Documentation

- [BENCHMARKS.md](BENCHMARKS.md) - Performance metrics and batch throughput.
- [TESTING.md](TESTING.md) - Test harness details and 100% test coverage.
- [EVIDENCE.md](EVIDENCE.md) - Cryptographic policy and standard references.
- [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) - Multi-python verification log.
- [USE_CASES.md](USE_CASES.md) - Integration recipes for API gateways and microservices.
- [SECURITY_NOTES.md](SECURITY_NOTES.md) - Security scope and parser considerations.
- [AGENTS.md](AGENTS.md) - Automated verification and integration instructions.
- [CHANGELOG.md](CHANGELOG.md) - Release history.

---

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
