# Changelog: pqblocks-jwe-audit

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-26

### Added
- Initial public release of `pqblocks-jwe-audit`.
- High-throughput JWE compact protected header parser (`parse_jwe_compact`).
- PQC compliance auditor (`audit_jwe`) supporting NIST FIPS 203 and NSA CNSA 2.0 standards.
- Detection of classical/quantum-vulnerable algorithms (RSA, ECDH, ECDSA).
- Recognition of post-quantum algorithms (ML-KEM-512, ML-KEM-768, ML-KEM-1024, X25519-ML-KEM-768).
- Complete documentation suite, verified examples, and automated test harness with 100% statement coverage.
