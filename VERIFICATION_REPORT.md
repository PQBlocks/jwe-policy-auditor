# Verification Report: pqblocks-jwe-audit

This report documents the verification results across supported Python runtimes.

## Verification Matrix

- **Package**: `pqblocks-jwe-audit`
- **Version**: 0.1.0
- **Test Suite**: 23 automated tests
- **Coverage**: 100% statement coverage (98/98 statements)

| Python Version | Wheel Build | Test Suite | Examples Execution | Gate Status |
|---|---|---|---|---|
| Python 3.11 | PASS | 23 passed | 2 examples passed | **PASS** |
| Python 3.12 | PASS | 23 passed | 2 examples passed | **PASS** |
| Python 3.13 | PASS | 23 passed | 2 examples passed | **PASS** |
| Python 3.14 | PASS | 23 passed | 2 examples passed | **PASS** |

## Executed Examples

1. `examples/quickstart.py`: Validates basic parsing and audit flagging against standard tokens.
2. `examples/02_gateway_policy_audit.py`: Validates simulated API gateway pipeline verifying mixed tokens against CNSA 2.0 and FIPS 203 policies.

## Zero Leaks Verification

Scanned 18 repository files against internal patterns and markers. Result: **0 leak hits**.
