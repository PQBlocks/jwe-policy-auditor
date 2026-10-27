# Agents Guide: pqblocks-jwe-audit

This guide provides automated agents and scripts with machine-readable instructions for testing and maintaining `pqblocks-jwe-audit`.

## Quick Validation

```bash
# Run test suite
pytest -v

# Check coverage
pytest --cov=pqblocks_jwe_audit --cov-fail-under=95

# Run examples
python examples/quickstart.py
python examples/02_gateway_policy_audit.py
```

## Maintenance Rules

- **Zero External Dependencies**: Keep `dependencies = []` in `pyproject.toml`.
- **Public API**: Export public symbols via `pqblocks_jwe_audit.__all__`:
  - `audit_jwe`
  - `AuditResult`
  - `parse_jwe_compact`
  - `decode_base64url`
  - `ComplianceStandard`
  - `get_compliance_standard`
- **Error Handling**: Fail-safe with `ValueError` on malformed compact structures.
