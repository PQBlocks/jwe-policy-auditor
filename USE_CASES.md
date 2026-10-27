# Use Cases: pqblocks-jwe-audit

`pqblocks-jwe-audit` is designed for seamless integration into production token processing pipelines.

## 1. API Gateway Ingress Filter

Enforce quantum-resistant encryption tokens before forwarding requests to backend microservices:

```python
from pqblocks_jwe_audit import audit_jwe, ComplianceStandard

def gateway_jwe_middleware(request_headers: dict) -> bool:
    auth_header = request_headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return True
    
    token = auth_header.split(" ", 1)[1]
    # Quick dot check to identify if it is a compact JWE (5 parts)
    if token.count(".") == 4:
        result = audit_jwe(token, standards=[ComplianceStandard.CNSA_2_0])
        if not result.compliant:
            # Reject non-compliant legacy RSA/ECDH tokens
            return False
    return True
```

## 2. Cryptographic Inventory & Audit Logging

Log token algorithm distributions to track post-quantum migration progress:

```python
from pqblocks_jwe_audit import parse_jwe_compact

def log_token_telemetry(token: str):
    try:
        header = parse_jwe_compact(token)
        alg = header.get("alg")
        enc = header.get("enc")
        # Send metric to monitoring system
        print(f"TELEMETRY: jwe_key_mgmt={alg} jwe_content_enc={enc}")
    except ValueError:
        pass
```

## 3. Pre-Commit CI/CD Security Gate

Scan test fixtures and mock authentication tokens in repository trees to prevent committing quantum-vulnerable configurations.
