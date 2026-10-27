"""Simulate API Gateway line-rate JWE cryptographic compliance audit."""
import base64
import json
from pqblocks_jwe_audit import audit_jwe, ComplianceStandard

def make_jwe(alg: str, enc: str = "A256GCM") -> str:
    h = base64.urlsafe_b64encode(json.dumps({"alg": alg, "enc": enc}).encode()).rstrip(b"=").decode()
    return f"{h}.encKey.iv.ciphertext.authTag"

def main():
    tokens = [
        ("Quantum-Safe Token (ML-KEM-768)", make_jwe("ML-KEM-768")),
        ("Legacy RSA Token (RSA-OAEP-256)", make_jwe("RSA-OAEP-256")),
        ("Elliptic Curve Token (ECDH-ES+A256KW)", make_jwe("ECDH-ES+A256KW")),
        ("High-Security Quantum Token (ML-KEM-1024)", make_jwe("ML-KEM-1024")),
    ]

    print("Auditing API Gateway Ingress JWE Tokens against CNSA 2.0 & FIPS 203:")
    print("=" * 65)

    for label, tok in tokens:
        res = audit_jwe(tok, standards=[ComplianceStandard.CNSA_2_0])
        status = "PASS" if res.compliant else "VIOLATION"
        print(f"[{status}] {label}")
        if not res.compliant:
            print(f"       -> Flagged Algorithms: {res.flagged_algorithms}")
        else:
            print(f"       -> Compliant under: {res.metadata.get('standards', [])}")

    print("=" * 65)
    print("Gateway JWE policy audit completed successfully.")

if __name__ == "__main__":
    main()
