# Security Notes: pqblocks-jwe-audit

## Scope of Operation

`pqblocks-jwe-audit` is a **static header inspector and cryptographic compliance auditor**.

- **No Cryptographic Decryption**: This package does not decrypt ciphertext or parse secret keys.
- **Header Parsing**: The library inspects the first segment of compact JWE structures (`JOSE Protected Header`).
- **Cryptographic Assurance**: Compliant algorithm flags indicate that the declared algorithm matches standard identifiers. The library does not verify whether the ciphertext or encapsulated key was properly formed.

## Defensive Parsing

1. **Header Size Limits**: Base64url decoders handle variable length headers safely using standard library implementations.
2. **Malformed Input Rejection**: Inputs without exactly 5 dot-separated segments or with invalid base64url characters are rejected with explicit `ValueError` exceptions.
3. **No Dynamic Execution**: Parsing is restricted strictly to `json.loads` without custom deserializers or unsafe reflection.

## Standards & Disclaimers

> [!NOTE]
> This software is not certified under NIST FIPS 140-3 or CMVP. It serves as an automated verification check against post-quantum algorithm identifiers.
