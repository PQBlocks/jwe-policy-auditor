from pqblocks_jwe_audit import audit_jwe

token = "eyJhbGciOiJNTC1LRU0tNzY4IiwiZW5jIjoiQTI1NkdDTSJ9.AAAA.BBBB.CCCC.DDDD"
res = audit_jwe(token)
print(f"Compliant: {res.compliant}, Flags: {res.flagged_algorithms}")
