## Verdict

Exploitable

## Source

The `token` variable at line 24, extracted from the `Authorization` header via `auth_header.removeprefix("Bearer ")`. This is untrusted, attacker-controlled input.

## Fix

**Vulnerable code:**
```python
payload = jwt.decode(token, options={"verify_signature": False})
```

**Fixed code:**
```python
import os

# At module load or config initialization:
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable is required")

# In the wrapper function:
payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
```

## Explanation

The vulnerable code disables JWT signature verification entirely by passing `options={"verify_signature": False}`, allowing an attacker to forge any JWT with arbitrary claims and bypass authentication. The fix re-enables signature verification by:

1. Loading the JWT signing secret from a secure source (environment variable, not hardcoded)
2. Passing the secret and an explicit `algorithms` list to `jwt.decode()`
3. Removing the `verify_signature: False` option

With signature verification enabled, `jwt.decode()` will raise `jwt.InvalidSignatureError` if the token was not signed with the correct secret, or `jwt.InvalidAlgorithmError` if it uses an unexpected algorithm. This ensures only tokens issued and signed by a trusted issuer can be decoded and their claims accepted. The specified algorithm (`HS256` here, an HMAC-based algorithm) must match the algorithm actually used to sign tokens - adjust to the actual issuer's algorithm (e.g., `["RS256"]` for RSA).

## Behaviour changes

None beyond closing the vulnerability. The `jwt.decode()` call still returns the payload dict as before; the contract is preserved. If a token is forged or expired, `jwt.decode()` raises an exception rather than returning a dict - this is correct defensive behaviour and should be handled with appropriate HTTP error responses (e.g., a 401 Unauthorized).
