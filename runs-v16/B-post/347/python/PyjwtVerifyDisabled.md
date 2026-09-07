## Verdict

Exploitable

## Source

Untrusted token from `request.headers.get("Authorization", "").removeprefix("Bearer ").strip()` at line 9

## Fix

**Vulnerable code (line 15):**
```python
claims = jwt.decode(token, options={"verify_signature": False})
```

**Fixed code:**
```python
import os
import jwt

# Load secret from environment or configuration
secret = os.getenv("JWT_SECRET")
if not secret:
    return jsonify({"error": "JWT secret not configured"}), 500

# Decode with signature verification enabled
try:
    claims = jwt.decode(token, secret, algorithms=["HS256"], options={"require": ["exp"]})
except jwt.InvalidTokenError:
    return jsonify({"error": "invalid token"}), 401
```

## Explanation

The original code explicitly disables signature verification with `options={"verify_signature": False}`, allowing any JWT token to be accepted without cryptographic validation. This enables attackers to forge tokens and bypass authentication. The fix removes this dangerous option, adds the required `algorithms` parameter (set to the expected algorithm, `["HS256"]` here), and passes the verification secret to `jwt.decode()`. The secret must be loaded from a secure configuration source (environment variable or secure store), never from the token itself. The `options={"require": ["exp"]}` ensures expiration validation is enforced. Error handling is added to reject malformed or expired tokens. PyJWT 2.4.0+ is required to prevent algorithm confusion attacks (CVE-2022-29217), where SSH-formatted keys could be misused as HMAC secrets.

## Behaviour changes

- **Added `algorithms=["HS256"]` argument**: Ensures only the expected algorithm is accepted, preventing algorithm confusion attacks where an attacker could switch to a weaker algorithm or use the public key as an HMAC secret.
- **Added `secret` parameter**: The decode() call now requires the correct signing secret, which the original omitted by relying on verification being disabled. Without the correct secret, forged tokens are rejected.
- **Added error handling with `try/except`**: The original code did not catch `jwt.InvalidTokenError` exceptions, so expired or malformed tokens would raise uncaught exceptions. The fix returns a 401 response for invalid tokens, matching the existing error-handling pattern in the code.
- **Added `options={"require": ["exp"]}`**: Enforces that tokens must include an expiration claim, preventing indefinitely-lived tokens and mitigating token-reuse attacks.
- **Added environment-variable loading**: The secret is now external to the code, improving security and configuration management. Failure to configure a secret returns a 500 error rather than silently accepting any token.

