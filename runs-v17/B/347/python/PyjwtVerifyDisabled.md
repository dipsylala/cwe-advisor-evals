## Verdict
Exploitable

## Source
HTTP request header `Authorization` (line 9): `token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()`

An attacker can supply any forged JWT token in the Authorization header without possessing the signing key.

## Fix

### File: PyjwtVerifyDisabled.py

```python
import jwt
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# Get the signing secret from environment variable
JWT_SECRET = os.environ.get("JWT_SECRET", "default-secret-key")


@app.route("/account", methods=["GET"])
def get_account():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()

    if not token:
        return jsonify({"error": "missing token"}), 401

    try:
        # Enable signature verification with explicit algorithm and secret
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid token"}), 401

    account_id = claims.get("account_id")
    if account_id is None:
        return jsonify({"error": "invalid token"}), 401

    return jsonify({"account_id": account_id, "plan": claims.get("plan", "free")})


if __name__ == "__main__":
    app.run()
```

## Explanation

The original code at line 15 disabled JWT signature verification with `options={"verify_signature": False}`, allowing attackers to forge tokens without possessing the signing key. The fix enables signature verification by:

1. **Removing the `options={"verify_signature": False}` parameter** - this re-enables the default secure behavior
2. **Adding explicit `algorithms=["HS256"]` parameter** - this enforces a single expected algorithm and prevents algorithm-confusion attacks where an attacker could switch algorithms
3. **Providing a signing secret via `JWT_SECRET`** - retrieved from environment configuration, used to verify the HMAC signature

The fixed code now properly validates that incoming tokens were signed with the correct secret key. Any token that doesn't have a valid HMAC signature computed with the same secret will be rejected with an `InvalidTokenError`, which is caught and returned as a 401 error.

## Behaviour changes

**Argument changes:**
- Removed: `options={"verify_signature": False}` - this was bypassing security checks
- Added: Second positional argument `JWT_SECRET` - the key used to verify HMAC signatures
- Added: `algorithms=["HS256"]` - explicitly specifies the only accepted signing algorithm

**Error handling change:**
- Original: `jwt.decode()` with verification disabled would always succeed and return claims (no exception)
- Fixed: `jwt.decode()` now raises `jwt.InvalidTokenError` when signature verification fails, which is caught and returns a 401 error to the client

This is the correct behavior - tokens with invalid signatures must be rejected. The fix preserves the existing HTTP response contract (still returns 401 on invalid token) but now it actually validates tokens instead of accepting any forged token.

**Import additions:**
- Added `import os` to read the `JWT_SECRET` from environment configuration

**Configuration requirement:**
- The application now requires `JWT_SECRET` environment variable to be set at runtime with the key used to sign tokens. A default value is provided for development, but production deployments must set this variable to a strong, randomly-generated secret shared with the token issuer.
