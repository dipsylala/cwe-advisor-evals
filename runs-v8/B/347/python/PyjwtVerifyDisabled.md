## Verdict

Exploitable. The code explicitly disables JWT signature verification with `options={"verify_signature": False}`, allowing an attacker to forge arbitrary JWT tokens and bypass authentication.

## Source

Attacker-controlled token from HTTP Authorization header, line 9:
```python
token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
```

## Fix

**Vulnerable code (line 15):**
```python
claims = jwt.decode(token, options={"verify_signature": False})
```

**Fixed code:**
```python
import os

# Obtain the secret key from secure configuration (environment variable)
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")

if not SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY must be set in environment")

@app.route("/account", methods=["GET"])
def get_account():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()

    if not token:
        return jsonify({"error": "missing token"}), 401

    try:
        # Always verify the signature with an explicit algorithm and secret key
        claims = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.InvalidTokenError as e:
        return jsonify({"error": "invalid token"}), 401

    account_id = claims.get("account_id")
    if account_id is None:
        return jsonify({"error": "invalid token"}), 401

    return jsonify({"account_id": account_id, "plan": claims.get("plan", "free")})
```

## Explanation

The fix removes `options={"verify_signature": False}` and replaces it with mandatory signature verification. The secret key is obtained from secure configuration (environment variable), never from the token itself. The `algorithms` parameter is pinned to `["HS256"]` (the single expected algorithm) to prevent algorithm-confusion attacks where an attacker signs with a different algorithm. PyJWT 2.0.0+ requires an explicit algorithms list and raises if it is omitted. Error handling is improved to catch and reject invalid tokens explicitly. This ensures only tokens signed by the server with the correct algorithm and secret can be decoded, closing the signature verification weakness.

## Behaviour changes

- **Added `SECRET_KEY` parameter**: Required by `jwt.decode()` to perform HMAC signature verification; was omitted in the original, allowing any token to be accepted.
- **Added `algorithms=["HS256"]` parameter**: Mandatory in PyJWT 2.0.0+; pins the expected algorithm to prevent an attacker from switching to a weaker or "none" algorithm; the original left this unspecified.
- **Removed `options={"verify_signature": False}`**: This debug-mode option disabled verification entirely; removal re-enables it.
- **Added try/except for jwt.InvalidTokenError**: Catches decoding failures (invalid signature, malformed token, expired token) and rejects them with a 401 response; the original had no error handling for the decode call, which would raise an unhandled exception.
- **Assumption**: The secret key is obtained from environment variable `JWT_SECRET_KEY`. This assumes a symmetric (HS256) JWT scheme. If the application uses asymmetric keys (RS256 with a public key from JWKS), the fix would instead load the public key from the configured source and set `algorithms=["RS256"]`.
