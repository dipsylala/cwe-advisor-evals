## Verdict

Exploitable. CWE-287 (Improper Authentication) at `account_api.py:28`.

## Source

The `Authorization` request header (`request.headers.get("Authorization", "")`), read in `require_bearer_token.wrapper` at line 20 and stripped of its `Bearer ` prefix at line 24 to produce `token`. This value is fully attacker-controlled - any caller can send any string as the header.

## Fix

### File: account_api.py

```python
"""Flask API for account self-service actions, gated by a bearer-token middleware."""

import os
from functools import wraps

import jwt
from flask import Blueprint, Flask, g, jsonify, request

app = Flask(__name__)
account_api = Blueprint("account_api", __name__)

# Signing secret for the tokens this API accepts; provisioned by the deployment
# environment, never hard-coded.
JWT_SECRET_KEY = os.environ["JWT_SECRET_KEY"]


def require_bearer_token(view_func):
    """Decode the caller's bearer token and stash the identified user on `g`.

    PyJWT 2.8.0.
    """

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "missing bearer token"}), 401

        token = auth_header.removeprefix("Bearer ")
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        except jwt.PyJWTError:
            return jsonify({"error": "invalid bearer token"}), 401
        g.current_user_id = payload["user_id"]
        return view_func(*args, **kwargs)

    return wrapper


@account_api.route("/account/close", methods=["POST"])
@require_bearer_token
def close_account():
    """Permanently close the authenticated caller's account."""
    user_id = g.current_user_id
    _mark_account_closed(user_id)
    return jsonify({"status": "closed", "user_id": user_id})


def _mark_account_closed(user_id):
    # Application-specific persistence omitted for brevity.
    pass


app.register_blueprint(account_api)
```

## Explanation

The token from the `Authorization` header reached `jwt.decode()` with `options={"verify_signature": False}`, which skips signature verification entirely - PyJWT decodes and returns the claims of any syntactically valid JWT regardless of who signed it or whether it was signed at all. An attacker can therefore mint a token with an arbitrary `user_id` claim and self-authenticate as any account, then hit `POST /account/close` to close it. The fix removes the `options` override and calls `jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])`, which requires a valid HMAC-SHA256 signature produced with the server's own secret before any claim is trusted, and pins the algorithm so an attacker cannot switch to `none` or another algorithm to bypass verification. The secret is sourced from the `JWT_SECRET_KEY` environment variable rather than hard-coded, per the project's key-management guidance. Because `jwt.decode()` now raises on a missing, expired, or forged signature, the call is wrapped in `try/except jwt.PyJWTError` so those cases fail closed with `401` instead of propagating as an unhandled exception (a `500`), matching the existing 401-on-missing-token behavior in the same function. `payload["user_id"]` is still read only from this single, now-verified decode - the request has no other decode call to leave un-broken.

## Behaviour changes

- Added `algorithms=["HS256"]` and the secret-key argument to `jwt.decode()`, replacing the `verify_signature: False` bypass - this is the fix itself, not incidental.
- Added `JWT_SECRET_KEY = os.environ["JWT_SECRET_KEY"]` at module scope: signature verification requires a key, and none existed before. The app now fails to start if this environment variable is unset - intentional fail-closed behavior, not a regression, but it is a new deployment requirement the original code did not have.
- Added a `try/except jwt.PyJWTError` around the decode call, returning `401 {"error": "invalid bearer token"}` on any verification failure (bad signature, expired token, malformed token). The original unverified decode rarely raised for these cases; enabling verification makes them raise, so the except clause is required to preserve "reject bad auth with 401" rather than let the exception surface as a `500`. This new 401 response does not include a `WWW-Authenticate` header, matching the existing missing-token 401 response in the same function, which also omits it.
- **Assumption**: the signing algorithm is HS256 and the key is a shared secret read from `JWT_SECRET_KEY`. The original code and this single file give no indication of the actual issuer, algorithm, or key-distribution mechanism used elsewhere in the application; if the real issuer signs with RS256/ES256 or distributes keys via JWKS, `algorithms` and the key argument must be changed to match the issuer's actual configuration. This lowers confidence in the fix's drop-in correctness even though the vulnerability class and remediation pattern are certain.

## Verification

Ran `python -m py_compile` against the fixed file in a scratch copy - no errors. Installed PyJWT 2.8.0 and Flask into a scratch environment, imported the fixed module, and exercised it with Flask's test client: a token signed with the matching secret (`jwt.encode({"user_id": 42}, "test-secret", algorithm="HS256")`) returned `200 {"status": "closed", "user_id": 42}`; the same claims signed with a different secret returned `401 {"error": "invalid bearer token"}`, confirming forged/mis-signed tokens are now rejected rather than accepted. Also confirmed `jwt.PyJWTError` is a real, importable symbol in installed PyJWT 2.8.0 (`jwt.exceptions.PyJWTError`, re-exported as `jwt.PyJWTError`).
