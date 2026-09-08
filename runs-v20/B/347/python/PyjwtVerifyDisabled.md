## Verdict

exploitable

- cwe_id: CWE-347
- location: `PyjwtVerifyDisabled.py`, line 15 (`jwt.decode(token, options={"verify_signature": False})`)
- confidence: high

## Source

The `Authorization` request header, read at line 9 (`request.headers.get("Authorization", "").removeprefix("Bearer ").strip()`). This is fully attacker-controlled network input reaching a Flask route handler with no prior authentication.

## Fix

### File: PyjwtVerifyDisabled.py

```python
import os

import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"


@app.route("/account", methods=["GET"])
def get_account():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()

    if not token:
        return jsonify({"error": "missing token"}), 401

    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
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

The sink at line 15 called `jwt.decode()` with `options={"verify_signature": False}`, which disables PyJWT's cryptographic signature check entirely (and, per PyJWT's own behaviour, disables the other `verify_*` checks such as expiry along with it). Any caller can therefore submit a token with an arbitrary, unsigned or garbage-signed payload - including `account_id` - and have it accepted as authentic, giving full impersonation of any account. The fix removes the `verify_signature: False` override and instead calls `jwt.decode(token, JWT_SECRET, algorithms=["HS256"])`, which restores mandatory signature verification, pins the algorithm to a single explicit value (never derived from the token's own header, closing the algorithm-confusion path the guidance warns about), and re-enables PyJWT's default expiry check. Because a verifying `decode()` call now raises on a forged, tampered, or expired token instead of silently accepting it, the call is wrapped in `try/except jwt.InvalidTokenError` (PyJWT's common base class for signature, expiry, and decode failures) so those tokens are rejected with a 401 rather than surfacing as an unhandled exception, matching the guidance's "fail securely on verification errors" principle.

## Behaviour changes

- **Verification key introduced (`JWT_SECRET` from `os.environ["JWT_SECRET"]`)**: the original call passed no key at all (verification was off). A verifying `decode()` call requires one; since the snippet has no existing key-management code, the fix loads a shared HMAC secret from a required environment variable. This is a genuinely new operational requirement - the deployment must supply `JWT_SECRET` - not something the original code needed, and it is called out here as an assumption below.
- **Algorithm choice fixed to `HS256`**: nothing in the original file indicates whether tokens are meant to be symmetric (HS256) or asymmetric (RS256/ES256). HS256 with a shared secret was chosen as the minimal scheme consistent with the file's flat, dependency-free structure; if the issuer actually signs with an asymmetric key, `JWT_ALGORITHM`/`JWT_SECRET` must be changed to the corresponding public key and algorithm instead.
- **New exception handling (`try/except jwt.InvalidTokenError`)**: required because a verifying `decode()` raises on invalid signature, expired token, or malformed structure, where the disabled-verification version would not raise for the first two. Mapped to the same `401 {"error": "invalid token"}` response the function already returns for a missing/invalid-claims token, so the external behaviour on bad input is consistent with the existing error contract rather than a new one.
- Return values, response shape, and the downstream handling of `claims.get("account_id")` / `claims.get("plan", "free")` are unchanged.

## Verification

Ran `python -m py_compile` against the fixed file copied to a scratch location outside the repository - compiled with no errors. `os` is a standard-library import. `jwt.decode`, `jwt.InvalidTokenError` (PyJWT's base decode-error class, aliasing `jwt.exceptions.InvalidTokenError`), and the `algorithms=` keyword are all part of PyJWT's public `decode()` API per the loaded language guidance; no PyJWT installation was available in this environment to additionally import-check the module, so that check was not run.

## Assumptions

- No key-management, config, or secret-loading code exists elsewhere in this single-file case, so the signing scheme (HS256, shared secret from `JWT_SECRET`) was chosen as the minimal addition consistent with the file's structure rather than derived from the codebase. If the real issuer uses RS256/ES256, the key material and `JWT_ALGORITHM` need to be swapped for the corresponding public key. Confidence is lowered to reflect this assumption.
