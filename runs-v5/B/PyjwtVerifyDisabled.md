## Verdict

Exploitable. `jwt.decode(token, options={"verify_signature": False})` accepts the `Authorization` bearer token's claims without checking any signature. Anyone can craft an arbitrary JWT (any header/payload, no valid signature required) and the endpoint will trust its `account_id` and `plan` claims to answer an authenticated account lookup - a full authentication/authorization bypass.

## Source

`request.headers.get("Authorization", ...)` (line 9) - the raw bearer token is attacker-controlled and passed unmodified into `jwt.decode()` at line 15, whose returned `claims` are then used directly to select the account (`account_id`, line 17) and its plan (`plan`, line 21) with no other check.

## Fix

```python
import os

import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

# Load from your existing key/secret store; must match the algorithm the
# issuer actually signs with (HS256 shown as an example - use the real
# algorithm/key type for your token issuer, e.g. an RS256 public key).
JWT_SIGNING_KEY = os.environ["JWT_SIGNING_KEY"]


@app.route("/account", methods=["GET"])
def get_account():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()

    if not token:
        return jsonify({"error": "missing token"}), 401

    try:
        claims = jwt.decode(token, JWT_SIGNING_KEY, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid token"}), 401

    account_id = claims.get("account_id")
    if account_id is None:
        return jsonify({"error": "invalid token"}), 401

    return jsonify({"account_id": account_id, "plan": claims.get("plan", "free")})


if __name__ == "__main__":
    app.run()
```

Vulnerable line being replaced:

```python
# SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
claims = jwt.decode(token, options={"verify_signature": False})
```

## Explanation

The fix removes `options={"verify_signature": False}` and instead calls `jwt.decode()` with the real verification key and an explicit `algorithms=["HS256"]` allowlist (PyJWT rejects the call outright if `algorithms` is omitted or `None`), so the library now cryptographically verifies the token before returning any claims, and the algorithm is fixed by the server rather than read from the token's own header - closing the algorithm-confusion path the same bug class opens. `JWT_SIGNING_KEY` is sourced from server-side configuration/secret storage, never derived from the token itself. Because a forged or tampered token now makes `decode()` raise `jwt.InvalidTokenError` instead of silently returning attacker-supplied claims, the handler wraps the call in a `try/except` and fails closed with `401`, matching the "fail securely on verification errors" principle.

Two items from the language guidance are intentionally not applied here: pinning PyJWT to >= 2.4.0 (CVE-2022-29217) is a dependency-manifest change this single source file cannot express - confirm the installed version via SCA/`pip show pyjwt` before merging; and enforcing `iss`/`aud`/`exp` via `options={"require": [...]}` plus `issuer=`/`audience=` needs the actual expected issuer/audience values, which aren't present anywhere in this file - add them once those values are known rather than guessing.

## Behaviour changes

- Requests bearing a token whose signature doesn't verify (forged, tampered, or signed with the wrong key/algorithm) now get `401 {"error": "invalid token"}` instead of being processed with the token's claims trusted as-is. This is the intended effect of closing the weakness, not a side effect.
- A `try/except` around `jwt.decode()` was added. It is required, not incidental: with verification enabled, an invalid signature raises rather than returning falsified claims, and without the handler the request would fall through to Flask's default 500 error instead of the endpoint's normal 401 failure response.
- `JWT_SIGNING_KEY` (real key material) and an explicit `algorithms=["HS256"]` were introduced because `jwt.decode()` cannot verify a signature without both; PyJWT also raises immediately if `algorithms` is omitted. The concrete algorithm/key-loading mechanism is an assumption (see below) and must be matched to how this service's tokens are actually issued.
- No change to the success-path response shape or the `plan` default of `"free"`.

Assumption: the actual signing key and algorithm the token issuer uses aren't visible in this single-file case, so `HS256` with a key read from `os.environ["JWT_SIGNING_KEY"]` is used as an illustrative, minimal placeholder for "a real, server-controlled verification key of the correct type" - swap in the project's actual key source/algorithm (e.g. an RS256/ES256 public key loaded via `cryptography` or fetched from a JWKS by `kid`) before merging.
