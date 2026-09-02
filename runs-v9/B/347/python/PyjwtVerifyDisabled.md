## Verdict

- CWE-347 (Improper Verification of Cryptographic Signature) - **exploitable**
- Location: `PyjwtVerifyDisabled.py:15`, inside `get_account()`
- Confidence: high (trace is direct, no intervening validation)

## Source

`request.headers.get("Authorization", "").removeprefix("Bearer ").strip()` (line 9) - fully attacker-controlled bearer token. It flows unmodified into the sink at line 15 with no signature check in between; the only guard on the path (line 11) rejects an empty string, not an unsigned or forged one.

Sink: `jwt.decode(token, options={"verify_signature": False})`. This disables signature verification entirely, so PyJWT accepts any syntactically valid JWT (including one with `alg: none` or an arbitrary self-signed header/payload) and returns its claims as trusted. `account_id` (line 17) and `plan` (line 21) are taken directly from those unverified claims and used to answer the request - an attacker can mint a token with any `account_id` and read any account's data.

## Fix

**Library recommendation:** PyJWT >= 2.4.0 (fixes CVE-2022-29217 / GHSA-ffqj-6fqr-9h24, an algorithm-confusion gap in the HMAC key-format blocklist). This single file has no visible manifest, so confirm the resolved version with SCA/dependency-check tooling before merging rather than assuming it's already met.

**Vulnerable code:**
```python
    # SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
    claims = jwt.decode(token, options={"verify_signature": False})
```

**Fixed code:**
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

The fix removes `options={"verify_signature": False}` and instead calls `jwt.decode()` with a real verification key and an explicit, single-entry `algorithms=["HS256"]` list, so PyJWT cryptographically checks the signature before returning any claims and rejects a forged, tampered, `alg=none`, or algorithm-swapped token instead of trusting it. The key is read from server-side configuration (`JWT_SECRET`, an environment variable) rather than anything derived from the token itself, and the algorithm is pinned rather than read from the token's own header, closing the algorithm-confusion path PyJWT's own key-format blocklist doesn't fully cover on older versions. Because `decode()` now raises on a bad signature instead of silently returning unverified claims, the call is wrapped in `try/except jwt.InvalidTokenError` so a rejected token fails closed with the same 401 the endpoint already used for a missing/invalid claim.

## Behaviour changes

- **New required configuration**: the endpoint now needs `JWT_SECRET` set in the environment; with it unset, `os.environ["JWT_SECRET"]` raises at import time instead of the app starting with signature checking silently disabled. This is intentional - fail loudly at startup rather than fail open at request time.
- **New exception path**: `jwt.decode()` can now raise (`InvalidSignatureError`, `ExpiredSignatureError`, `InvalidAlgorithmError`, etc., all subclasses of `jwt.InvalidTokenError`). The added `try/except` maps every such rejection to the existing `401 {"error": "invalid token"}` response, so a forged or tampered token now correctly fails before reaching the `account_id` claim lookup, rather than being read as if genuine. No new response shape was introduced.
- **Assumption**: the original file has no key material, algorithm choice, or manifest to confirm the intended scheme, so `HS256` with a shared secret was assumed as the minimal-infrastructure fix consistent with the rest of the file. If this service actually issues asymmetric (RS256/ES256) tokens, `JWT_ALGORITHM` and `JWT_SECRET` should be replaced with the public key loaded via `cryptography`'s key-loading functions, resolved by `kid` from a trusted keystore/JWKS rather than a single static secret. This lowers confidence in the exact fix (key source/algorithm) while leaving the core verdict - signature verification was disabled and must be re-enabled - unaffected.
- No other arguments, return values, or response fields were added, removed, or reordered relative to the original.
