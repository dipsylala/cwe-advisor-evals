## Verdict

Confirmed. `jwt.decode()` is called with `options={"verify_signature": False}`, which disables signature verification entirely. Any caller can submit a JWT with an arbitrary, unsigned or wrongly-signed payload — including an `alg: none` token or one signed with any key — and have its claims (`account_id`, `plan`) accepted as authentic. This lets an attacker forge a token for any `account_id` and grant themselves any `plan` value, bypassing authentication and authorization entirely.

## Source

`token`, taken from the `Authorization` request header at line 9 (`request.headers.get("Authorization", "")`), stripped of the `Bearer ` prefix. This is fully attacker-controlled input.

## Fix

```python
import os

import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHMS = ["HS256"]


@app.route("/account", methods=["GET"])
def get_account():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()

    if not token:
        return jsonify({"error": "missing token"}), 401

    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=JWT_ALGORITHMS)
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

`jwt.decode()` verifies the signature by default; the vulnerable code explicitly disables that check with `options={"verify_signature": False}` and also omits the `algorithms` allowlist and the verification key, so the returned claims dict is accepted straight from unauthenticated attacker input.

The fix does three things:

- Removes `verify_signature: False` so PyJWT cryptographically validates the token against a real key, and passes that key (`JWT_SECRET`, loaded from environment/secret storage rather than hardcoded) as the second positional argument.
- Passes an explicit `algorithms=["HS256"]` allowlist. PyJWT requires this whenever a key is supplied, and it also closes the classic "alg confusion" attack where a token crafted with `alg: none` or a different algorithm (e.g. swapping `RS256` for `HS256` and signing with the public key) would otherwise be accepted.
- Wraps the call in `try/except jwt.InvalidTokenError` (PyJWT's common base for expired, malformed, and bad-signature tokens) so a rejected token returns 401 instead of raising an unhandled exception.

With this change, only tokens signed with the server's own secret and using an approved algorithm are accepted, and PyJWT's default claim checks (e.g. `exp`) are enforced automatically since no verification options are being suppressed.
