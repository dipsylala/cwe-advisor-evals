## Verdict

Exploitable

## Source

`token` from the HTTP Authorization header (line 9), untrusted user input.

## Fix

**Vulnerable code:**
```python
claims = jwt.decode(token, options={"verify_signature": False})
```

**Fixed code:**
```python
import os
import jwt
from jwt.exceptions import InvalidTokenError

# At module level:
SECRET_KEY = os.environ.get("JWT_SECRET", "").encode() if os.environ.get("JWT_SECRET") else None

# Inside get_account():
try:
    claims = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
except InvalidTokenError:
    return jsonify({"error": "invalid token"}), 401
```

## Explanation

The original code disables signature verification via `options={"verify_signature": False}`, accepting any JWT regardless of its authenticity. This allows an attacker to forge tokens with arbitrary claims (including any `account_id`), bypassing authentication. The fix enables signature verification by removing the `verify_signature: False` option and explicitly providing both the `algorithms` list and the `SECRET_KEY` used to verify the token. This forces `jwt.decode()` to validate the token's HMAC signature before returning claims. The `SECRET_KEY` must be loaded from a trusted configuration source (environment variable shown here), never derived from the token itself. Invalid tokens now raise `InvalidTokenError` and are rejected with a 401 response, eliminating the weakness.

## Behaviour changes

- **Added exception handling:** `jwt.decode()` now raises `InvalidTokenError` on verification failure; the fix catches this and returns 401. This is necessary because verification is now enabled. Without it, the endpoint would crash on invalid tokens instead of returning a proper error response.
- **Added `algorithms=["HS256"]` argument:** This constrains the acceptable algorithm to HS256; it cannot be changed via the token header, stopping algorithm-confusion attacks.
- **Added `SECRET_KEY` argument:** The verification key is now supplied explicitly from configuration. Previously, verification was disabled entirely.
- **Added `os` and `jwt.exceptions` imports:** Required for environment variable access and exception handling.
