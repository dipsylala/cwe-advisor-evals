## Verdict

Exploitable.

## Source

`token` from the `Authorization` header (user-controlled). Attacker can supply a forged JWT with any `user_id` value.

## Fix

**Vulnerable code (line 28):**
```python
payload = jwt.decode(token, options={"verify_signature": False})
```

**Fixed code:**
```python
import os

SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY environment variable not set")

payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
```

Library recommendation: PyJWT 2.8.0 or later (as documented in the code); ensure `JWT_SECRET_KEY` is configured with sufficient entropy before production deployment.

## Explanation

The original code disables JWT signature verification with `options={"verify_signature": False}`, allowing any attacker to forge a token with an arbitrary `user_id` claim and bypass authentication entirely. The fix enables signature verification by removing that option and supplying an explicit `algorithms` allowlist and signing secret. The `algorithms=["HS256"]` parameter prevents algorithm-confusion attacks (e.g., accepting `alg: none` or switching to RSA public-key verification). The signing secret must be loaded from a secure location (environment variable or secret manager, never hard-coded) and have sufficient entropy. On verification failure, `jwt.decode()` raises `InvalidSignatureError` or `DecodeError`, which causes the request to fail with an unhandled exception - that exception should be caught and returned as a 401 response to the caller. The guard clause raising `ValueError` ensures the application cannot run without the required configuration.

## Behaviour changes

- `jwt.decode()` now validates the JWT signature; a request with a missing, malformed, expired, or unsigned token will trigger an exception instead of passing through.
- The application requires `JWT_SECRET_KEY` to be set in the environment; starting without it will fail at module load time with a clear error message rather than silently accepting forged tokens.
- Callers must implement error handling around `jwt.decode()` to catch `jwt.InvalidSignatureError`, `jwt.DecodeError`, and `jwt.ExpiredSignatureError`, and return a 401 response with a `WWW-Authenticate` header instead of allowing the exception to propagate.
