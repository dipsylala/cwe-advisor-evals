## Verdict

Exploitable

## Source

`Authorization` HTTP header containing bearer token (line 20-24: extracted via `request.headers.get("Authorization")` and `removeprefix("Bearer ")`). Attacker-controlled.

## Fix

**Vulnerable code:**
```python
payload = jwt.decode(token, options={"verify_signature": False})
```

**Fixed code:**
```python
import os

SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY environment variable required")

payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
```

## Explanation

The vulnerability disables signature verification entirely with `options={"verify_signature": False}`, allowing any attacker to forge a JWT with an arbitrary `user_id` claim and bypass authentication. The fix restores verification by passing the server's signing secret and pinning the algorithm to the one actually in use. The `algorithms=["HS256"]` parameter prevents algorithm-confusion attacks (including `alg: none`). The signing secret must be loaded from a secure source (environment variable, secrets manager) rather than hardcoded.

## Behaviour changes

- **Key loading added**: The fixed code loads `JWT_SECRET_KEY` from environment and raises if missing. The original code had no key requirement. This is necessary for signature verification to work and should be part of deployment configuration.
- **Algorithm pinning added**: `algorithms=["HS256"]` restricts accepted algorithms. The original accepted any algorithm. This prevents algorithm-confusion bypass attempts.
- **Signature verification enabled**: Removing `options={"verify_signature": False}` and passing the secret enables full JWT validation. The original accepted unsigned or forged tokens without checking; the fixed code rejects any token not signed with the correct secret using the specified algorithm.
