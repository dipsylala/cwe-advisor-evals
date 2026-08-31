## Verdict

Exploitable. The `jwt.decode()` call on line 15 explicitly disables signature verification with `options={"verify_signature": False}`, allowing an attacker to forge any JWT token and impersonate any account.

## Source

Line 9: `token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()` - untrusted JWT token from HTTP header.

## Fix

**Vulnerable code:**
```python
    # SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
    claims = jwt.decode(token, options={"verify_signature": False})
```

**Fixed code:**
```python
    # Retrieve the secret key from configuration (environment variable or Flask config)
    secret_key = app.config.get("JWT_SECRET_KEY")
    if not secret_key:
        return jsonify({"error": "server misconfigured"}), 500
    
    claims = jwt.decode(token, secret_key, algorithms=["HS256"])
```

## Explanation

The fix re-enables signature verification by removing `options={"verify_signature": False}` and providing the required `secret_key` and `algorithms=["HS256"]` arguments. The secret key must be retrieved from a trusted configuration source (Flask's config, environment variables, or a secrets manager), not hardcoded. The `algorithms` parameter is pinned to `["HS256"]` to prevent algorithm confusion attacks; if the application uses RSA keys and RS256, substitute the appropriate algorithm and load the public key using `cryptography`'s key-loading functions instead. The server-side secret key ensures that only the legitimate issuer can create valid signatures, and any forged or tampered token will be rejected immediately by `jwt.decode()`. Added error handling for missing configuration to prevent silent failures.

## Behaviour changes

**New behavior:** `jwt.decode()` now verifies the signature and raises `InvalidSignatureError` if verification fails, causing an unhandled exception that propagates as a 500 error. Caller code should wrap the call in try/except to handle verification failures gracefully (e.g., return 401 "invalid token" on `InvalidSignatureError` or `DecodeError`).

**Reason:** Signature verification is mandatory for security. The original code's silent acceptance of forged tokens is the vulnerability; rejecting invalid tokens is the corrected behavior. The calling code should be updated to catch `jwt.ExpiredSignatureError`, `jwt.InvalidAlgorithmError`, and `jwt.DecodeError` specifically to provide appropriate HTTP responses (401 for expired/invalid tokens).

**Configuration requirement:** Flask app must have `JWT_SECRET_KEY` set in its config (typically from `os.environ["JWT_SECRET_KEY"]` or similar), or the endpoint will return 500 on every request. Use a cryptographically strong, randomly generated key (minimum 32 bytes for HS256).
