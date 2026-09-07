## Verdict

Exploitable. The `update_account_settings()` endpoint accepts state-changing POST requests without validating CSRF tokens, while the framework (starlette-wtf with CSRFProtectMiddleware) has token validation available. An attacker can craft a cross-site request that, if a victim visits a malicious site while authenticated, will modify their account settings using the victim's active session.

## Source

HTTP POST request to `/account/settings` initiated by an authenticated user, carrying the user's session cookie. The attacker-controlled entry point is the request body (the `AccountSettingsUpdate` payload), but the vulnerability is not in how the payload is processed—it is in the absence of token validation that would authenticate the request as originating from the application itself.

## Fix

**Vulnerable code (line 38-40):**
```python
@router.post("/settings")
# SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
async def update_account_settings(
```

**Fixed code:**
```python
@router.post("/settings")
@csrf_protect
async def update_account_settings(
```

Add the `@csrf_protect` decorator immediately before the `async def update_account_settings(` line. The decorator is already imported from `starlette_wtf` (line 5) and already applied correctly to `update_profile_note()` on line 25 as a working example.

## Explanation

FastAPI does not provide framework-native CSRF protection, so when using `starlette-wtf`, the `CSRFProtectMiddleware` only makes CSRF tokens available—it does not enforce validation by itself. The enforcement point is the `@csrf_protect` decorator on individual state-changing routes. The vulnerable endpoint was missing this decorator while `update_profile_note()` correctly included it. Adding the decorator restores token validation: the handler will reject requests that lack a valid CSRF token, preventing attackers from forging state-changing requests from cross-site contexts.

## Behaviour changes

None. The decorator validates the CSRF token before the handler executes, does not modify the request payload or return value, and does not alter the function signature. Session-authenticated requests carrying a valid CSRF token continue to work; only forged cross-site requests (those without a valid token) are rejected with a 403 response from the middleware.
