## Verdict
exploitable

## Source
Attacker-controlled cross-site request originating from a malicious site visited by the authenticated user.

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

## Explanation
The `update_account_settings` endpoint modifies authenticated user state (display name, email, notification preferences) in response to a POST request without validating a CSRF token. An attacker can craft a malicious request that forces an authenticated user to update their account settings by visiting a compromised site while logged in. Adding the `@csrf_protect` decorator enforces server-side validation of the CSRF token, matching the pattern already applied to the `update_profile_note` endpoint above it. The decorator validates the incoming request against the server-controlled token issued during the user's session, preventing forged cross-site requests. The `starlette_wtf` middleware is already registered on the application and issues tokens for every session; the decorator is the enforcement point for FastAPI routes.

## Behaviour changes
None. The `@csrf_protect` decorator validates the request before the handler executes, adding a security check without altering return values, response structure, or other observable behaviour. The token is automatically validated by the decorator; no changes to the handler implementation are required.
