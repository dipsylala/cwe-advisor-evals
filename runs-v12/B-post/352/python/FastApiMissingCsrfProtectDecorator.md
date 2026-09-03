## Verdict

Exploitable. The `/account/settings` endpoint is a POST method (state-changing) that modifies user account settings in the database but lacks the `@csrf_protect` decorator required by FastAPI's `starlette-wtf` middleware to validate CSRF tokens. An attacker can craft a malicious request using a victim's authenticated session to update their account settings without their knowledge.

## Source

Attacker-controlled HTTP POST request to the `/account/settings` endpoint. The request includes the victim's session cookie (automatically sent by the browser) and carries user-supplied `AccountSettingsUpdate` payload data. The vulnerability exists because the endpoint enforces authentication via `Depends(get_current_user)` but does not validate CSRF tokens, so the browser's implicit session cookie is sufficient to authorize arbitrary account modifications.

## Fix

Add the `@csrf_protect` decorator to the `update_account_settings` function, matching the protection pattern used on the `update_profile_note` route.

**Vulnerable code (lines 38-40):**
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

The FastAPI application uses `starlette-wtf`'s `CSRFProtectMiddleware` to generate and issue CSRF tokens to clients, but token validation in FastAPI requires the explicit `@csrf_protect` decorator on each state-changing route. The `update_profile_note` route (lines 24-35) correctly includes this decorator and validates CSRF tokens; the `update_account_settings` route (lines 38-59) lacks it and therefore accepts forged cross-site POST requests carrying the victim's session cookie. Adding the `@csrf_protect` decorator to line 38 restores token validation and closes the vulnerability by enforcing verification that the request originated from the application itself.

## Behaviour changes

None. The `@csrf_protect` decorator only validates the incoming CSRF token and raises an HTTP 403 exception if validation fails—it does not modify the function signature, return type, or normal-case execution path. Legitimate requests from the application's own forms and AJAX clients (which already include valid CSRF tokens) continue to work identically. Only forged cross-site requests without valid tokens are rejected.
