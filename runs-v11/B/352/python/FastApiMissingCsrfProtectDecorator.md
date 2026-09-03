## Verdict

Exploitable. The `update_account_settings` POST endpoint modifies authenticated user state (display name, email, notification preferences) without validating a CSRF token. An attacker can forge a cross-site request that executes state-changing operations on behalf of an authenticated user.

## Source

No untrusted input source. The vulnerability is structural: a state-changing endpoint lacks the CSRF protection mechanism that is correctly applied to the paired `update_profile_note` endpoint.

## Fix

**Vulnerable code:**

```python
@router.post("/settings")
# SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
async def update_account_settings(
    payload: AccountSettingsUpdate,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db_session),
):
```

**Fixed code:**

```python
@router.post("/settings")
@csrf_protect
async def update_account_settings(
    payload: AccountSettingsUpdate,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db_session),
):
```

## Explanation

The `@csrf_protect` decorator validates that incoming requests carry a valid, server-controlled CSRF token bound to the user's session. FastAPI with `starlette-wtf` uses decorator-based per-route enforcement (not global middleware validation), so every state-changing endpoint must explicitly carry the decorator. The middleware that issued the token on session creation is registered but does nothing without the matching per-route validation. Adding `@csrf_protect` to `update_account_settings` completes the protection already correctly implemented on `update_profile_note`.

## Behaviour changes

None. The decorator adds server-side token validation before the endpoint executes; it does not alter the function's signature, return value, or success path—only rejects unauthenticated cross-site requests before the handler runs.
