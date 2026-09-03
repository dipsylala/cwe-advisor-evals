## Verdict

The `update_account_settings` endpoint at line 40 lacks CSRF token validation and can be exploited by attackers to modify account settings of authenticated users without authorization.

## Source

**File:** account.py  
**Line:** 38–40  
**Root cause:** The `@csrf_protect` decorator is missing from the POST endpoint that modifies sensitive account settings (display name, email, notification preferences).

The sibling endpoint `update_profile_note` (line 24–25) correctly applies `@csrf_protect`, but `update_account_settings` does not. Even though CSRFProtectMiddleware is registered on the app and issues tokens, this endpoint accepts forged requests carrying only the user's session cookie.

## Fix

Add the `@csrf_protect` decorator immediately before the function definition:

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

The vulnerability occurs because a POST endpoint that modifies account settings fails to validate a CSRF token. An attacker can craft a forged request (e.g., a hidden form submitted from an attacker-controlled site) that changes the victim's email, display name, or notification settings if the victim is logged in and visits the attacker's page.

The `@csrf_protect` decorator from `starlette_wtf` enforces CSRF token validation by:
1. Issuing a unique token to each session (handled by CSRFProtectMiddleware).
2. Requiring the token to be present and valid in any state-changing request (POST, PUT, DELETE, etc.).

Since the same import and decorator already exist and are correctly applied to the sibling `update_profile_note` endpoint, adding `@csrf_protect` to `update_account_settings` restores the missing validation without additional dependencies or configuration.
