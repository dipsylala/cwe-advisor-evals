## Verdict

**CONFIRMED VULNERABILITY**: The `update_account_settings` endpoint lacks the `@csrf_protect` decorator required to validate CSRF tokens. This allows an attacker to forge cross-site requests that modify the authenticated user's account settings (display name, email, notification preferences) by exploiting the user's existing session cookie.

## Source

**File**: `evals/cases/352/python/FastApiMissingCsrfProtectDecorator/account.py`  
**Line**: 40 (function definition)  
**Affected code**:
```
@router.post("/settings")
# Missing @csrf_protect decorator
async def update_account_settings(...)
```

The vulnerability exists because:
1. CSRFProtectMiddleware is registered on the application and issues CSRF tokens to every session
2. The `update_profile_note` endpoint (line 24) correctly validates tokens via `@csrf_protect`
3. The `update_account_settings` endpoint (line 40) performs a state-changing operation (POST) but omits the decorator, accepting any cross-site request carrying the user's session cookie

## Fix

Add the `@csrf_protect` decorator to the `update_account_settings` function:

```python
@router.post("/settings")
@csrf_protect
async def update_account_settings(
    payload: AccountSettingsUpdate,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db_session),
):
```

This ensures the endpoint validates the CSRF token before accepting the request, consistent with the pattern established on `update_profile_note`.

## Explanation

CSRF protection in FastAPI with `starlette_wtf` requires two components: middleware that issues tokens and a decorator that validates them. The middleware (`CSRFProtectMiddleware`) is installed globally and generates tokens for every session. The `@csrf_protect` decorator on individual endpoints enforces validation by:

1. Extracting the CSRF token from the request (typically from form data or headers)
2. Verifying it matches the token bound to the user's session
3. Rejecting the request if validation fails

Without the decorator, POST endpoints accept requests from any origin that can access the user's session cookie—the core CSRF attack. The fix mirrors the existing secure pattern on the `update_profile_note` endpoint and requires no additional dependencies or configuration changes.
