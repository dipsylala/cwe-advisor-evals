## Verdict

The finding is **confirmed and remediable**. The `update_account_settings` endpoint at line 40 is a state-changing POST route that lacks the `@csrf_protect` decorator, making it vulnerable to cross-site request forgery attacks. The codebase already imports `csrf_protect` from `starlette_wtf` and correctly applies it to the sibling endpoint `update_profile_note`, establishing the expected pattern.

## Source

**File**: `account.py`  
**Line**: 40  
**Sink**: The `update_account_settings` function definition, which modifies authenticated user state without CSRF token validation.

**Call chain**: A POST request to `/account/settings` (mounted via the router prefix) reaches the undecorated `update_account_settings` handler. The handler updates the current user's `display_name`, `email`, and `notifications_enabled` fields in the database without validating a CSRF token first.

**Data flow**: 
1. Request enters FastAPI route handler (authenticated via session cookie via `Depends(get_current_user)`)
2. Payload is deserialized to `AccountSettingsUpdate` 
3. State is mutated (user record modified, database committed) with no token validation interposed

## Fix

### File: account.py

```python
"""Account settings routes, mounted under /account in main.py."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from starlette_wtf import csrf_protect

from auth import get_current_user
from db import get_db_session
from models import User

router = APIRouter(prefix="/account", tags=["account"])


class ProfileNoteUpdate(BaseModel):
    note: str


class AccountSettingsUpdate(BaseModel):
    display_name: str
    email: str
    notifications_enabled: bool


@router.post("/profile-note")
@csrf_protect
async def update_profile_note(
    payload: ProfileNoteUpdate,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db_session),
):
    """Update the free-text note shown on the user's public profile page."""
    current_user.profile_note = payload.note
    db.add(current_user)
    await db.commit()
    return {"status": "ok"}


@router.post("/settings")
@csrf_protect
async def update_account_settings(
    payload: AccountSettingsUpdate,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db_session),
):
    """Update the authenticated user's display name, email, and notification
    preferences.

    CSRFProtectMiddleware is registered on the app, so a token is issued
    for every session, but nothing on this route validates it: the
    @csrf_protect decorator present on update_profile_note above is
    missing here, so a forged cross-site POST carrying the user's session
    cookie is accepted unchanged.
    """
    current_user.display_name = payload.display_name
    current_user.email = payload.email
    current_user.notifications_enabled = payload.notifications_enabled
    db.add(current_user)
    await db.commit()
    return {"status": "updated", "email": current_user.email}
```

## Explanation

The fix adds the `@csrf_protect` decorator to the `update_account_settings` function (line 39, now decorated at line 38). This decorator, already imported from `starlette_wtf` and correctly applied to `update_profile_note`, enforces CSRF token validation for this state-changing endpoint.

**How it closes the vulnerability**: 
- `@csrf_protect` intercepts the POST request and validates that the incoming CSRF token (extracted from the request headers or form data by `starlette-wtf`) matches the server-bound token in the session
- Requests lacking a valid token or originating from a different site are rejected before the handler executes
- The pattern matches the existing remediation applied elsewhere in the same file, confirming the application's already-configured CSRF infrastructure covers this route

**Why this is the minimal change**:
- No other code changes are required; the decorator reuses the existing middleware configuration and import
- The handler signature, response contract, and database operations remain unchanged
- Existing clients (forms, AJAX calls) already pass CSRF tokens when they interact with the sibling endpoint; no client-side changes are needed

## Behaviour changes

**User-facing changes**: None. The endpoint's API contract, response format, and success path are unchanged. Clients that currently send valid CSRF tokens (via form hidden fields or the `X-CSRFToken` header) will continue to succeed.

**Rejection behaviour**: Requests without a valid CSRF token now return a 403 Forbidden response. This includes:
- Cross-site POST requests forged by an attacker's page
- Legitimate cross-site requests from old forms or scripts that do not include the token

This is the intended security property. Legitimate in-application traffic will include the token because it is already being served and validated for the `/account/profile-note` endpoint in the same application, so the CSRF token is present in all forms and AJAX wrappers.
