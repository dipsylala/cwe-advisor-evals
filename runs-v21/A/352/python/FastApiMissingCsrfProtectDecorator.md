## Verdict
Confirmed - the `update_account_settings` route is missing the `@csrf_protect` decorator required to validate CSRF tokens, allowing state-changing POST requests to proceed without protection.

## Source
File: `account.py`, line 40
Function: `update_account_settings` (POST /settings route)

The route accepts POST requests that modify sensitive user data (email, display name, notification preferences) but does not validate the CSRF token. The `@csrf_protect` decorator is applied to `update_profile_note` (line 27) but is missing from this route.

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
FastAPI does not have framework-native CSRF protection. When `starlette-wtf` is configured with `CSRFProtectMiddleware`, it generates and stores per-session CSRF tokens but does not enforce validation by itself. Each state-changing route (POST, PUT, DELETE, PATCH) must explicitly apply the `@csrf_protect` decorator to validate the token from the request before processing.

The fix adds `@csrf_protect` directly above the `update_account_settings` function definition (line 40). This decorator:
1. Extracts the CSRF token from the request (form data or headers)
2. Compares it against the token stored in the session
3. Returns HTTP 403 if the token is missing or invalid
4. Only allows the request to proceed if the token matches

This prevents cross-site request forgery by ensuring only requests originating from pages that loaded the valid per-session token can modify the user's settings.
