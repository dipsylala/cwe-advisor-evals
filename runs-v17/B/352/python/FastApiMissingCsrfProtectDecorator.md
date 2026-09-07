## Verdict
exploitable

## Source
Cross-site POST request carrying the authenticated user's session cookie (sent by the browser automatically when a user visits an attacker's malicious page)

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
    for every session, and the @csrf_protect decorator now validates it,
    closing the CSRF vulnerability.
    """
    current_user.display_name = payload.display_name
    current_user.email = payload.email
    current_user.notifications_enabled = payload.notifications_enabled
    db.add(current_user)
    await db.commit()
    return {"status": "updated", "email": current_user.email}
```

## Explanation
The endpoint `update_account_settings` modifies authenticated user state (display name, email, notification settings) in response to a POST request but lacks the `@csrf_protect` decorator required by FastAPI when using starlette-wtf middleware. This allows an attacker to forge an authenticated request from a malicious website: when a logged-in user visits the attacker's site, malicious JavaScript or a form submission sends a POST to `/account/settings` with the user's session cookie (sent automatically by the browser). Without CSRF token validation, the request is processed as if the user intentionally made it. Adding the `@csrf_protect` decorator enforces validation of the CSRF token, preventing forgery. The decorator is already correctly applied to the similar `update_profile_note` endpoint; the fix applies the same pattern here.

## Behaviour changes
none

