## Verdict
Confirmed CWE-352: Cross-Site Request Forgery vulnerability. The `update_account_settings` route handler at line 40 lacks the `@csrf_protect` decorator required to validate CSRF tokens for state-changing POST requests.

## Source
File: `account.py`, lines 38-59

The `update_account_settings` function accepts a POST request that modifies authenticated user state (display name, email, notification preferences) without validating a CSRF token. The identical endpoint `update_profile_note` (lines 24-35) demonstrates the correct pattern by including the `@csrf_protect` decorator, confirming that CSRF protection is expected on this route.

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
The vulnerability is remediated by adding the `@csrf_protect` decorator before the `update_account_settings` function definition, immediately following the `@router.post("/settings")` decorator on line 39.

The `@csrf_protect` decorator validates that requests carry a valid CSRF token matching the user's session. Without it, an attacker can craft a malicious webpage that triggers state-changing requests (email change, notification preference updates) using only the victim's session cookie, since the browser automatically includes cookies in cross-site requests.

This fix aligns the `/settings` endpoint with the existing protective pattern already implemented for the `/profile-note` endpoint, ensuring consistent CSRF protection across all state-modifying operations in the account settings module.
