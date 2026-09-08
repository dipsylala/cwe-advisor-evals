## Verdict

Confirmed. `update_account_settings` performs a state-changing POST (updates display name, email, and notification preferences) using only session-cookie authentication via `get_current_user`, with no CSRF token validation. `CSRFProtectMiddleware` issues a token for the session but does not itself validate it on every route — validation only happens where `@csrf_protect` is applied, per `starlette_wtf`'s design. The sibling route `update_profile_note` in the same file carries `@csrf_protect`; this route does not. A cross-site form or fetch that rides the victim's session cookie can therefore silently change the account's email address (a common precursor to account takeover via password-reset interception) or other settings.

## Source

`E:/Github/cwe-advisor/evals/cases/352/python/FastApiMissingCsrfProtectDecorator/account.py`, lines 38-59 (decorator missing before the `async def update_account_settings` at line 40; state-changing sink at lines 54-58).

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

    CSRFProtectMiddleware issues a token for every session, and this route
    now validates it via @csrf_protect, matching update_profile_note above.
    """
    current_user.display_name = payload.display_name
    current_user.email = payload.email
    current_user.notifications_enabled = payload.notifications_enabled
    db.add(current_user)
    await db.commit()
    return {"status": "updated", "email": current_user.email}
```

## Explanation

`starlette_wtf.csrf_protect` is a per-route decorator: it checks the CSRF token carried in the submitted form/request against the one tied to the session, and rejects the request if it is missing or invalid. `CSRFProtectMiddleware` only handles issuing/rotating the token and making it available to templates and requests — it does not enforce validation on routes that lack the decorator, so an undecorated state-changing POST is reachable by a forged cross-site request that merely rides the victim's session cookie (which browsers attach automatically to same-site-cookie-scoped requests unless `SameSite` blocks it, and this app's own use of the decorator elsewhere shows it isn't relying on `SameSite` alone).

The fix adds `@csrf_protect` to `update_account_settings`, placed immediately above the function definition and below the routing decorator, exactly mirroring the working pattern already present on `update_profile_note` directly above it in the same file. This is the minimal, correct change: no new dependency, no altered request/response contract for legitimate same-origin callers (which already send the token because the middleware issues it for every session), and no change to the route's business logic. Non-legitimate cross-site submissions that omit a valid token will now receive the library's standard CSRF-validation-failure response instead of having the update applied.
