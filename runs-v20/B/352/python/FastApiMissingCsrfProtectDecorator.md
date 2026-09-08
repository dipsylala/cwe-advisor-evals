## Verdict

Exploitable. Confidence: high.

- CWE: CWE-352 (Cross-Site Request Forgery)
- Location: `account.py`, line 40, `update_account_settings`
- Source: an authenticated cross-site request forged by an attacker (a form or script on a third-party page, submitted by the victim's browser, which automatically attaches the victim's session cookie)
- Sink: the `@router.post("/settings")` handler `update_account_settings`, which mutates `current_user.display_name`, `current_user.email`, and `current_user.notifications_enabled` and commits them to the database

## Source

`account.py` defines two POST routes under `/account`. `CSRFProtectMiddleware` (from `starlette-wtf`) is registered on the app, which issues a CSRF token per session but validates nothing on its own; validation happens only where the `@csrf_protect` decorator is applied to a route. The sibling route `update_profile_note` (line 24-26) carries `@csrf_protect` directly above its handler. `update_account_settings` (line 38-40) does not: the state-changing POST route is reachable with a forged cross-site request carrying only the victim's session cookie, and the handler commits the attacker-supplied `display_name`, `email`, and `notifications_enabled` values unchanged. This matches `cwe/352/python/INDEX.md`'s documented FastAPI/starlette-wtf gap exactly: "the enforcement point is the `@csrf_protect` decorator on each state-changing route, so a cookie-authenticated endpoint without it is unprotected."

Sink contract (`db.add(current_user)` / `await db.commit()`):
- **Returns**: nothing to the caller directly; the handler returns a JSON status dict once the commit succeeds.
- **Discards**: nothing security-relevant.
- **Arguments left implicit**: none change - the ORM call signatures are untouched by this fix.
- **Failure behaviour**: an unhandled exception during `commit()` propagates as a 500; unchanged by this fix. The `@csrf_protect` decorator, when it rejects a request, is expected to short-circuit before the handler body runs at all (matching how it behaves on `update_profile_note`), so it never reaches this commit.

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

    Validated by CSRFProtectMiddleware's token check via the @csrf_protect
    decorator, matching update_profile_note above.
    """
    current_user.display_name = payload.display_name
    current_user.email = payload.email
    current_user.notifications_enabled = payload.notifications_enabled
    db.add(current_user)
    await db.commit()
    return {"status": "updated", "email": current_user.email}
```

## Explanation

The fix adds the `@csrf_protect` decorator (already imported from `starlette_wtf` at the top of the file) to `update_account_settings`, mirroring the pattern already correctly applied to `update_profile_note` immediately above it. `CSRFProtectMiddleware` issues the token but performs no validation by itself in `starlette-wtf`; `@csrf_protect` is the per-route enforcement point that checks the submitted token against the session before the handler body executes. With the decorator present, a forged cross-site POST that carries only the victim's session cookie and no valid token is rejected before it can reach the `db.add`/`db.commit()` calls that persist the attacker-controlled `display_name`, `email`, and `notifications_enabled` values. No other library or dependency change is required - `starlette-wtf` is already a project dependency and the middleware is already registered; only the missing per-route decorator was absent.

`@csrf_protect` is verified against this codebase, not assumed: it is already imported in this file and already used successfully on the sibling `update_profile_note` route, so its name, import path, and decorator usage are established by the existing, working code rather than by recall.

## Behaviour changes

- Added `@csrf_protect` above `update_account_settings` (and reworded the docstring's last paragraph to describe the now-correct state instead of the missing-decorator finding). This is the sole change; it closes the CWE-352 gap and introduces no other behavioural difference.
- A legitimate same-origin request that omits or sends a stale/invalid CSRF token will now receive the decorator's rejection response (as already happens on `update_profile_note`) instead of having its update applied. Any client already calling `/account/profile-note` correctly (i.e., sending the CSRF token) needs no change; a client calling `/account/settings` without a token must be updated to include one, the same way any legitimate caller of `update_profile_note` already must.
- No changes to arguments, return values, status codes on success, or database operations.

**Verification**: The fixed file was written to a scratch copy outside the repository and checked with `python -m py_compile account.py` (Python 3.13.12) - exit code 0, no diagnostics. `csrf_protect` was not newly introduced: it was already imported in this file's original source and already applied to `update_profile_note`, so no new import or unverified name was added.
