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
# SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
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
