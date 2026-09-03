## Verdict

The finding is confirmed. Line 40 defines a POST endpoint that modifies user state (display name, email, notification settings) without validating a CSRF token. An authenticated user can be tricked into submitting this form from a malicious website, causing the endpoint to process the attacker's data as if the user had requested it.

## Source

```python
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
```

The endpoint lacks the `@csrf_protect` decorator present on the `/profile-note` endpoint immediately above it.

## Fix

```python
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

Add the `@csrf_protect` decorator immediately before the function definition.

## Explanation

FastAPI has no framework-native CSRF protection; `starlette-wtf` provides the `CSRFProtectMiddleware` and `@csrf_protect` decorator. The middleware makes CSRF tokens available to the application but does not enforce validation automatically—the `@csrf_protect` decorator on each state-changing endpoint is what performs the token check. Without it, authenticated users can be tricked via cross-site requests into performing unwanted state changes. The decorator validates the token before the handler executes; if validation fails, it returns a 403 response.

## Behaviour changes

- POST requests to `/settings` without a valid CSRF token are rejected with HTTP 403.
- Legitimate requests from the application (that include the token in the request) continue to work.
- Session authentication behaviour is unchanged; the decorator adds token validation on top of the existing authentication dependency.
- The response for successful requests (`{"status": "updated", "email": ...}`) remains unchanged.
