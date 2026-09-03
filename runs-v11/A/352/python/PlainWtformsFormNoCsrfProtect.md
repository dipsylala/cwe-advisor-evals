## Verdict

**Confirmed CSRF vulnerability.** The form uses plain `wtforms.Form` without CSRF token generation or validation, allowing an attacker to forge cross-site requests that modify the user's account settings.

## Source

**File:** `account_settings.py`  
**Lines:** 9 (form definition), 36 (form instantiation), 38 (validation)

The vulnerability spans three points:
- Line 9: Form class inherits from plain `wtforms.Form` (no CSRF protection)
- Line 36: Form instantiated with only `request.form` (no CSRF token access)
- Line 38: Validation uses `form.validate()` (does not check CSRF token)

When an attacker creates a malicious form pointing to this endpoint and tricks a logged-in user into submitting it, the form has no CSRF token and no validation occurs, so the request succeeds.

## Fix

Replace plain `wtforms.Form` with `flask_wtf.FlaskForm`, which automatically generates CSRF tokens, validates them, and simplifies form handling:

```python
"""Account settings blueprint: lets a logged-in user update their profile."""

from flask import Blueprint, current_app, redirect, render_template, request, session, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, validators

account_bp = Blueprint("account", __name__)


class AccountSettingsForm(FlaskForm):
    """FlaskForm provides automatic CSRF token generation and validation."""

    display_name = StringField(
        "Display name", [validators.Length(min=1, max=80)]
    )
    contact_email = StringField(
        "Contact email", [validators.Email(), validators.Length(max=120)]
    )
    timezone = StringField(
        "Timezone", [validators.Length(min=1, max=64)]
    )


def _load_current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return current_app.db.users.find_one({"id": user_id})


@account_bp.route("/account/settings", methods=["GET", "POST"])
def account_settings():
    user = _load_current_user()
    if user is None:
        return redirect(url_for("auth.login"))

    form = AccountSettingsForm()

    if form.validate_on_submit():
        current_app.db.users.update_one({"id": user["id"]}, {"$set": {
            "display_name": form.display_name.data,
            "contact_email": form.contact_email.data,
            "timezone": form.timezone.data,
        }})
        return redirect(url_for("account.account_settings"))

    return render_template("account_settings.html", form=form, user=user)
```

## Explanation

**Root cause:** Plain `wtforms.Form` has no built-in CSRF protection. The endpoint accepts POST requests but does not validate a CSRF token, so any cross-origin request that obtains a user's session cookie can modify their account.

**Primary fix:** Replace `wtforms.Form` with `flask_wtf.FlaskForm`.

- `FlaskForm` automatically generates a unique CSRF token per session and includes it in the rendered form.
- `FlaskForm()` instantiation requires no arguments; it accesses `request.form` and the session internally.
- `form.validate_on_submit()` returns `True` only if the request is a POST and the CSRF token in the submitted form matches the session token.
- On GET, the form is rendered with the CSRF token embedded, which the template includes in a hidden field (typically `<input type="hidden" name="csrf_token">`).

**Defense-in-depth considerations:**
- Ensure Flask's session secret key is strong and unique (controls CSRF token signing).
- Confirm the template includes `{{ form.csrf_token }}` or uses Flask-WTF's form rendering helper to inject the token automatically.
- Set `WTF_CSRF_ENABLED = True` in Flask config (the default).

This fix prevents forged cross-site requests while preserving the form's input validation.
