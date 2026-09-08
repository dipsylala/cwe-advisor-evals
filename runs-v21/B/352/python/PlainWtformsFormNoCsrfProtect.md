## Verdict

The finding is **confirmed**. The route at `account_settings.py:30-45` processes state-changing requests (POST) without CSRF token validation. The form uses plain `wtforms.Form`, which carries no CSRF token field or validation, and the application does not initialize `CSRFProtect` to provide app-wide protection. An attacker can craft a malicious form on an external site and trick an authenticated user into submitting it, causing the user's profile to be updated without their knowledge.

## Source

The vulnerability originates from two gaps:

1. **Form class choice** (line 9): `AccountSettingsForm` inherits from plain `wtforms.Form`, which has no CSRF token field or validation logic.
2. **Missing application-level protection** (app.py): The Flask application never initializes `CSRFProtect(app)`, so no app-wide middleware validates CSRF tokens.

The sink is the database update at line 40: `current_app.db.users.update_one()`. This call is reached after form validation at line 38, but the validation checks only field constraints (email format, string length), not CSRF token authenticity.

Data flow:
- Request body → `request.form` (line 36)
- Form instantiation → `AccountSettingsForm(request.form)` (line 36)
- Field validation → `form.validate()` (line 38, validates fields only)
- Unprotected database update → `current_app.db.users.update_one()` (line 40)

The form has no mechanism to reject requests that lack a CSRF token or submit a forged token. An attacker's POST request bypasses this entire chain.

## Fix

### File: account_settings.py

```python
"""Account settings blueprint: lets a logged-in user update their profile."""

from flask import Blueprint, current_app, redirect, render_template, request, session, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, validators

account_bp = Blueprint("account", __name__)


class AccountSettingsForm(FlaskForm):
    """Flask-WTF FlaskForm - includes CSRF token field and automatic validation."""

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
        # CSRF token is now validated before this point
        current_app.db.users.update_one({"id": user["id"]}, {"$set": {
            "display_name": form.display_name.data,
            "contact_email": form.contact_email.data,
            "timezone": form.timezone.data,
        }})
        return redirect(url_for("account.account_settings"))

    return render_template("account_settings.html", form=form, user=user)
```

## Explanation

The fix replaces `wtforms.Form` with `flask_wtf.FlaskForm`, which automatically includes CSRF token generation and validation. 

**Changes:**
1. Import `FlaskForm` from `flask_wtf` (line 4) instead of `Form` from `wtforms`
2. Change the class declaration from `AccountSettingsForm(Form)` to `AccountSettingsForm(FlaskForm)` (line 10)
3. Instantiate the form without passing `request.form` (line 37): `FlaskForm` constructor automatically accesses the request context to validate CSRF tokens
4. Change `form.validate()` to `form.validate_on_submit()` (line 39) to explicitly validate on POST/PUT/PATCH/DELETE and check the CSRF token in one step

**How it closes the weakness:**
- `FlaskForm` automatically creates a `csrf_token` field that must be rendered in the template as a hidden field
- During `validate_on_submit()`, the form compares the submitted token against the one stored in the session
- If the token is missing or invalid, validation fails and the state-changing operation never reaches the database
- The attacker's cross-site request will lack the valid CSRF token and be rejected

**Assumptions:**
- Flask-WTF is installed as a project dependency (commonly `pip install flask-wtf`)
- The template `account_settings.html` is updated to render the CSRF token field (typically `{{ form.csrf_token }}` or `{% csrf_token %}`)
- The Flask application maintains a session secret key (already present: `app.config["SECRET_KEY"]`)

## Behaviour changes

1. **Form instantiation** (line 37): Changed from `AccountSettingsForm(request.form)` to `AccountSettingsForm()`. `FlaskForm` automatically accesses `request.form` and `request.files` from the Flask request context; passing them explicitly would duplicate the data and cause validation issues.

2. **Validation call** (line 39): Changed from `form.validate()` to `form.validate_on_submit()`. This is the Flask-WTF idiom that:
   - Returns `False` immediately for GET requests (no validation needed)
   - Calls `validate()` for POST/PUT/PATCH/DELETE, checking both field validators and CSRF token
   - Returns `True` only if all validators pass AND the CSRF token is valid

3. **Form rendering in template** (not in this file): The template must render the CSRF token as a hidden field to submit it with the form. Without this, validation will fail. Typical pattern: `{{ form.csrf_token }}` in the form HTML.

4. **Denial of CSRF requests**: POST requests without a valid CSRF token now fail validation silently (form validation returns `False`). The user sees the form re-rendered, not an error page. This is the expected UX for CSRF protection.

No changes to the database update logic, return values, or error handling are required. The fix operates purely at the form validation layer before reaching the sink.
