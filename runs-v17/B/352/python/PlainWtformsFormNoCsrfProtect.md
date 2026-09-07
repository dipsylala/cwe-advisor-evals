## Verdict

Exploitable. The route accepts POST requests that modify user account data without validating a CSRF token, allowing attackers to forge authenticated state-changing requests.

## Source

Untrusted POST request data enters through `request.form` at line 36, propagated through the form object to line 40 where the account data update is performed.

## Sink

Database update at line 40-44: `current_app.db.users.update_one({"id": user["id"]}, {"$set": {...}})` performs state change without CSRF token verification. The form validation at line 38 validates only field content, not request authenticity.

## Fix

### File: account_settings.py

```python
"""Account settings blueprint: lets a logged-in user update their profile."""

from flask import Blueprint, current_app, redirect, render_template, request, session, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, validators

account_bp = Blueprint("account", __name__)


class AccountSettingsForm(FlaskForm):
    """FlaskForm with built-in CSRF token field and validation."""

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
        # CSRF token validated automatically by FlaskForm.validate_on_submit()
        current_app.db.users.update_one({"id": user["id"]}, {"$set": {
            "display_name": form.display_name.data,
            "contact_email": form.contact_email.data,
            "timezone": form.timezone.data,
        }})
        return redirect(url_for("account.account_settings"))

    return render_template("account_settings.html", form=form, user=user)
```

## Explanation

The fix replaces `wtforms.Form` (which has no CSRF protection) with `flask_wtf.FlaskForm` (which includes cryptographic CSRF token generation and validation). The key change at the vulnerability point (line 38/now line 38) switches from `form.validate()` to `form.validate_on_submit()`. The `validate_on_submit()` method performs three checks: (1) verifies the request is a POST/PUT/PATCH/DELETE operation, (2) extracts the CSRF token from the form data, and (3) validates it against the server-side session token before field validation proceeds. Only when both the CSRF token and field validators pass does the condition evaluate true, blocking the database update at line 40. The form instantiation no longer passes `request.form` explicitly; `FlaskForm` automatically extracts request data and validates the CSRF token in a constant-time comparison. The template rendering will automatically include the CSRF token via the form's hidden field (rendered by `{{ form.csrf_token() }}` or implicit in form rendering, depending on the template's form rendering helper), which the POST submission will echo back for validation.

## Behaviour changes

- **Form initialization** (line 36→37): Changed from `AccountSettingsForm(request.form)` to `AccountSettingsForm()`. The new form automatically populates from `request.form`, `request.files`, and other request data without explicit passing. This is simpler and more secure, as it isolates CSRF token handling inside the form class.
- **Validation method** (line 38→38): Changed from `form.validate()` to `form.validate_on_submit()`. The `validate_on_submit()` method incorporates CSRF token validation as part of its check, whereas `validate()` only validates field content. For GET requests, `validate_on_submit()` returns `False` (no error, the form simply does not validate and proceeds to render). For POST requests without a token or with an invalid token, it returns `False` and sets form-level errors that can be displayed to the user.
- **Form class import** (line 4): Changed from importing `Form` from `wtforms` to importing `FlaskForm` from `flask_wtf`. `FlaskForm` extends `Form` with CSRF token field management and Flask request context integration. No other import changes; field definitions remain identical.

All other behavior is preserved. The database update logic, session checking, and rendering remain functionally the same. The route still handles both GET (render form) and POST (validate and update) as before. No changes to the database schema, API surface, or return values.
