## Verdict

CONFIRMED. The form processes state-changing data (user profile updates) without CSRF token validation, allowing attackers to forge authenticated requests through cross-site request forgery.

## Source

`account_settings.py`, lines 9–44:

The `AccountSettingsForm` class uses plain `wtforms.Form` without CSRF protection. The form lacks a CSRF token field, and the route handler at line 38 validates with `form.validate()` instead of checking CSRF tokens. An attacker can craft a malicious form that submits to this endpoint and modify any logged-in user's account settings.

## Fix

Replace the form class definition and validation:

```python
"""Account settings blueprint: lets a logged-in user update their profile."""

from flask import Blueprint, current_app, redirect, render_template, request, session, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, validators

account_bp = Blueprint("account", __name__)


class AccountSettingsForm(FlaskForm):
    """FlaskForm with automatic CSRF token generation and validation."""

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

**Key changes:**
- Line 4: Import `FlaskForm` from `flask_wtf` instead of plain `Form`
- Line 9: `AccountSettingsForm` now inherits from `FlaskForm`
- Line 36: Change form instantiation from `AccountSettingsForm(request.form)` to `AccountSettingsForm()` (FlaskForm handles request data automatically)
- Line 38: Change validation from `form.validate()` to `form.validate_on_submit()` (checks POST/PUT/PATCH/DELETE and validates CSRF token)

**Application setup requirement:**
Ensure the Flask app initializes CSRF protection at startup:
```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()
csrf.init_app(app)
```

**Template requirement:**
The form template must include the CSRF token field:
```html
<form method="POST">
    {{ form.hidden_tag() }}
    <!-- other form fields -->
</form>
```

## Explanation

Plain `wtforms.Form` provides no CSRF protection—it validates only field constraints (type, length, email format). `flask_wtf.FlaskForm` extends this with automatic CSRF token generation and validation:

- Tokens are cryptographically random, bound to the session, and compared in constant-time
- `validate_on_submit()` checks that the request method is safe for mutation (POST/PUT/PATCH/DELETE) and that the included CSRF token matches the session token
- The token is transmitted via `form.hidden_tag()` in the rendered template and automatically extracted from the POST body during validation
- Without the token in the POST request, `validate_on_submit()` rejects the request as invalid

This prevents attackers from forging authenticated requests through malicious forms on third-party sites, since they cannot obtain the victim's session-bound CSRF token.

## Behaviour changes

- The form now requires a valid CSRF token in all POST requests; requests without a matching token are rejected with validation failure
- `form.validate()` calls must be replaced with `form.validate_on_submit()` across the codebase for consistency and to ensure CSRF validation runs
- The form template must include `{{ form.hidden_tag() }}` or `{{ form.csrf_token }}` to render the token field; existing templates that don't include it will reject all POST requests as invalid CSRF tokens
- GET requests to render the form continue to work without restriction; the CSRF token is generated and embedded when the page is rendered
