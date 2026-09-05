## Verdict

Exploitable. The endpoint processes state-changing POST requests that update user account settings without validating a CSRF token. An attacker can craft a malicious form that forces an authenticated victim to modify their account settings.

## Source

HTTP POST request data from `request.form`, which provides untrusted user-supplied values for display_name, contact_email, and timezone.

## Fix

Replace `wtforms.Form` with `flask_wtf.FlaskForm` and add CSRF protection via `CSRFProtect`:

**Vulnerable code:**
```python
from flask import Blueprint, current_app, redirect, render_template, request, session, url_for
from wtforms import Form, StringField, validators

class AccountSettingsForm(Form):
    """Plain wtforms.Form - no CSRF token field or check, unlike FlaskForm."""
    display_name = StringField(
        "Display name", [validators.Length(min=1, max=80)]
    )
    contact_email = StringField(
        "Contact email", [validators.Email(), validators.Length(max=120)]
    )
    timezone = StringField(
        "Timezone", [validators.Length(min=1, max=64)]
    )

@account_bp.route("/account/settings", methods=["GET", "POST"])
def account_settings():
    user = _load_current_user()
    if user is None:
        return redirect(url_for("auth.login"))

    form = AccountSettingsForm(request.form)

    if form.validate():
        # SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
        current_app.db.users.update_one({"id": user["id"]}, {"$set": {
            "display_name": form.display_name.data,
            "contact_email": form.contact_email.data,
            "timezone": form.timezone.data,
        }})
        return redirect(url_for("account.account_settings"))

    return render_template("account_settings.html", form=form, user=user)
```

**Fixed code:**
```python
from flask import Blueprint, current_app, redirect, render_template, request, session, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, validators

class AccountSettingsForm(FlaskForm):
    """FlaskForm with automatic CSRF token validation."""
    display_name = StringField(
        "Display name", [validators.Length(min=1, max=80)]
    )
    contact_email = StringField(
        "Contact email", [validators.Email(), validators.Length(max=120)]
    )
    timezone = StringField(
        "Timezone", [validators.Length(min=1, max=64)]
    )

@account_bp.route("/account/settings", methods=["GET", "POST"])
def account_settings():
    user = _load_current_user()
    if user is None:
        return redirect(url_for("auth.login"))

    form = AccountSettingsForm()

    if form.validate_on_submit():
        # CSRF token is now validated automatically by FlaskForm
        current_app.db.users.update_one({"id": user["id"]}, {"$set": {
            "display_name": form.display_name.data,
            "contact_email": form.contact_email.data,
            "timezone": form.timezone.data,
        }})
        return redirect(url_for("account.account_settings"))

    return render_template("account_settings.html", form=form, user=user)
```

## Explanation

The vulnerability arises because `wtforms.Form` validates only field format and type, not request origin. By switching to `flask_wtf.FlaskForm`, the form automatically generates a cryptographically random CSRF token, binds it to the session, and validates the token during form submission. The form no longer accepts requests that lack a valid CSRF token, preventing forged cross-site requests. Additionally, `validate_on_submit()` is the proper method for FlaskForm, which validates both the CSRF token and field validators, and returns false for non-POST/PUT/PATCH/DELETE requests. The template must include `{{ form.csrf_token() }}` in the form to render the hidden token field that the POST request will submit.

## Behaviour changes

**Import statement**: Changed from `from wtforms import Form` to `from flask_wtf import FlaskForm` to gain automatic CSRF protection. Flask-WTF must be installed as a dependency.

**Form instantiation**: Changed from `AccountSettingsForm(request.form)` to `AccountSettingsForm()`. FlaskForm automatically accesses the request context to retrieve form data, so passing `request.form` is not needed and not recommended. This is the standard FlaskForm pattern.

**Validation method**: Changed from `form.validate()` to `form.validate_on_submit()`. The new method validates the CSRF token during form processing and also returns `False` for GET requests, making the code more explicit about which HTTP methods the form accepts. The sink contract remains unchanged—the database update only occurs when the form validates successfully, now with CSRF verification included.

**Template requirement**: The template `account_settings.html` must include `{{ form.csrf_token() }}` as a hidden field in the form. If not already present, add it:
```html
<form method="POST">
    {{ form.csrf_token() }}
    <!-- other form fields -->
</form>
```

**Session cookie configuration**: Add `SESSION_COOKIE_SAMESITE='Strict'` to Flask configuration for defence-in-depth. This is not required for the CSRF fix to work, but it provides an additional layer of protection by preventing the session cookie from being transmitted in cross-site requests.
