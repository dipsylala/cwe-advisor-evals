## Verdict

Exploitable. `account_settings()` authenticates the request purely via the session cookie (`_load_current_user` reads `session.get("user_id")`) and then, on a successful `form.validate()`, performs a state-changing write (`current_app.db.users.update_one`). The form is built from plain `wtforms.Form`, which carries no CSRF token field and performs no token check, so any cross-site page that induces the victim's browser to submit a POST to `/account/settings` (an auto-submitting HTML form, since this is a same-origin-cookie-sent, simple `application/x-www-form-urlencoded` POST that needs no preflight) will have that request authenticated by the ambient session cookie and will change the victim's display name, contact email, and timezone. Confidence: high.

## Source

Cross-site forged POST request to `/account/settings`, authenticated only by the ambient session cookie sent automatically by the browser (`session.get("user_id")` in `_load_current_user`). No origin or token verification exists between this source and the sink.

## Fix

### File: account_settings.py

```python
"""Account settings blueprint: lets a logged-in user update their profile."""

from flask import Blueprint, current_app, redirect, render_template, request, session, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, validators

account_bp = Blueprint("account", __name__)


class AccountSettingsForm(FlaskForm):
    """FlaskForm - carries and validates a CSRF token automatically."""

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

## Explanation

The only change is the form's base class: `AccountSettingsForm` now extends `flask_wtf.FlaskForm` instead of plain `wtforms.Form`. `FlaskForm` adds a hidden `csrf_token` field and, on every call to `validate()` (which `validate_on_submit()` also calls), checks that field against the value bound to the user's session before the rest of validation runs; a request missing the token or carrying a stale/mismatched one fails validation the same way a request with an invalid `display_name` would - `form.validate()` returns `False` and control falls through to `render_template`, so the state-changing `update_one` call is never reached. This closes the gap without touching the sink, the DB call's arguments, or the success/failure return paths, and it requires the corresponding template to render the token (`{{ form.csrf_token }}`) inside the settings `<form>` so legitimate submissions keep succeeding - that template is not part of this file and was not modified here. Library: `Flask-WTF` (import name `flask_wtf`), named directly in the loaded CWE-352/Python guidance; the guidance carries no minimum-safe-version floor for it, so confirm the resolved version with SCA/dependency-check tooling before merging rather than pinning one from memory.

## Behaviour changes

- **GET requests**: no change. `request.form` is empty on GET, so the existing field validators (`Length(min=1)`) already fail `form.validate()`, returning the render-with-form path; the added CSRF check fails for the same empty-body reason and does not change the outcome.
- **Legitimate POST requests**: now require a valid `csrf_token` field in the submitted form data. This is a required, additive dependency on the rendering template (`account_settings.html`, out of scope for this file) including `{{ form.csrf_token }}` inside the `<form>` element - without that addition, genuine submissions would also fail validation and land back on the settings page with a CSRF error. This template change is not included here because the template file is outside the file(s) provided for this fix.
- **Forged/cross-site POST requests**: now rejected by `form.validate()` before the sink is reached - this is the fix, not a side effect.
- **Sink (`current_app.db.users.update_one`)**: arguments, return handling, and failure behaviour are all unchanged.
- **Assumptions**: the Flask application has `SECRET_KEY` configured (required for `FlaskForm`'s CSRF token signing); this is already implied by the existing use of `session` for authentication in `_load_current_user`, since Flask sessions also require `SECRET_KEY`. `flask_wtf.FlaskForm` is named directly by the loaded `cwe/352/python/INDEX.md` guidance, so its name was not independently verified against an installed package in this environment; `python -m py_compile` was run against the fixed file (in a scratch copy, not the case directory) and returned no errors, but the `flask_wtf` package itself was not importable in this environment to confirm resolution - flag this to the maintainer's SCA/dependency check as noted above.
