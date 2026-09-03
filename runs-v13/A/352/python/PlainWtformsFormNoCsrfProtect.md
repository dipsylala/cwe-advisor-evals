## Verdict
CWE-352 confirmed. The application accepts state-changing POST requests (account settings updates) without validating a CSRF token, allowing attackers to forge requests on behalf of authenticated users.

## Source
The vulnerability is in `account_settings()` at line 40. The form is instantiated using plain `wtforms.Form` (line 36: `AccountSettingsForm(request.form)`), which does not provide CSRF token validation. An attacker can craft a cross-site form submission to update the victim's account settings without their knowledge or consent, because the application does not verify that the request originated from a legitimate form on its own pages.

## Fix
Replace `wtforms.Form` with `FlaskForm` from `flask_wtf`:

```python
from flask import Blueprint, current_app, redirect, render_template, request, session, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, validators

class AccountSettingsForm(FlaskForm):
    """FlaskForm with automatic CSRF token handling."""
    
    display_name = StringField(
        "Display name", [validators.Length(min=1, max=80)]
    )
    contact_email = StringField(
        "Contact email", [validators.Email(), validators.Length(max=120)]
    )
    timezone = StringField(
        "Timezone", [validators.Length(min=1, max=64)]
    )
```

The form instantiation on line 36 requires no code change. `FlaskForm` automatically extracts and validates the CSRF token from the request. In the template (account_settings.html), include the CSRF token field:

```html
<form method="POST">
    {{ form.csrf_token }}
    <!-- other form fields -->
</form>
```

If FlaskForm is not already available, install it: `pip install Flask-WTF`.

## Explanation
`FlaskForm` differs from `wtforms.Form` by integrating with Flask's session and configuration to automatically generate, validate, and manage CSRF tokens. When the form is instantiated with request data, FlaskForm validates that an incoming POST request carries a valid CSRF token matching the one in the user's session. A cross-origin POST from an attacker's site will not have access to the token (protected by the same-origin policy), so the form validation will fail and the state-changing operation will not execute. This is the standard defence against CSRF in Flask applications built with WTForms.
