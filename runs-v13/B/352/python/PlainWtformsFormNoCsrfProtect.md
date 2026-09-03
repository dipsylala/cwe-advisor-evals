## Verdict

The finding is valid. The account settings endpoint processes authenticated state-changing requests without CSRF token validation. A plain `wtforms.Form` lacks CSRF protection, and no global CSRF middleware or decorator is deployed.

## Source

POST request data via `request.form`, reaching the handler at line 30-47. The form is instantiated at line 36 from untrusted request.form without any CSRF token verification.

## Fix

Replace `wtforms.Form` with `flask_wtf.FlaskForm`. This automatically includes a CSRF token field and validates it during form submission.

**Import change** (top of file):
```python
from flask_wtf import FlaskForm
```

Remove or update:
```python
from wtforms import Form, StringField, validators
```

**Class definition** (lines 9-20):
```python
class AccountSettingsForm(FlaskForm):
    """Flask-WTF form with automatic CSRF token validation."""

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

**No changes required to the route handler** (lines 30-47). The form's `validate()` call automatically checks the CSRF token as part of Flask-WTF's `FlaskForm.validate_on_submit()` contract. The form will reject POST requests without a valid CSRF token before reaching line 40.

**Template requirement** (in `account_settings.html`):
Ensure the form rendering includes the CSRF token field:
```html
<form method="POST">
    {{ form.csrf_token }}
    <!-- other form fields -->
</form>
```

## Explanation

`FlaskForm` from Flask-WTF automatically generates, tracks, and validates CSRF tokens. When the form is rendered in the template, `{{ form.csrf_token }}` includes a hidden input field containing the server-generated token. On submission, Flask-WTF validates that the token in the POST request matches the one bound to the session before allowing `form.validate()` to proceed. This prevents Cross-Site Request Forgery by ensuring the browser-side confirmation of origin. The token is automatically managed by Flask-WTF and does not require manual handling in the view handler.

## Behaviour changes

- POST requests to `/account/settings` without a valid CSRF token will now fail form validation and the database update will not execute.
- The form now includes a hidden `csrf_token` field that must be present in the HTML form for submissions to succeed.
- Legitimate form submissions from the application's own pages continue to work because the CSRF token is automatically populated and validated.
- Any external or programmatic POST requests to this endpoint without the CSRF token will be rejected.
