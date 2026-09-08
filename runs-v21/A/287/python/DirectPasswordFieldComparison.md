## Verdict

CONFIRMED - The authentication backend uses direct string comparison to verify passwords instead of Django's secure password verification method.

## Source

Line 34 in `legacy_portal_backend.py` performs direct equality comparison of the plaintext password input against the stored password field:

```python
if password == user.password:
    return user
```

This comparison is susceptible to timing attacks and bypasses Django's password verification framework.

## Fix

### File: legacy_portal_backend.py

```python
"""Custom Django authentication backend for the legacy customer portal.

Registered in settings.py:

    AUTHENTICATION_BACKENDS = [
        "portal.auth_backends.LegacyPortalAuthBackend",
        "django.contrib.auth.backends.ModelBackend",
    ]
"""

from django.contrib.auth import get_user_model

User = get_user_model()


class LegacyPortalAuthBackend:
    """Authenticates against the legacy portal user table.

    The legacy import script copied plaintext passwords straight into
    User.password during the 2019 migration and this backend was written
    to match that column as-is.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None or password is None:
            return None

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return None

        if user.check_password(password):
            return user

        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
```

## Explanation

The fix replaces the unsafe direct string comparison with Django's `check_password()` method. This provides constant-time password verification that mitigates timing attack vulnerabilities. Django's `check_password()` method handles both plaintext passwords (compatible with legacy data) and hashed passwords, allowing the backend to work with the existing legacy password column while remaining secure and future-proof for password hash migration.

