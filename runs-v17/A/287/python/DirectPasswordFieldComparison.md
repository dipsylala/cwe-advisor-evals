## Verdict
CWE-287: Direct plaintext password comparison vulnerability confirmed on line 34.

## Source
Line 34 uses direct string equality comparison (`password == user.password`) to validate user credentials, which violates proper authentication mechanisms and introduces timing attack vectors.

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

        # Use Django's check_password() for constant-time comparison
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
Replace the direct plaintext comparison `password == user.password` with Django's `check_password()` method. This addresses CWE-287 by:

1. **Proper authentication mechanism**: Django's `check_password()` uses the framework's built-in password verification, which handles both hashed and plaintext passwords correctly.
2. **Timing attack prevention**: `check_password()` implements constant-time comparison to prevent attackers from inferring password correctness through response timing variations.
3. **Future-proof hashing support**: When passwords are eventually migrated to proper hashing (SHA-256, bcrypt, etc.), `check_password()` will automatically verify against those hashes without code changes.

The method works regardless of whether the stored password is plaintext (legacy state) or properly hashed (future state), making it the correct sink for authentication validation in Django.
