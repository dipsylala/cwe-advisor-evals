## Verdict

Exploitable. The backend's `authenticate()` method performs a direct plaintext comparison (`password == user.password`) instead of using Django's `check_password()` method, which bypasses the framework's password hashing verification layer and is vulnerable to timing attacks on the password verification itself.

## Source

`password` parameter supplied by the caller to `authenticate(self, request, username=None, password=None, **kwargs)` at line 24.

## Sink

Line 34: `if password == user.password:` - direct comparison of user-supplied password to stored password without using Django's cryptographic verification.

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
from django.contrib.auth.hashers import check_password, make_password

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
            # Timing attack mitigation: perform password verification on unknown
            # usernames to avoid leaking information about account existence
            check_password(password, make_password(password))
            return None

        # Use Django's check_password for proper password verification
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

The fix replaces the insecure direct password comparison with Django's `check_password()` method, which properly delegates to the configured password hashers. This ensures password verification is performed through cryptographic functions rather than plaintext comparison. Additionally, timing attack mitigation is added by performing a hashing operation against a dummy password when the username does not exist, preventing attackers from using response-time analysis to enumerate valid usernames. The fix imports `check_password` and `make_password` from `django.contrib.auth.hashers`, both standard Django APIs. The `User.DoesNotExist` branch now calls `check_password(password, make_password(password))` to maintain constant-time verification regardless of whether the user exists, closing the timing oracle.

## Behaviour changes

- **Added imports**: `check_password` and `make_password` from `django.contrib.auth.hashers` - standard Django cryptographic utilities.
- **Changed verification path**: Replaced direct string comparison with `user.check_password(password)`, which delegates to Django's configured `PASSWORD_HASHERS` for proper cryptographic verification instead of plaintext comparison.
- **Added timing attack mitigation**: User.DoesNotExist branch now performs `check_password(password, make_password(password))` instead of silently returning `None`, ensuring consistent verification time whether the account exists or not.
- **Functional impact on plaintext passwords**: If the application stores plaintext passwords and has no plaintext password hasher configured in `PASSWORD_HASHERS`, authentication will fail until either: (1) a plaintext hasher is added as a temporary migration measure, or (2) stored passwords are hashed using Django's standard hashers. This is the correct security posture - the plaintext storage is itself a separate vulnerability (CWE-256) that should be addressed during password migration.
