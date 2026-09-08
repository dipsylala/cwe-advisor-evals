## Verdict

Confirmed. Line 34 compares the submitted password directly to the stored password string instead of using Django's `check_password()` hash verification function, bypassing the application's configured password-hashing mechanism. The code also has a timing-attack vulnerability: it only performs cryptographic work when the user exists, creating a sub-millisecond timing oracle that reveals whether a username is valid.

## Source

**File**: `legacy_portal_backend.py`  
**Lines**: 29-35

The vulnerability occurs in the `authenticate()` method of the `LegacyPortalAuthBackend` class. When a user is found, the code performs a plaintext string comparison:

```python
try:
    user = User.objects.get(username=username)
except User.DoesNotExist:
    return None

# SAST FINDING: CWE-287 (Improper Authentication) reported here.
if password == user.password:  # Line 34: Direct comparison, no hashing
    return user
```

The sink is the comparison on line 34, which accepts a match without verifying the password through Django's configured hash verification. The data flow is: attacker-submitted `password` parameter → direct comparison against `user.password` (stored value) → user returned without proper verification.

The timing oracle is present because line 31 returns immediately for a non-existent user without executing any hash verification, while line 34 executes `check_password()` semantics (via the direct comparison) only for existing users.

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

# Generate a dummy hash for timing-attack mitigation
DUMMY_PASSWORD_HASH = make_password("DUMMY_PASSWORD")


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
            # Check password against dummy hash to prevent timing attacks
            check_password(password, DUMMY_PASSWORD_HASH)
            return None

        # Use Django's check_password to verify credentials securely
        if check_password(password, user.password):
            return user

        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
```

## Explanation

The fix addresses CWE-287 through two complementary changes:

**Primary fix (line 38)**: Replace the direct string comparison `password == user.password` with `check_password(password, user.password)`. This delegates password verification to Django's configured password-hashing algorithm (typically PBKDF2, Argon2, or bcrypt depending on `PASSWORD_HASHERS` settings). The `check_password()` function rehashes the submitted password using the same algorithm and parameters stored in the hash, then performs a constant-time comparison. This prevents the application from accepting plaintext or incorrectly hashed passwords.

**Secondary fix (line 34)**: Add a call to `check_password(password, DUMMY_PASSWORD_HASH)` in the `User.DoesNotExist` exception handler before returning `None`. The `DUMMY_PASSWORD_HASH` is generated once at module import time using `make_password()` with a fixed dummy value. This ensures that whether a user is found or not, the backend always executes the hasher, preventing timing-based user enumeration. An attacker timing the response no longer learns whether a username exists, because both the valid-user and invalid-user branches now spend the same cryptographic time verifying a password.

The imports `check_password` and `make_password` are from `django.contrib.auth.hashers`, which is Django's standard library for secure password handling. Both are widely available in all supported Django versions.

## Behaviour changes

- **Correct password, user exists**: Authentication succeeds and the user is returned (unchanged from the vulnerable code).
- **Incorrect password, user exists**: Authentication fails; `None` is returned (unchanged from the vulnerable code, but now verified through the correct hash comparison).
- **Any password, user does not exist**: Authentication fails; `None` is returned (unchanged from the vulnerable code, but now with timing-attack mitigation).
- **Timing**: All authentication failures (wrong password, missing user) now take approximately the same wall-clock time because both branches execute the hasher. This eliminates the sub-millisecond timing oracle that previously distinguished between invalid usernames and invalid passwords.
- **Hash algorithm**: Password verification now depends on Django's configured `PASSWORD_HASHERS` list. If the list is configured with Argon2, passwords are verified against Argon2 hashes; if PBKDF2, against PBKDF2, etc. Changing `PASSWORD_HASHERS` in settings will affect all future authentication attempts (rehashing on successful login if configured to do so).
