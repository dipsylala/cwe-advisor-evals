## Verdict

Confirmed. `authenticate()` accepts the credential by comparing the submitted password directly against `user.password` with Python's `==` operator (line 34). This bypasses Django's password-hashing framework entirely: the comparison is not constant-time (a timing side channel leaks how many leading characters match), and it depends on `User.password` holding a plaintext value rather than a hash produced by `django.contrib.auth.hashers.make_password`. Any row that is ever migrated to a proper hash format will silently and permanently fail to authenticate under this code, and any row that stays plaintext remains authenticatable by an attacker who can measure response timing.

## Source

`password` - the credential parameter passed into `LegacyPortalAuthBackend.authenticate(request, username=None, password=None, **kwargs)` by Django's authentication machinery (`django.contrib.auth.authenticate()`), ultimately originating from the login form submission. It flows unmodified to the comparison at line 34 against `user.password`, the value loaded from the database for the matched username.

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
from django.contrib.auth.hashers import check_password, identify_hasher, make_password
from django.utils.crypto import constant_time_compare

User = get_user_model()


class LegacyPortalAuthBackend:
    """Authenticates against the legacy portal user table.

    The legacy import script copied plaintext passwords straight into
    User.password during the 2019 migration. Rows that still hold a
    plaintext value are verified with a constant-time comparison and then
    rehashed in place with Django's password hasher, so each successful
    login migrates that row off plaintext. Rows that already hold a
    recognized hash (either migrated by this backend or created normally)
    are verified with Django's standard check_password.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None or password is None:
            return None

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return None

        try:
            identify_hasher(user.password)
        except ValueError:
            # Legacy row: User.password is still the raw plaintext value.
            if not constant_time_compare(password, user.password):
                return None
            user.password = make_password(password)
            user.save(update_fields=["password"])
            return user

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

`identify_hasher()` inspects the stored value's format and raises `ValueError` when it does not match any registered hasher's encoding - exactly the case for the legacy plaintext rows described in the docstring. That branch verifies the credential with `constant_time_compare()` (Django's own timing-safe comparison, used internally by its hashers) instead of `==`, so the check no longer leaks match-length information through response timing. On success it immediately calls `make_password()` to produce a properly salted hash and persists it back to `user.password`, so the row is migrated off plaintext the first time its owner logs in, rather than staying a standing weakness.

Rows that already hold a recognized hash - either migrated by this backend or created through normal Django user creation - take the other branch and go through `check_password()`, Django's standard hash verification, which is itself constant-time and never regresses to a raw `==` comparison. This also fixes a latent correctness bug: the original code would have permanently locked out any account manually migrated to a real hash, since a hash string will never equal the submitted plaintext password.

No new dependency is introduced; `check_password`, `identify_hasher`, and `make_password` are part of `django.contrib.auth.hashers`, and `constant_time_compare` is part of `django.utils.crypto` - both are stdlib-equivalent modules shipped with Django itself.
