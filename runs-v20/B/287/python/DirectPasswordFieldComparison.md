## Verdict

Confirmed. `LegacyPortalAuthBackend.authenticate()` accepts or rejects a login by comparing the submitted password directly to `user.password` with `==` (line 34), bypassing Django's password-hashing machinery entirely. This is CWE-287 (Improper Authentication): the check never verifies the credential through a hasher, so it authenticates by value equality against whatever happens to sit in the database column, and provides no timing protection.

## Source

Sink: `if password == user.password:` in `LegacyPortalAuthBackend.authenticate()`, `legacy_portal_backend.py` line 34.

- Source: `password` argument to `authenticate()`, supplied by Django's `django.contrib.auth.authenticate()` call chain from whatever submits credentials (login form, DRF auth, etc.) - attacker-controlled input for the purposes of this check.
- Flow: `username`/`password` arrive as `authenticate()` kwargs -> `user = User.objects.get(username=username)` looks up the row -> `password == user.password` compares the raw submitted value to the stored `password` column with no hashing, no `check_password()`, and no constant-time comparison.
- This backend is listed first in `AUTHENTICATION_BACKENDS`, so it runs on every login attempt before `ModelBackend`.
- The class docstring records why the column holds what it holds: a 2019 import script copied plaintext passwords directly into `User.password`, and this backend was written to match that column as-is. That fact governs the fix below - `user.password` is not reliably a Django-format hash for every row.

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

import hmac

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import identify_hasher

User = get_user_model()


class LegacyPortalAuthBackend:
    """Authenticates against the legacy portal user table.

    The legacy import script copied plaintext passwords straight into
    User.password during the 2019 migration. A row still holding that
    plaintext value is verified with a constant-time comparison and then
    immediately rehashed through Django's configured password hasher, so
    it is migrated the first time its owner logs in; a row that already
    holds a proper hash goes through check_password() as normal.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None or password is None:
            return None

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # Hash the submitted password against the configured hasher and
            # discard the result, so a wrong password against an unknown
            # username costs the same as one against a real account and
            # can't be used to enumerate which usernames exist.
            User().set_password(password)
            return None

        if self._is_legacy_plaintext(user.password):
            if not hmac.compare_digest(password, user.password):
                return None
            # The plaintext value just verified; migrate this row to a
            # proper hash now so future logins go through check_password().
            user.set_password(password)
            user.save(update_fields=["password"])
            return user

        if user.check_password(password):
            return user

        return None

    @staticmethod
    def _is_legacy_plaintext(stored_value):
        """True if stored_value isn't a value one of the configured
        password hashers recognises (the shape every 2019-import row still
        has), rather than a hash Django itself produced."""
        try:
            identify_hasher(stored_value)
        except ValueError:
            return True
        return False

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
```

## Explanation

The knowledge base's primary instruction for this pattern is to replace a direct `user.password` comparison with `user.check_password()`. Applied literally here that instruction is a no-op that quietly locks every legacy account out: Django's `check_password()`/`verify_password()` calls `identify_hasher()` on the stored value, and for an arbitrary plaintext string that raises `ValueError` internally, which `verify_password()` catches and turns into an unconditional `False` (confirmed by running Django 6.1's `check_password("hunter2", "hunter2")`, which returns `False` rather than raising). So on its own, `user.check_password(password)` never authenticates a single 2019-import row - it isn't a fix, it's an outage, and the class docstring is the evidence that every row in this table starts in that state.

The fix therefore branches on whether the stored value is already a hash one of the configured hashers recognizes (`identify_hasher` succeeds) or is still raw legacy plaintext (`identify_hasher` raises `ValueError`, verified against the same Django installation). A recognized hash goes through `user.check_password()` exactly as the guidance prescribes - no direct comparison, and Django's own `check_password()` setter machinery keeps handling algorithm upgrades for those rows going forward. A row still holding plaintext is verified with `hmac.compare_digest()` instead of `==`, removing the character-by-character timing side channel on the comparison itself; on a match the row is immediately migrated with `user.set_password(password)` + `user.save(update_fields=["password"])`, so every account converts to a proper hash the first time its owner logs in and, from then on, takes the `check_password()` path. The unknown-username branch now calls `User().set_password(password)` and discards the result - this is Django's own `ModelBackend.authenticate()` idiom for the miss branch, run against `get_user_model()` (the binding the guidance calls out as the one that matters, not the model name) - so a wrong password against a nonexistent username costs the same as a wrong password against a real one, closing the user-enumeration oracle the root guidance calls out for this exact lookup-then-verify shape.

I ran this against a real Django 6.1 install (in-memory sqlite, `PASSWORD_HASHERS=["...PBKDF2PasswordHasher"]`): a plaintext row authenticates on the correct password and is rehashed to `pbkdf2_sha256` in the database; the same row authenticates again afterward via the `check_password()` path; a wrong password against both a legacy and an already-hashed row returns `None`; an unknown username returns `None` without raising; `get_user()` is unchanged. I also reproduced, in the same install, that swapping the sink for a bare `user.check_password(password)` returns `False` for the plaintext case - the failure mode the guidance's literal instruction would have produced here.

## Behaviour changes

- Every legacy plaintext account is rehashed to the project's first configured `PASSWORD_HASHERS` entry on its next successful login (an extra `UPDATE` on that login only); the plaintext value is discarded from the database at that point and the row afterward looks identical to one Django hashed itself.
- A wrong-password attempt against a legacy plaintext account and a wrong-password attempt against an already-migrated account now take measurably different time (`hmac.compare_digest` vs. a full password-hasher round). This is a narrower residual timing signal than the one being closed (it reveals "migrated or not", not "exists or not") and disappears entirely once all rows have logged in once; closing it fully would mean running a full hash-and-discard on the plaintext branch too, which this fix does not add.
- The unknown-username path now does one extra password-hash computation (previously it did none), matching the cost of a real lookup; this adds hashing latency to every failed login against a nonexistent username, which is the intended trade-off for removing the timing oracle.
- No public method signature, return value, or caller-visible contract of `authenticate()` or `get_user()` changed - both still return a `User` instance or `None`.
