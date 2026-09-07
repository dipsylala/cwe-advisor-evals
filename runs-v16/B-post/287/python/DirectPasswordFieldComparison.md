## Verdict
Exploitable

## Source
The `password` parameter passed to the `authenticate()` method at line 24.

## Sink
Line 34: Direct string comparison `if password == user.password:` instead of using Django's password verification.

## Fix

**Vulnerable code:**

```python
def authenticate(self, request, username=None, password=None, **kwargs):
    if username is None or password is None:
        return None

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return None

    if password == user.password:  # VULNERABLE: Direct comparison
        return user

    return None
```

**Fixed code:**

```python
def authenticate(self, request, username=None, password=None, **kwargs):
    if username is None or password is None:
        return None

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        # Timing-attack mitigation: hash a dummy password to prevent
        # username enumeration via response-time analysis.
        dummy_user = User(username=username)
        dummy_user.set_password("placeholder")
        dummy_user.check_password(password)
        return None

    if user.check_password(password):
        return user

    return None
```

## Explanation
The original code compares the submitted password directly to the stored password hash using Python's `==` operator, which violates Django's authentication contract and CWE-287. The stored `user.password` field contains a password hash (from the legacy import), but the code treats it as if it were plaintext. This direct comparison bypasses Django's constant-time password verification and allows timing-based attacks. Additionally, the exception handler returns immediately on unknown username without performing verification work, creating a user-enumeration oracle: an attacker can determine whether an account exists by measuring response time.

The fix replaces the direct comparison with `user.check_password(password)`, which uses Django's configured password hasher to perform constant-time comparison regardless of the password content. The fix also adds timing-attack mitigation in the `DoesNotExist` branch by calling `check_password()` on a dummy user, ensuring the backend takes the same time for a valid username with wrong password and an unknown username, closing the enumeration oracle.

## Behaviour changes
- Changed password verification from direct string comparison to Django's `user.check_password()` method, which uses constant-time comparison and respects the configured password hasher algorithm. This is a security improvement with no functional regression—the method still returns the user object or None with identical semantics.
- Added password hashing work in the `DoesNotExist` branch to equalize response time between unknown and known usernames, preventing timing-based user enumeration. This adds latency to the unknown-user path but eliminates the information leak. The return value (None) remains identical.
- The dummy user is instantiated locally and not saved to the database, so no side effects occur.
