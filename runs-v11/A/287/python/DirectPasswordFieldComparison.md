## Verdict

**CWE-287: Improper Authentication** — Direct plaintext password comparison allows authentication bypass if the database is compromised or if password equality checking is predictable.

## Source

**File:** `evals/cases/287/python/DirectPasswordFieldComparison/legacy_portal_backend.py`  
**Line:** 34  
**Code:**
```python
if password == user.password:
    return user
```

The vulnerability occurs because the `authenticate` method compares the incoming plaintext password directly against the stored password using Python's `==` operator. This bypasses Django's built-in password hashing and verification mechanism.

## Fix

Replace the direct comparison with Django's `check_password()` utility:

```python
from django.contrib.auth.hashers import check_password

# In the authenticate method:
if check_password(password, user.password):
    return user
```

**Migration path:** After applying this fix, migrate stored plaintext passwords to hashed form. Django provides `make_password()` to hash existing plaintext passwords before storing them:

```python
from django.contrib.auth.hashers import make_password

# One-time migration script:
for user in User.objects.all():
    if not user.password.startswith('!'):  # Check if already hashed
        user.password = make_password(user.password)
        user.save()
```

After migration, `check_password()` will automatically verify hashed passwords correctly.

## Explanation

**Why this is a vulnerability:** Storing passwords in plaintext and comparing them directly violates fundamental authentication principles. If the database is breached, an attacker gains immediate access to all user accounts. Additionally, direct string comparison can be vulnerable to timing attacks if not constant-time.

**Why the fix works:** Django's `check_password()` function:
- Handles both plaintext (legacy) and hashed password verification transparently
- Uses constant-time comparison to prevent timing attacks
- Supports multiple hashing algorithms (PBKDF2, bcrypt, Argon2, scrypt)
- Automatically identifies the hashing algorithm used and applies the correct verification method

**Key principle:** Passwords must never be stored in plaintext. Use Django's built-in `make_password()` to hash on storage and `check_password()` to verify on authentication. The `check_password()` function provides defense-in-depth against both compromise scenarios (plaintext storage exposure, timing attacks) and supports transparent algorithm migration.

**Verification:** After applying the fix, confirm that:
1. The authenticate method uses `check_password()` instead of `==`
2. Stored plaintext passwords are migrated to hashed form
3. Test authentication still succeeds with the correct password
4. Test authentication fails with an incorrect password
