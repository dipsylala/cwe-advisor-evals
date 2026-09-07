## Verdict

Exploitable. A password-reset token is generated using `random.choice()`, a cryptographically weak PRNG (Mersenne Twister), making it predictable despite the seed from `os.urandom()`. The underlying algorithm remains compromised.

## Source

Password-reset token generation triggered by request to `/password-reset` endpoint (line 20).

## Fix

**Vulnerable code:**
```python
import os
import random
import string

from flask import Flask, jsonify, request

app = Flask(__name__)

RESET_TOKENS = {}

@app.post("/password-reset")
def request_password_reset():
    email = request.form["email"]

    random.seed(os.urandom(32))
    alphabet = string.ascii_letters + string.digits

    # SAST FINDING: CWE-338 (Use of Cryptographically Weak PRNG) reported here. Sink is the next statement.
    token = "".join(random.choice(alphabet) for _ in range(32))

    RESET_TOKENS[token] = email
    return jsonify(token=token)
```

**Fixed code:**
```python
import secrets
import string

from flask import Flask, jsonify, request

app = Flask(__name__)

RESET_TOKENS = {}

@app.post("/password-reset")
def request_password_reset():
    email = request.form["email"]

    alphabet = string.ascii_letters + string.digits

    # Use cryptographically secure random generation for tokens
    token = "".join(secrets.choice(alphabet) for _ in range(32))

    RESET_TOKENS[token] = email
    return jsonify(token=token)
```

## Explanation

The fix replaces Python's `random` module with the `secrets` module, which is cryptographically secure and designed for security-sensitive operations. `secrets.choice()` uses `os.urandom()` internally and does not require manual seeding. The dangerous token generation at line 20 now uses a CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) rather than Mersenne Twister. The imports are simplified by removing the `os` and `random` imports that are no longer needed, and the manual seeding logic is eliminated. The token format and length remain the same, preserving the application contract.

## Behaviour changes

- **Removed imports**: `os` and `random` are no longer needed; `secrets` is added to standard library imports.
- **Removed seeding**: The `random.seed(os.urandom(32))` call is eliminated. `secrets` handles seeding automatically through the OS entropy source.
- **Token generation unchanged**: Token format (32-character alphanumeric string) and storage in `RESET_TOKENS` dictionary remain identical.
- **Reason**: Manual seeding with `os.urandom()` does not compensate for Mersenne Twister's predictability; the CSPRNG in `secrets` is the required replacement for security-sensitive token generation.

