## Verdict

Real vulnerability. Password reset tokens must use cryptographically secure randomness to prevent attackers from guessing or predicting valid tokens and hijacking user accounts.

## Source

File: `evals/cases/338/python/ReseededTokenPrng/ReseededTokenPrng.py`, lines 16–20.

```python
random.seed(os.urandom(32))
alphabet = string.ascii_letters + string.digits

# SAST FINDING: CWE-338 (Use of Cryptographically Weak PRNG) reported here. Sink is the next statement.
token = "".join(random.choice(alphabet) for _ in range(32))
```

The token is used as a password reset token (stored in `RESET_TOKENS` dict and returned to the user).

## Fix

**Step 1:** Add `secrets` module import at the top of the file.

```python
import secrets
```

**Step 2:** Replace lines 16–20 with cryptographically secure alternative:

```python
alphabet = string.ascii_letters + string.digits
token = "".join(secrets.choice(alphabet) for _ in range(32))
```

Remove the `random.seed(os.urandom(32))` call—it is ineffective for securing the Mersenne Twister PRNG and is no longer needed.

**Result:**

```python
import os
import secrets  # Added
import string

from flask import Flask, jsonify, request

app = Flask(__name__)

RESET_TOKENS = {}


@app.post("/password-reset")
def request_password_reset():
    email = request.form["email"]

    alphabet = string.ascii_letters + string.digits
    token = "".join(secrets.choice(alphabet) for _ in range(32))

    RESET_TOKENS[token] = email
    return jsonify(token=token)
```

## Explanation

The `random` module uses the Mersenne Twister algorithm, which is predictable and not suitable for security-sensitive operations. Even when seeded with cryptographic randomness via `os.urandom()`, the Mersenne Twister remains weak—its internal state can still be reconstructed from observed outputs, allowing attackers to forecast future tokens.

The `secrets` module (Python 3.6+) wraps `os.urandom()` and provides cryptographically secure random selection. `secrets.choice()` uses the operating system's cryptographically secure random source to select from a given sequence, making each chosen character unpredictable and preventing token forgery or guessing attacks.

This fix preserves the token format (32 alphanumeric characters) while eliminating the predictability vulnerability.

## Behaviour changes

- Token generation is now unpredictable and non-reproducible across sessions.
- The `random` module is no longer imported or used (it can be removed from the import list).
- No change to token length, format, or API response structure.
- Password reset tokens are now resistant to prediction or reconstruction attacks.
