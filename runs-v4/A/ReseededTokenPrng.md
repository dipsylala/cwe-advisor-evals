# CWE-338: Use of Cryptographically Weak PRNG - ReseededTokenPrng.py

## Verdict

Confirmed. Line 20 generates a password-reset token with `random.choice`, which draws from the
`random` module's Mersenne Twister generator. Mersenne Twister is a statistical PRNG, not a
cryptographic one: its output is designed to look uniform, not to be unpredictable to an observer.
A password-reset token is a bearer credential - anyone holding it can take over the account it
belongs to - so it must come from a cryptographically secure source.

The `random.seed(os.urandom(32))` call on line 16 looks like a mitigation but is not one. Seeding
does not change the algorithm; it only changes where in the sequence the generator starts. Mersenne
Twister makes no attempt to conceal its internal state, and that state is recoverable from the
output it produces, no matter how the state was originally seeded. An attacker who requests a reset
for an account they control, harvests the tokens returned to them, and recovers the generator state
can then derive the token issued to a victim from the same generator. The strong seed raises the
work factor for that recovery slightly; it does not prevent it. Treat "seeded from `os.urandom`" as
a non-fix wherever it appears.

Two further properties of this code make the exposure worse rather than better:

- `random`'s module-level functions are a single shared `Random` instance for the whole process.
  Under a threaded WSGI server every request handler draws from that one generator, so tokens for
  different users are consecutive outputs of the same stream - exactly the observation an attacker
  needs. Any other code anywhere in the process that calls `random.seed()` with a predictable value
  (a test helper, a data-generation script, a library seeding for reproducibility) silently makes
  every subsequent token predictable.
- Re-seeding on every request is a global side effect performed from inside a request handler. It
  resets shared state that other parts of the application may be relying on, and it buys no
  security here.

## Source

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

    token = "".join(random.choice(alphabet) for _ in range(32))

    RESET_TOKENS[token] = email
    return jsonify(token=token)
```

## Fix

Replace the generator with the `secrets` module, which is backed by the operating system's CSPRNG
(`os.urandom`) and is the standard library's designated source for tokens, keys, and other secrets.
`secrets.choice` is the direct, drop-in counterpart to `random.choice`, so the token keeps its
existing 32-character alphanumeric shape and no storage, comparison, or client-side code has to
change:

```python
import secrets
import string

from flask import Flask, jsonify, request

app = Flask(__name__)

RESET_TOKENS = {}

ALPHABET = string.ascii_letters + string.digits


@app.post("/password-reset")
def request_password_reset():
    email = request.form["email"]

    token = "".join(secrets.choice(ALPHABET) for _ in range(32))

    RESET_TOKENS[token] = email
    return jsonify(token=token)
```

Changes:

- `random.choice` becomes `secrets.choice`. This is the whole fix for the reported weakness.
- The `random.seed(os.urandom(32))` line is deleted. It was only ever there to make the weak
  generator look acceptable, and `secrets` needs no seeding - it reads from the OS entropy pool on
  every call.
- `import random` and `import os` are dropped, as nothing else in the file used them. Leaving
  `import random` in place is worth avoiding beyond tidiness: it is what a reviewer or a future
  scanner run will grep for in a file that mints credentials.
- The alphabet moves to a module-level `ALPHABET` constant, since it was rebuilt on every request
  and never varies.

If you would rather not carry an explicit alphabet at all, `secrets.token_urlsafe(24)` is the more
idiomatic form and produces a 32-character URL-safe token with 192 bits of entropy. It is the
better choice for new code; `secrets.choice` is used above because it preserves the existing token
format exactly, which matters if any tokens are already in flight or if downstream code validates
the character set.

Both are safe. What matters is that the bytes originate from the OS CSPRNG rather than from
Mersenne Twister.

## Explanation

**Why the seed is not the fix.** The distinction this finding turns on is between a generator that
is *statistically* random and one that is *unpredictable*. Mersenne Twister satisfies the first and
makes no claim to the second - `random`'s own documentation carries an explicit warning steering
security uses to `secrets`. Its 19937-bit state is transformed by a public, invertible tempering
function, so the outputs are a window onto the state rather than a one-way function of it.
Recovering that state from truncated output (which is what `choice` over a 62-character alphabet
yields - a handful of bits per character, with rejection sampling discarding some draws) is not a
closed-form calculation, but it is a well-understood constraint-solving problem that off-the-shelf
SMT-solver tooling handles given enough sampled output. An attacker who can request reset tokens
for their own account at will has an unlimited supply of that output.

A CSPRNG closes this by construction: its output is a one-way function of its state, so observing
any quantity of output leaves the attacker no better placed to predict the next value. That is the
property a bearer credential needs, and it is why the fix is a change of generator rather than a
change of seeding.

**Sizing.** 32 characters from a 62-symbol alphabet is roughly 190 bits of entropy, well above the
128-bit floor generally recommended for a bearer token, so there is no need to lengthen it while
making this change. Length was never the weakness here - the source of randomness was.

**Where else to look.** `random.seed(...)` immediately before a security-relevant draw is a
recognisable pattern, usually added in response to an earlier scanner finding. Wherever it appears,
the draw itself still needs replacing. When auditing the rest of this codebase, search for
`random.` alongside the values that must be unpredictable - session identifiers, password-reset and
email-verification tokens, API keys, CSRF tokens, nonces, salts, OTPs, invitation codes, and
temporary passwords - rather than searching for `seed`. Each of those should be reached via
`secrets` (or `os.urandom` for raw bytes). `random.SystemRandom` is also CSPRNG-backed and safe if
you need the `random.Random` method surface, but prefer `secrets` for new code because the intent
is legible at the call site. `random` remains entirely appropriate for simulations, sampling, test
fixtures, jitter, and shuffling non-sensitive data.

**Adjacent hardening, outside this finding.** Two things about this handler are worth a follow-up
ticket, though neither is the reported weakness and neither is included in the fix above:

- The token is stored in plaintext in `RESET_TOKENS` and used directly as the dictionary key. Reset
  tokens are password-equivalent while valid; storing a hash of the token and looking up by hash
  limits the damage if that store is ever read out through a debug endpoint, a log dump, or a
  memory disclosure.
- The token has no expiry and is never invalidated after use, so it stays valid indefinitely. Reset
  tokens should be single-use and short-lived, typically 15 to 60 minutes.

Returning the token in the HTTP response rather than emailing it is presumably an artefact of this
sample rather than the real flow, but if it reflects production behaviour it defeats the purpose of
the token entirely and should be raised separately.
