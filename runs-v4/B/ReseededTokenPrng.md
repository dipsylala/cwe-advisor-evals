# ReseededTokenPrng - CWE-338

- **CWE:** CWE-338 (Use of Cryptographically Weak PRNG)
- **Location:** `evals/cases/338/python/ReseededTokenPrng/ReseededTokenPrng.py`, line 20
- **Confidence:** high

## Verdict

`exploitable`.

The value being generated is a password-reset token - a credential whose whole security property is that nobody but the intended recipient can guess it. It is produced by `random.choice()`, which draws from the `random` module's Mersenne Twister generator. MT19937 is a linear, fully invertible generator: its outputs are designed to be well-distributed, not unpredictable, and observed output reveals internal state. Reseeding it does not change that property.

The `random.seed(os.urandom(32))` call on line 16 looks like it closes the gap, and it is worth being precise about what it does and does not do. It does not lose entropy - `Random.seed()` on a `bytes` argument folds the full 32 bytes (plus a SHA-512 of them) into the seed, so the initial state is genuinely unpredictable. What it cannot do is make the output stream resistant to state recovery, and it introduces two problems of its own:

1. **Shared global state under concurrency.** `random.seed()` and `random.choice()` both act on the single process-wide `random.Random` instance. A Flask handler runs concurrently across threads or workers, so two overlapping `/password-reset` requests interleave on one generator: one request's seed lands after the other has already seeded, and both then draw from the same stream. An attacker who requests a reset for an address they control, concurrently with the victim's request, receives a token drawn from that same interleaved stream and learns 32 sampled positions of it - direct information about the token the victim receives. That is the practical path from "predictable generator" to "account takeover", and it exists only because the generator is global and shared.
2. **Collateral damage to other consumers.** Any other code in the process that uses the module-level `random` - a library's retry jitter, a sampling decision - has its stream reset on every reset request. Nothing here depends on that, but it is a side effect of the reseed that a reader should not have to reason about.

The token is also returned directly in the HTTP response to whoever posted the email address, so the generator's output is observable by an unauthenticated caller. That makes it exactly the case the guidance flags: observable by someone not entitled to what it protects, and guessing it grants access rather than merely revealing information.

## Source

- **Source:** `random.choice(alphabet)` (line 20), drawing from the module-level Mersenne Twister generator seeded at line 16 by `random.seed(os.urandom(32))`.
- **Sink:** `token` at lines 22-23 - used as the key of `RESET_TOKENS`, binding the token to `email`, and returned to the caller via `jsonify(token=token)`.
- **Path:** `random.choice()` -> `"".join(...)` -> `token` -> `RESET_TOKENS[token] = email` and the JSON response body.

Existing sink contract, which the fix has to preserve:

- **Returns:** a 32-character string over `string.ascii_letters + string.digits` (62 symbols, `[A-Za-z0-9]{32}`). Used as a dict key and serialised into JSON, so it must stay a `str` and stay JSON-safe.
- **Discards:** nothing. Every generated character reaches both the dict key and the response.
- **Implicit arguments:** `range(32)` fixes the length; `alphabet` fixes the character set. Neither has a default being relied on.
- **Failure behaviour:** the generator does not raise for this input, so the handler has no error path around token generation. Note that `RESET_TOKENS[token] = email` silently overwrites on a duplicate token - there is no collision check, so the replacement must not make duplicates more likely.

## Fix

No library dependency is required - `secrets` is in the Python standard library (3.6+). No manifest change, and therefore no SCA check, is needed for this fix.

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

    # PROBLEM: seeds and draws from the process-wide Mersenne Twister generator.
    # Strong seed material does not make MT19937 a CSPRNG - its output stream is
    # linear and state-recoverable, and the generator is shared across concurrent
    # requests, so one caller's token leaks information about another's.
    random.seed(os.urandom(32))
    alphabet = string.ascii_letters + string.digits

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

    token = "".join(secrets.choice(alphabet) for _ in range(32))

    RESET_TOKENS[token] = email
    return jsonify(token=token)
```

`secrets.choice()` is the right call here because the token's shape is load-bearing: it keeps the length at 32 and the alphabet at `[A-Za-z0-9]`, so anything that already parses, stores, or pattern-matches these tokens keeps working. Where the format is not constrained, `secrets.token_urlsafe(32)` is the more idiomatic call, but it returns roughly 43 characters and includes `-` and `_`, which changes the token format and is not a like-for-like substitution in this handler.

## Explanation

The token generator moves from `random` to `secrets`. Each character now comes from `secrets.choice()`, which draws from the operating system's CSPRNG (`os.urandom` via `SystemRandom`) with unbiased rejection sampling, instead of from the `random` module's Mersenne Twister. This eliminates the weakness at its root rather than papering over it: a CSPRNG's outputs carry no recoverable state, so observing any number of previously issued tokens gives an attacker no advantage in predicting the next one. The explicit `random.seed(os.urandom(32))` goes away because it was only ever an attempt to compensate for the weak generator, and it was itself part of the problem - `secrets` needs no seeding, keeps no state the application can perturb, and holds no shared global that concurrent request handlers can trample. Thirty-two characters over a 62-symbol alphabet is about 190 bits of entropy, which puts both guessing and accidental collision far out of reach. One thing this change does not address, because it is a different weakness: the handler returns the reset token in the response body to whoever posts an email address, so any caller can obtain a valid reset token for any account. A cryptographically strong token is necessary but not sufficient there - the token should be delivered out-of-band to the address on file rather than echoed to the requester.

## Behaviour changes

- **Token values differ from run to run in the same way as before, but come from a different generator.** The output remains a 32-character `[A-Za-z0-9]` string, so length, character set, type, dict-key usage, and JSON serialisation are all unchanged. Any test that asserts on the token's shape still passes; any test that pins exact token values by seeding `random` would already have been broken by the per-request reseed and will not work against `secrets` at all, by design - reproducibility is the property being removed.
- **`random.seed(os.urandom(32))` is removed.** Deliberate, and part of the fix rather than incidental cleanup: it existed only to harden the weak generator, and it mutated process-global generator state on every request. Removing it stops `/password-reset` from resetting the `random` stream underneath any other code in the process that uses the module-level `random`. Nothing in this file read from `random` afterwards, so nothing else depends on it.
- **`import os` and `import random` are removed; `import secrets` is added.** `os` and `random` were used only by the deleted seed line and the replaced `choice` call, so both became unused as a direct result of this change. `string` is retained - `alphabet` still uses it.
- **The `# SAST FINDING:` marker comment on line 19 is dropped**, since it points at a call that no longer exists. No behavioural effect.
- **Failure behaviour is unchanged.** `secrets.choice()` raises `IndexError` only on an empty sequence, which `alphabet` never is; the handler keeps its existing no-error-path shape around token generation.
- **Collision behaviour is unchanged or better.** `RESET_TOKENS[token] = email` still overwrites without a collision check - this fix does not add one, as that is outside the reported weakness - but a CSPRNG over the same 190-bit space makes duplicates no more likely than before, and removes the concurrency-driven stream sharing that could have produced correlated tokens.
- **No change to the route, the request parsing, the response shape, or the `RESET_TOKENS` structure.**

## Assumptions

- The reported line 20 sink is the token generation, and the token is security-relevant. Treated as a finding on the strength of its use as a password-reset credential; the guidance names password-reset tokens explicitly, and no reading of this handler makes the value non-security-relevant.
- The token format (32 characters, alphanumeric) is assumed to matter to callers, since it is returned over the API and used as a lookup key elsewhere. This drove the choice of `secrets.choice()` over `secrets.token_urlsafe()`. If no consumer depends on the format, `secrets.token_urlsafe(32)` is the preferred call.
- The application is assumed to serve requests concurrently, as any production Flask deployment does. The concurrency argument strengthens the verdict but is not load-bearing for it: the fix is required on the state-recovery property of MT19937 alone.
