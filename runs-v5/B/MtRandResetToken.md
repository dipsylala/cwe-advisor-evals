## Verdict

exploitable (confidence: high)

- **CWE:** CWE-338 (Use of Cryptographically Weak PRNG)
- **Location:** `MtRandResetToken.php:18`, inside `handlePasswordResetRequest()`

## Source

- **Source:** `$request['client_seed']` (line 16) - an attacker-controlled value read directly from the incoming password-reset request, with no validation, defaulting to `0` only if absent.
- **Sink:** `mt_rand($seed, $seed + 999999)` (line 18). The result, `$token`, is written to `users.reset_token` (line 20-21) and emailed to the account holder in plaintext (line 23) as the code used to authorize a password reset.
- **Flow:** `$request['client_seed']` -> `$seed` -> both bounds of `mt_rand()` -> `$token` -> persisted reset credential -> emailed to the user.

This is a password-reset token, one of the cases the knowledge base treats as a finding even when the surrounding code looks incidental: it is observable by whoever receives the email, guessing it grants an account takeover (not just an information leak), and it is valid for a full hour (`time() + 3600`), giving ample window for repeated attempts. `mt_rand()` uses the Mersenne Twister, a non-cryptographic PRNG whose internal state can be recovered from a handful of outputs, making future and past tokens predictable. The finding is compounded here: the request also supplies `client_seed`, which becomes the literal lower bound passed into `mt_rand()`, so the token-generation function is taking untrusted input as a direct argument rather than only being reachable from a request handler.

## Fix

No third-party library is required - `random_int()` is a PHP core function (available since PHP 7.0) and needs no dependency-manifest change.

Vulnerable code:

```php
$seed = $request['client_seed'] ?? 0;
// SAST FINDING: CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)) reported here. Sink is the next statement.
$token = mt_rand($seed, $seed + 999999);
```

Fixed code:

```php
$token = random_int(0, 999999);
```

## Explanation

`mt_rand()` is replaced with `random_int()`, PHP's cryptographically secure integer generator, which draws from the OS CSPRNG and cannot be predicted from prior outputs. The fix also drops `client_seed` from the generation path entirely rather than passing it through as the new call's lower bound: the range in the original code was `[$seed, $seed + 999999]`, a caller-chosen offset applied to an otherwise fixed 1,000,000-value span, and a security token's generation should not accept any input from the party the token is meant to authenticate against. Removing it closes that avenue rather than leaving an unexplained, attacker-influenced parameter feeding a security-critical value. The replacement keeps the same integer type and the same size range (1,000,000 possible values, `0` to `999999`) that the sink already consumes, so no other code needs to change.

## Behaviour changes

- `client_seed` from the request is no longer read or used anywhere in token generation. Reason: it was the attacker-controlled input that let the caller choose the base of the "random" range; a reset token must not take input from the requester. If any caller relied on `client_seed` to reproduce a specific token (e.g. for testing), that capability is removed - by design, since reproducibility is exactly what a reset token must not have.
- The generated token's numeric range shifts from `[client_seed, client_seed + 999999]` to the fixed range `[0, 999999]`. Reason: preserves the original 1,000,000-value span and integer type the sink (DB column, email body) already expects, while removing the attacker-supplied offset.
- No change to control flow, database write, email content/format, or error handling - `$token`'s type (int) and downstream usage (line 20-23) are unchanged.
