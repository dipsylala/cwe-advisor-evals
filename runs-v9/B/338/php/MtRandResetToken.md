## Verdict

CWE-338 (Use of a Cryptographically Weak PRNG) - **exploitable**. Confidence: high.

`handlePasswordResetRequest()` generates the password-reset token with `mt_rand()`, a
Mersenne-Twister PRNG that is not cryptographically secure. The token is a security-sensitive
credential (it authorizes a password reset for the account tied to `$email`), so an attacker who
can recover or predict Mersenne Twister state (e.g. by observing other `mt_rand()` output from the
same process, or by brute-forcing the reduced entropy of a six-digit-scale range) can predict or
narrow down valid reset tokens without needing to intercept the email.

## Source

- **Generation point (line 18):** `$token = mt_rand($seed, $seed + 999999);` - a value used as a
  password-reset credential is produced by PHP's non-cryptographic PRNG.
- **Range input (line 16):** `$seed = $request['client_seed'] ?? 0;` - `$seed` comes directly from
  the incoming request and sets the lower bound of the range `mt_rand()` draws from. It is not
  passed to `mt_srand()`, so it does not reseed the generator; it only shifts the window from which
  the weak PRNG picks. This does not by itself change the finding (the window stays 1,000,000 values
  wide regardless of `$seed`), so the fix below preserves the existing range arguments unchanged
  and addresses only the weak generator.
- **Sink (lines 21, 23):** the value is persisted as `reset_token` in the `users` table and then
  emailed to the user as "Use this code to reset your password" - i.e. it is consumed as the
  bearer credential that proves the reset request is legitimate.

## Fix

Vulnerable code:

```php
$seed = $request['client_seed'] ?? 0;
// SAST FINDING: CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)) reported here. Sink is the next statement.
$token = mt_rand($seed, $seed + 999999);
```

Fixed code:

```php
$seed = $request['client_seed'] ?? 0;
$token = random_int($seed, $seed + 999999);
```

## Explanation

The fix replaces `mt_rand()` with `random_int()`, PHP's cryptographically secure integer generator,
per the CWE-338 PHP guidance's primary defence ("use `random_bytes()` or `random_int()` for all
security-critical random value generation") and its specific rule that `random_int()` is the right
choice "for random integers within a specific range." `random_int()` draws from the OS CSPRNG, so
its output cannot be predicted or reproduced even by an attacker who has observed the Mersenne
Twister state from other `mt_rand()` calls in the same process - closing the predictability weakness
that CWE-338 flags. The call arguments and the numeric range they define are left exactly as they
were; only the generator function name changed.

## Behaviour changes

None. `random_int($min, $max)` and `mt_rand($min, $max)` return the same type (an `int` in the
closed range `[$min, $max]`) and are used identically by the caller (stored via the same
`PDO::execute()` parameter binding, and interpolated into the same email string), so the DB write
and the emailed message are unaffected. Failure behaviour is effectively unchanged: PHP 8's
`mt_rand()` already throws `\ValueError` when `$min > $max`, and `random_int()` throws `\Error` for
the same condition (`random_int()` can additionally throw `\Exception` if the OS CSPRNG cannot
supply sufficient randomness, an operational failure with no practical difference in observed
behaviour for this code path). No other line was touched.

Assumption: `$seed` is left unvalidated exactly as in the original code, since validating or
constraining request input is outside the scope of this CWE-338 finding, which concerns the choice
of generator rather than the bounds passed to it.
