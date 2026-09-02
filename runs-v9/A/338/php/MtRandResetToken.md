## Verdict

Confirmed. `mt_rand()` is used to generate a password-reset token, and the Mersenne Twister PRNG behind it is not cryptographically secure. Its output is predictable given a handful of samples (or knowledge of its seed), which lets an attacker compute or narrow down valid reset tokens and take over another user's account. The finding is made worse here because the range is derived from `client_seed`, a value read directly from the request: the caller can choose the token's numeric window itself, collapsing the search space to a handful of guesses instead of the already-weak `mt_rand()` output space.

## Source

`$request['client_seed']` (attacker-controlled HTTP input) flows into `$seed` on line 16, which is then used unmodified as the lower bound of the token range on line 18. `$request['email']` is also attacker-controlled but is safely parameterized in the SQL query and is not part of this finding.

## Fix

```php
<?php

// Handles a "forgot password" request and emails the user a reset link.
function handlePasswordResetRequest(PDO $db, array $request): void
{
    $email = $request['email'] ?? '';

    $stmt = $db->prepare('SELECT id FROM users WHERE email = ?');
    $stmt->execute([$email]);
    $userId = $stmt->fetchColumn();

    if ($userId === false) {
        return;
    }

    // Reset token must be unpredictable and independent of any client-supplied input.
    $token = bin2hex(random_bytes(32));

    $update = $db->prepare('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?');
    $update->execute([$token, time() + 3600, $userId]);

    mail($email, 'Password Reset', 'Use this code to reset your password: ' . $token);
}
```

## Explanation

Two changes were needed, not one:

1. **Replace the PRNG.** `mt_rand()` is seeded and produces output using the Mersenne Twister algorithm, which is designed for statistical distribution, not unpredictability, and is not safe for security tokens. PHP's CSPRNG primitives (`random_bytes()`, or `random_int()` for a bounded integer) are drawn from the OS-level cryptographic random source and are the correct replacement wherever the output is used as a credential, token, or key.
2. **Stop deriving the token's value or range from client input.** Even with a correct CSPRNG, seeding or bounding the token with `client_seed` would still let a caller narrow or choose the value space. The fix drops `client_seed` entirely and generates the token as a fixed-length random byte string (`random_bytes(32)`, rendered as hex for storage/emailing), so the token's entropy is independent of anything the requester supplies.

Storing and emailing a long, high-entropy, unpredictable token closes the account-takeover path: an attacker can no longer reduce the guessing space by controlling the seed, nor predict future tokens from observed ones the way they could with `mt_rand()` output.
