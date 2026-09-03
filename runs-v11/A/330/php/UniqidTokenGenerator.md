## Verdict
The code uses `uniqid()` with a user-supplied prefix to generate a password reset token. This violates CWE-330 because `uniqid()` is not cryptographically secure — it relies on the server's microtime and hostname, both of which are predictable. An attacker can enumerate valid reset tokens.

## Source
Line 20 generates the token:
```php
$resetToken = uniqid($prefix, true);
```

The prefix comes from untrusted user input on line 18:
```php
$prefix = $post['client_nonce'] ?? '';
```

## Fix
Replace the token generation with cryptographically secure randomness:

```php
$resetToken = bin2hex(random_bytes(32));
```

Remove or ignore the user-supplied prefix — do not incorporate it into the token. The token itself must be generated entirely by the server using a secure source of entropy.

## Explanation
`uniqid()` is designed for uniqueness, not security. It generates values based on the current Unix timestamp in microseconds plus the server hostname, making tokens predictable within a narrow time window. An attacker can brute-force or predict reset tokens without knowing the prefix.

`random_bytes(32)` generates 32 bytes (256 bits) of cryptographically secure random data from the operating system's entropy pool. `bin2hex()` converts the raw bytes to a hexadecimal string safe for transport in URLs and databases.

The user-supplied `client_nonce` should not influence the token — token generation must be entirely under the server's control. If a nonce is needed for request validation, store it separately and verify it, but never mix it into security-critical tokens.
