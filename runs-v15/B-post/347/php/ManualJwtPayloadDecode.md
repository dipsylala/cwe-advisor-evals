## Verdict

exploitable

## Source

`$_SERVER['HTTP_AUTHORIZATION']` — untrusted HTTP Authorization header supplied by the client

## Fix

### Library Recommendation

Upgrade to `firebase/php-jwt` v6.0.0 or later. Pre-6.0.0 versions allow algorithm confusion attacks; v6.0.0+ binds algorithms to keys, preventing this class of attack.

### Vulnerable Code

```php
<?php

// Reads the bearer token from the request and decodes its claims without checking the signature.
function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    $parts = explode('.', $matches[1]);
    if (count($parts) !== 3) {
        return null;
    }

    $payload = strtr($parts[1], '-_', '+/');

    // VULNERABILITY: Decodes payload without verifying the signature.
    $claims = json_decode(base64_decode($payload), true);

    return [
        'id' => $claims['sub'] ?? null,
        'role' => $claims['role'] ?? null,
    ];
}
```

### Fixed Code

```php
<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Reads the bearer token from the request and verifies its signature before trusting claims.
function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    try {
        $secret = $_ENV['JWT_SECRET'] ?? getenv('JWT_SECRET');
        if (!$secret) {
            return null;
        }
        
        $claims = JWT::decode($matches[1], new Key($secret, 'HS256'));
        
        return [
            'id' => $claims->sub ?? null,
            'role' => $claims->role ?? null,
        ];
    } catch (Exception $e) {
        return null;
    }
}
```

## Explanation

The fix replaces manual JWT parsing with cryptographic signature verification using `firebase/php-jwt` v6.0.0+. The key changes are:

1. **Use `JWT::decode()`** instead of manual base64-decoding — this method verifies the signature before returning claims.
2. **Wrap the secret key in `new Key($secret, 'HS256')`** — this binds the key to a specific algorithm, preventing algorithm confusion attacks where an attacker switches the token's `alg` header to bypass verification.
3. **Retrieve the secret from trusted configuration** (e.g., environment variables) — never derive the secret from the token or client input.
4. **Catch verification exceptions** — `JWT::decode()` throws `UnexpectedValueException` on signature mismatch, invalid token format, or algorithm mismatch. The code safely rejects any tampered token.

The library now verifies that the token's signature was computed with the server's secret key using the expected algorithm (HS256). An attacker cannot forge a token with false claims because `JWT::decode()` will reject any signature that does not match.

## Behaviour changes

- **Return type of claims**: `json_decode()` returns an associative array (when passed `true`), but `JWT::decode()` returns a `stdClass` object. Claim access changes from array indexing (`$claims['sub']`) to property access (`$claims->sub`). This is functionally equivalent for the given use case.
- **Error handling**: The original code silently ignored malformed payloads (returning `null` on count check failure). The fixed code wraps the call in a try-catch and returns `null` on any verification failure (invalid format, signature mismatch, expired token, etc.). This is more secure and correctly rejects forged tokens.
- **Configuration dependency**: The fixed code requires `JWT_SECRET` to be set in environment variables or via `getenv()`. If not set, authentication fails (returns `null`). This is correct behaviour — the server must have a configured secret to verify tokens.
- **Standard claim validation**: `JWT::decode()` validates standard claims like `exp` (expiration), `iat` (issued-at), and `nbf` (not-before) by default. If the token is expired or used before its `nbf` time, verification fails. Additional custom claim validation (e.g., `aud`, `iss`) can be added via `$options` parameter if needed.
