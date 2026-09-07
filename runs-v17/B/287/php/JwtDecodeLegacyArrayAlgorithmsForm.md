## Verdict
Exploitable

## Source
Bearer token from `Authorization` header, extracted at line 35 via regex match into `$jwt` variable at line 39.

## Fix

### File: AuthController.php

```php
<?php

// composer.json (excerpt): "firebase/php-jwt": "^6.0"
// Updated to 6.x line: the array-of-algorithms call form has been removed and replaced
// with the Key class form that pins one explicit algorithm to the key.

namespace App\Http\Controllers;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;

class AuthController
{
    /** PEM-encoded RSA public key used to verify RS256-signed tokens. */
    private string $rsaPublicKey;

    /** Shared HMAC secret used to verify HS256-signed tokens. */
    private string $hmacSecret;

    public function __construct(string $rsaPublicKey, string $hmacSecret)
    {
        $this->rsaPublicKey = $rsaPublicKey;
        $this->hmacSecret = $hmacSecret;
    }

    /**
     * Authenticates an API request from its bearer token and returns the
     * decoded claims, or null if the token is missing or invalid.
     */
    public function authenticateRequest(array $headers): ?object
    {
        $authHeader = $headers['Authorization'] ?? '';
        if (!preg_match('/^Bearer\s+(\S+)$/', $authHeader, $matches)) {
            return null;
        }

        $jwt = $matches[1];
        $publicKey = $this->rsaPublicKey;

        try {
            // CWE-287 FIX: Pin the algorithm to RS256 using the Key class.
            // The Key class binds one explicit algorithm to the key, preventing
            // algorithm-confusion attacks where a forged HS256 token could be
            // verified using the RSA public key as an HMAC secret.
            $decoded = JWT::decode($jwt, new Key($publicKey, 'RS256'));
        } catch (ExpiredException | SignatureInvalidException | \UnexpectedValueException $e) {
            return null;
        }

        return $decoded;
    }
}
```

### File: composer.json

```json
{
    "require": {
        "firebase/php-jwt": "^6.0"
    }
}
```

## Explanation

The vulnerability is an algorithm-confusion attack enabled by the `firebase/php-jwt` 5.x array-of-algorithms call form `JWT::decode($jwt, $publicKey, ['RS256', 'HS256'])`. This form allows the token's `alg` header to select which algorithm is used for verification. An attacker can craft a token with `"alg": "HS256"`, sign it with the RSA public key (which is public and easily obtained), and the token will verify successfully because HS256 is in the accepted list. The fix upgrades to `firebase/php-jwt` 6.0+, which removed the vulnerable array form and introduced the `Key` class. `new Key($publicKey, 'RS256')` pins the algorithm to RS256 server-side, ensuring the token's header cannot override it. This eliminates algorithm confusion—HS256 tokens are rejected regardless of how they are signed.

## Behaviour changes

The fixed code rejects tokens signed with HS256 that were previously accepted. This is the intended security hardening: only tokens signed with RS256 using the RSA private key are now accepted. The algorithm pinning matches the intended authentication flow where the server holds the RSA private key for signing and distributes only the public key, so only tokens signed with that key should be trusted.

