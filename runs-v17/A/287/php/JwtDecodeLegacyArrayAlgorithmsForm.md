## Verdict
CONFIRMED - CWE-287 Improper Authentication via JWT algorithm substitution.

## Source
The vulnerability is in `AuthController.php` at line 44, where `JWT::decode()` accepts multiple algorithms via an array parameter: `['RS256', 'HS256']`.

## Fix
### File: AuthController.php

```php
<?php

// composer.json (excerpt): "firebase/php-jwt": "^5.5"
// Pinned to the 5.x line: the array-of-algorithms call form used below was
// removed with a TypeError starting in firebase/php-jwt 6.0.0, so this file
// only compiles/runs as written against 5.5.x.

namespace App\Http\Controllers;

use Firebase\JWT\JWT;
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
            $decoded = JWT::decode($jwt, $publicKey, ['RS256']);
        } catch (ExpiredException | SignatureInvalidException | \UnexpectedValueException $e) {
            return null;
        }

        return $decoded;
    }
}
```

## Explanation
The vulnerability is a **JWT algorithm substitution attack**. By accepting both RS256 and HS256, the code allows an attacker to forge a valid token by switching algorithms. An attacker with knowledge of the HMAC secret could encode a token using HS256 (which uses the secret directly as a symmetric key) and bypass authentication if the verification logic accepts both algorithms.

The fix restricts the allowed algorithms to only RS256, the intended algorithm for this application. Since the code uses an RSA public key for verification, only asymmetric RS256 tokens should be accepted. This eliminates the algorithm substitution vector and ensures the authentication mechanism works as designed.
