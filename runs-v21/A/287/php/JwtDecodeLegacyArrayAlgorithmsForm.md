## Verdict
Real vulnerability confirmed. The code accepts both RS256 (asymmetric) and HS256 (symmetric) algorithms when decoding JWTs. An attacker can forge an authentication token by signing with HS256 using the public key (which is publicly available) as the HMAC secret, bypassing the authentication check.

## Source
File: AuthController.php, line 44

```php
$decoded = JWT::decode($jwt, $publicKey, ['RS256', 'HS256']);
```

The vulnerability: The allowed algorithms array includes both RS256 and HS256. When HS256 is accepted, an attacker can sign a token with HS256 using the public key, and the decoder will treat it as valid. This is a classic JWT algorithm confusion attack.

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
            // Only allow RS256 to prevent algorithm confusion attacks
            $decoded = JWT::decode($jwt, $publicKey, ['RS256']);
        } catch (ExpiredException | SignatureInvalidException | \UnexpectedValueException $e) {
            return null;
        }

        return $decoded;
    }
}
```

## Explanation
The fix restricts the allowed algorithms array to only `['RS256']`. This prevents the algorithm confusion vulnerability by:

1. **Explicitly specifying asymmetric signing only**: RS256 (RSA with SHA-256) is an asymmetric algorithm that requires the private key for signing and the public key for verification.

2. **Preventing HS256 abuse**: By excluding HS256 (HMAC with SHA-256), we prevent an attacker from using the public key as a symmetric secret to forge valid tokens.

3. **Enforcing correct key usage**: The public key is now only used for its intended purpose—verifying RS256-signed tokens—not as a shared secret.

The `hmacSecret` property remains in the class but is unused after this fix, which is acceptable since the application's authentication model has shifted to exclusively using asymmetric (RS256) token signing.
