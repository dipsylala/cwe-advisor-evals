## Verdict
CONFIRMED. The `JWT::decode()` call at line 44 uses the removed firebase/php-jwt 5.x array-of-algorithms form, which allows the token's own `alg` header to determine the validation algorithm. An attacker can forge a token signed with HS256 using the public RSA key (which is often known) and bypass the intended RS256 verification.

## Source
Bearer token from `Authorization` header (line 34), parsed by regex at line 35, extracted into `$jwt` at line 39.

## Fix
The code must be updated to firebase/php-jwt 6.0+ (current: 7.1.0) and use the `Key` class to bind the algorithm explicitly:

### File: AuthController.php
```php
<?php

// composer.json (excerpt): "firebase/php-jwt": "^6.0"

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
            // Bind the RS256 algorithm explicitly to this key; the token's `alg`
            // header cannot override it. This closes algorithm-confusion attacks
            // where an attacker signs with HS256 using the known public key.
            $decoded = JWT::decode($jwt, new Key($publicKey, 'RS256'));
        } catch (ExpiredException | SignatureInvalidException | \UnexpectedValueException $e) {
            return null;
        }

        return $decoded;
    }
}
```

## Explanation
The vulnerability is algorithm confusion: firebase/php-jwt 5.x's array-of-algorithms form lets the JWT's `alg` header select which algorithm validates the signature. An attacker can forge a token claiming `alg: HS256` and signed with the RSA public key (which is often publicly available), bypassing the intended RS256 verification with an RSA private key.

The fix upgrades to firebase/php-jwt 6.0+ and wraps the key in a `Key` object that binds exactly one algorithm (`RS256`) to it. When `JWT::decode()` receives a token with `alg: HS256`, it now throws `SignatureInvalidException` instead of attempting HMAC validation. The caught exception at line 45 (now line 51) rejects the malformed token as before.

The import statement adds `use Firebase\JWT\Key;` at line 5, and the `composer.json` comment updates the version constraint from `^5.5` to `^6.0` to document the dependency.

## Behaviour changes
- Tokens claiming any algorithm other than RS256 are now rejected unconditionally (formerly could be accepted if signed with HS256 using the public key).
- The `composer.json` version constraint changes from `^5.5` to `^6.0`; firebase/php-jwt 6.0+ requires PHP 7.4+ (was 7.1+).
- No change to the returned data or exception types: `JWT::decode()` still throws on invalid tokens and returns the decoded claims on success.
