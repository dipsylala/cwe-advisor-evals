## Verdict

Confirmed. `authenticateRequest()` calls `JWT::decode($jwt, $publicKey, ['RS256', 'HS256'])`, passing a single key value (the RSA public key) alongside an allowed-algorithms list that mixes an asymmetric algorithm (RS256) with a symmetric one (HS256). `firebase/php-jwt` 5.x does not bind an algorithm to a key in this call form - it will accept a token signed with either algorithm against the same key. An RSA public key is not secret, so an attacker who obtains it (it is frequently published, e.g. via a JWKS endpoint or embedded in a client) can forge a token by signing it with HMAC-SHA256 using the public key bytes as the HMAC secret. The server, allowing HS256 in this decode call, verifies that forged HMAC signature successfully using the same public key value and accepts the token as authentic - a classic algorithm-confusion authentication bypass (CWE-287).

## Source

Untrusted input enters at the `Authorization` request header (`$headers['Authorization']`), which is attacker-controlled. It is extracted via the `Bearer <token>` regex into `$jwt` and flows unmodified into `JWT::decode()` at the reported sink (line 44), where the vulnerable multi-algorithm/single-key call form allows the forged-signature bypass described above.

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

        // Read the algorithm the token itself claims to use, then verify
        // against only the single key that corresponds to that algorithm,
        // restricting JWT::decode() to exactly that one algorithm. Never
        // resolve a key first and then let decode() accept either an
        // asymmetric or a symmetric algorithm against it: an attacker who
        // knows the RSA public key can sign a token with HS256 using that
        // public key's bytes as the HMAC secret, and a decode() call that
        // permits both RS256 and HS256 for the same key value will verify
        // that forged signature successfully.
        $segments = explode('.', $jwt);
        if (count($segments) !== 3) {
            return null;
        }

        $headerJson = JWT::urlsafeB64Decode($segments[0]);
        $header = $headerJson === false ? null : json_decode($headerJson);
        if (!is_object($header) || !isset($header->alg) || !is_string($header->alg)) {
            return null;
        }

        switch ($header->alg) {
            case 'RS256':
                $key = $this->rsaPublicKey;
                $allowedAlgs = ['RS256'];
                break;
            case 'HS256':
                $key = $this->hmacSecret;
                $allowedAlgs = ['HS256'];
                break;
            default:
                return null;
        }

        try {
            $decoded = JWT::decode($jwt, $key, $allowedAlgs);
        } catch (ExpiredException | SignatureInvalidException | \UnexpectedValueException $e) {
            return null;
        }

        return $decoded;
    }
}
```

## Explanation

The vulnerable call resolved a single key (the RSA public key) and then told `JWT::decode()` it may accept either RS256 or HS256 for that key. Because `firebase/php-jwt` 5.x's `decode($jwt, $key, $allowed_algs)` form does not pair a specific algorithm with a specific key - it only checks that the token's `alg` header is a member of `$allowed_algs` and then verifies with the one `$key` given - an HS256-signed forgery using the (non-secret) RSA public key as the HMAC key passes verification.

The fix inspects the token's own `alg` header first (via `JWT::urlsafeB64Decode()`, a public static helper already present on the same `JWT` class in 5.x) before choosing a key, then calls `decode()` with the one key that matches that algorithm and an `$allowed_algs` list containing only that single algorithm. RS256 tokens are now verified solely against the RSA public key restricted to `['RS256']`; HS256 tokens are verified solely against the HMAC secret restricted to `['HS256']`. No key is ever checked against a mismatched algorithm, so the public-key-as-HMAC-secret forgery no longer verifies. This also puts the previously-unused `$this->hmacSecret` property to its intended use rather than dropping HS256 support outright. An unrecognized or missing `alg`, or a malformed (non-three-segment) token, is rejected before any key material is touched, matching the existing "return null on invalid token" contract of the method.
