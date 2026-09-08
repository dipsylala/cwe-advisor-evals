## Verdict

Confirmed - exploitable. `JWT::decode()` is called with the array-of-algorithms form (`['RS256', 'HS256']`) against a single key value, and that value is the RSA **public** key. A caller who knows the public key (public by definition) can forge a token with header `"alg":"HS256"`, sign it with HMAC-SHA256 using the PEM public-key bytes as the shared secret, and `JWT::decode()` will accept it as valid - a classic RS256/HS256 key-confusion authentication bypass. The `$hmacSecret` field exists on the class but is never actually used to verify anything, so the "HS256 support" this call appears to offer was never soundly implemented.

## Source

`$headers['Authorization']` (attacker-controlled bearer token, extracted via `preg_match` into `$jwt` at `AuthController.php:39`).

## Fix

### File: AuthController.php

```php
<?php

// composer.json (excerpt): "firebase/php-jwt": "^6.0"
// Requires firebase/php-jwt 6.0.0 or later, where JWT::decode() takes a
// Key object binding one explicit algorithm to the verification key; the
// legacy array-of-algorithms call form was removed (not deprecated) in
// 6.0.0 and raises a TypeError if passed. Current release is 7.1.0 -
// confirm the resolved version against SCA/dependency-check tooling
// before merging.

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
            $decoded = JWT::decode($jwt, new Key($publicKey, 'RS256'));
        } catch (ExpiredException | SignatureInvalidException | \UnexpectedValueException $e) {
            return null;
        }

        return $decoded;
    }
}
```

## Explanation

Two things had to change together, and each addresses a different half of the finding.

Library: the vulnerable call form (`JWT::decode($jwt, $key, ['RS256', 'HS256'])`) only exists on `firebase/php-jwt` 5.x - it was removed, not deprecated, in 6.0.0, where the third parameter became `?stdClass &$headers`. There is no way to make this call form safe on 5.x; the manifest has to move to `^6.0` (current release 7.1.0 per this repository's guidance - verify the resolved version with SCA tooling before merging, since that number isn't re-derived here from a live advisory feed).

Code: on 6.x, `JWT::decode()` takes a `Firebase\JWT\Key` object that binds one explicit algorithm to one explicit key, so the algorithm used to verify a token is chosen by the server, never by the token's own `alg` header. The fix wraps `$publicKey` as `new Key($publicKey, 'RS256')` and drops HS256 from the accepted set. This isn't an incidental narrowing: `$publicKey` is the only key value the original call ever passed to the verifier, so the HS256 branch it advertised was never checked against the shared secret in `$hmacSecret` - it was checked against the public key, which is what made the confusion attack possible. Pinning to RS256 with the RSA key is the only algorithm this sink was ever legitimately able to verify with the key material it had. Genuinely supporting both RS256 and HS256 tokens from two different keys would require a `kid`-keyed array of `Key` objects and issuer-side `kid` assignment - there's no evidence in this method that issued tokens carry a `kid`, so adding that mapping here would be a speculative feature addition rather than a fix, not something this change makes.

The two existing catch targets (`ExpiredException`, `SignatureInvalidException`, `\UnexpectedValueException`) still cover 6.x's failure modes for a bad signature, expired token, or algorithm mismatch, so the fail-closed `return null` behavior on any verification failure is unchanged.

Checked: `php -l` (PHP 8.5.8 CLI) against the fixed file in isolation - "No syntax errors detected". `Key` is the exact class and two-argument constructor named in this repository's `cwe/287/php/INDEX.md` guidance (`new Key($key, 'HS256')`), so it is not a recalled/unverified name. No other call site references `authenticateRequest()`'s return value differently, and no other file in this call chain calls `JWT::decode()`.

## Behaviour changes

- A request bearing a valid RS256 token, correctly signed by the corresponding RSA private key, is unaffected.
- A request bearing an HS256 token is now always rejected (`null`), including one signed with `$this->hmacSecret`. Before the fix, HS256 tokens were only ever "accepted" if signed with the RSA public key bytes as the HMAC secret - i.e., forged - so no legitimate HS256 flow is being removed; the forgery path is what's closed. `$hmacSecret` becomes an unused constructor parameter as a result; it is left in place since removing it is outside this file's finding and it may be consumed elsewhere in the class hierarchy not shown here.
- Deploying this fix requires bumping `firebase/php-jwt` from the 5.x line to `^6.0` in `composer.json` (not shown as a case file here) before the code will even compile, since the array-of-algorithms call form no longer exists as of 6.0.0.
