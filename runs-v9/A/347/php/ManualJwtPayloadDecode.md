## Verdict

Confirmed. The token's payload segment is base64-decoded and parsed directly; the signature segment (`$parts[2]`) is read only to count parts and is never cryptographically verified. Any caller can forge a header/payload pair, base64url-encode arbitrary claims (including `"role": "admin"`), append any third segment, and `getAuthenticatedUser()` will accept it and grant admin access.

## Source

`$_SERVER['HTTP_AUTHORIZATION']` (line 6) — attacker-controlled HTTP request header, split into JWT segments and flowed unverified into the authorization decision at line 28.

## Fix

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;

// Reads the bearer token from the request, verifies its signature, and decodes its claims.
function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    $secretKey = getenv('JWT_SIGNING_KEY'); // load from secret manager / env, not source

    try {
        // JWT::decode verifies the signature (and exp/nbf/iat) before returning claims.
        // The allowed algorithm is pinned explicitly to prevent alg-confusion/"none" attacks.
        $claims = JWT::decode($matches[1], new Key($secretKey, 'HS256'));
    } catch (SignatureInvalidException | ExpiredException | \UnexpectedValueException $e) {
        return null;
    }

    return [
        'id' => $claims->sub ?? null,
        'role' => $claims->role ?? null,
    ];
}

$user = getAuthenticatedUser();
if ($user !== null && $user['role'] === 'admin') {
    echo 'Welcome, admin.';
}
```

(Requires `firebase/php-jwt`, e.g. `composer require firebase/php-jwt`.)

## Explanation

The original code treats a JWT as a self-authenticating structure: it splits the token on `.`, base64-decodes the middle segment, and JSON-decodes it into claims — but a JWT's integrity guarantee comes entirely from its signature (segment 3), verified against a key the server controls. Skipping that verification means the "claims" object is just attacker-supplied JSON with extra formatting; nothing prevents a client from submitting `eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.` (or any other base64url payload) and being treated as `role: admin`.

The fix delegates decoding to a maintained JWT library (`firebase/php-jwt`) whose `JWT::decode()` recomputes the signature over the header+payload using the server's key and rejects the token if it doesn't match, along with checking standard time-based claims (`exp`, `nbf`, `iat`) when present. The algorithm is passed explicitly via `Key($secretKey, 'HS256')` rather than trusted from the token's own `alg` header, which closes the classic "alg: none" / algorithm-confusion bypass where an attacker asks the verifier to use a weaker or absent algorithm. `$secretKey` must be a real secret pulled from environment/secret storage and never hardcoded, and it must match whatever algorithm/key type actually issued the tokens (an asymmetric algorithm such as RS256 would use the issuer's public key instead of a shared secret). Any decode failure — bad signature, expired token, malformed structure — is caught and treated as unauthenticated rather than allowed through.
