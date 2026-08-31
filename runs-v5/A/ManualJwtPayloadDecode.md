## Verdict

Confirmed. `getAuthenticatedUser()` splits the bearer token into its three dot-separated segments, base64-decodes the payload segment, and trusts the resulting claims — the third segment (the signature) is never checked against the header and payload. Anyone can craft a token with an arbitrary payload (e.g. `role: admin`), base64url-encode it, append any junk as a third segment, and the function will accept it and return `role => 'admin'`, which line 28 then trusts for an authorization decision.

## Source

`$_SERVER['HTTP_AUTHORIZATION']` — the `Authorization` request header, attacker-controlled. It flows through the `Bearer\s+(.+)` regex capture (`$matches[1]`) into `explode('.', ...)`, and `$parts[1]` (the payload segment) is base64url-decoded and JSON-decoded at line 19 with no cryptographic check anywhere in the path.

## Fix

Replace the manual split/decode with a vetted JWT library that verifies the signature before any claim is trusted, for example `firebase/php-jwt` (`composer require firebase/php-jwt`):

```php
<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;

// Reads the bearer token from the request and returns its claims only after verifying the signature.
function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    $secret = getJwtSigningKey(); // load from environment/secret store, not hardcoded
    $algorithm = 'HS256'; // must match how tokens are issued; do not read alg from the token itself

    try {
        $claims = JWT::decode($matches[1], new Key($secret, $algorithm));
    } catch (ExpiredException | SignatureInvalidException | \UnexpectedValueException $e) {
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

Key points in the fix:

- `JWT::decode()` recomputes the HMAC (or verifies the asymmetric signature) over the header and payload and rejects the token if it does not match the supplied key, before any claim is returned.
- The verification key and algorithm are supplied by the server (`$secret`, `'HS256'`) rather than taken from the token's own `alg`/`kid` header, which closes the classic "algorithm confusion" / `alg: none` bypass that a naive decode-and-trust-header implementation would otherwise be exposed to.
- `JWT::decode()` also enforces standard claims such as `exp` (and `nbf` if present), so an expired token is rejected instead of accepted the way the original code accepted anything at all.
- Library exceptions are caught and turned into `null` (unauthenticated) rather than allowing a malformed or invalid token to fall through to a partially-populated `$claims` array.

## Explanation

The vulnerable code treats a JWT purely as a container format: it destructures the three dot-separated parts, decodes the middle one, and reads fields out of it — exactly the operation the format's signature exists to gate. Because nothing recomputes or checks the third segment against a known key, the "signature" is decorative; the server accepts self-asserted claims from the client. This is precisely CWE-347: the code determines trust (`role === 'admin'`) from data whose authenticity was never cryptographically established.

The fix does not change *what* claims are read, only *how* the token is validated before those claims are trusted: signature verification must happen using a server-held key and a server-chosen algorithm, and it must happen before a single claim value is used for any authorization or identity decision. Using an established library instead of hand-rolled base64/JSON handling also brings in the surrounding correctness work (constant-time comparison, algorithm pinning, expiry/not-before enforcement) that a bespoke implementation would otherwise have to reproduce and would be easy to get subtly wrong.
