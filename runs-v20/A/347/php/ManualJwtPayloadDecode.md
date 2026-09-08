## Verdict

Confirmed. `getAuthenticatedUser()` splits the bearer token into its three dot-separated parts, base64-decodes the middle segment, and hands the resulting JSON straight to the caller as trusted claims. No signature is ever computed or compared, so any client can forge a token with an arbitrary `role` claim (e.g. `role: admin`) using nothing but base64 encoding, and the code at the bottom of the file will treat it as an authenticated admin.

## Source

`$_SERVER['HTTP_AUTHORIZATION']` (the client-supplied `Authorization` header) is the tainted source. It flows through `preg_match` (extracts the token), `explode('.', ...)` (splits header/payload/signature), and reaches the sink at `json_decode(base64_decode($payload), true)`, where the payload segment is decoded and trusted without any cryptographic check of the third segment (the signature). The `sub` and `role` claims pulled from that unverified structure then drive an authorization decision (`$user['role'] === 'admin'`).

## Fix

Replace the manual split/base64/json_decode logic with a maintained JWT library that verifies the signature before any claim is trusted: `firebase/php-jwt` (package `firebase/php-jwt`, use its `Firebase\JWT\JWT::decode()` with an explicit `Firebase\JWT\Key`). The algorithm is pinned explicitly (`HS256`) so the library cannot be tricked into accepting an unsigned or differently-algorithmed token, and the secret/key is read from server-side configuration rather than derived from the token itself. Any verification failure (bad signature, expired token, wrong algorithm) throws, and is treated as "not authenticated" rather than falling through to a partially-populated claims array.

### File: ManualJwtPayloadDecode.php

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\ExpiredException;

// Reads the bearer token from the request, verifies its signature, and decodes its claims.
function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    $token = $matches[1];

    // Secret must come from server-side configuration, never from the token or the request.
    $secret = getenv('JWT_SIGNING_SECRET');
    if ($secret === false || $secret === '') {
        return null;
    }

    try {
        $claims = JWT::decode($token, new Key($secret, 'HS256'));
    } catch (SignatureInvalidException | ExpiredException | \UnexpectedValueException $e) {
        // Invalid signature, expired token, malformed structure, or algorithm mismatch.
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

## Explanation

`JWT::decode()` recomputes the HMAC over the token's header and payload using the server-held secret and rejects the token (via a thrown exception) unless it matches the signature segment byte-for-byte, closing the forgery path that the original code left wide open. Pinning the algorithm to `HS256` in the `Key` object prevents an attacker from switching the token's `alg` header to `none` or to an asymmetric algorithm to bypass verification (the classic JWT "alg confusion" bypass) - the library only accepts the algorithm the caller explicitly names. All decode failure modes (bad signature, expiry, malformed token) are caught and treated as "no authenticated user," so `getAuthenticatedUser()` can no longer return a claims array assembled from unverified attacker input. The secret is read from server-side configuration (`JWT_SIGNING_SECRET`) rather than anything derived from the request, so no part of the trust decision is attacker-controlled. `firebase/php-jwt` is an actively maintained library; before deploying this fix, confirm the installed version is current via composer/SCA, since JWT libraries have historically shipped algorithm-confusion and signature-bypass advisories that were fixed in specific releases.
