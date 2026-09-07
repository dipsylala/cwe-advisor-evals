## Verdict
Real vulnerability confirmed. The code decodes a JWT payload without verifying the cryptographic signature, allowing an attacker to forge arbitrary claims.

## Source
Line 19 of `ManualJwtPayloadDecode.php` decodes the Base64-encoded payload of a JWT without checking the signature. The payload is extracted from the Authorization header, decoded, and its claims are trusted unconditionally. An attacker can craft a JWT with forged claims (e.g., `"role": "admin"`) and sign it with any key; the signature is never validated, so the forged token is accepted.

## Fix

### File: ManualJwtPayloadDecode.php
```php
<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Reads the bearer token from the request and verifies its signature before decoding claims.
function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    $token = $matches[1];
    $secret = getenv('JWT_SECRET');
    if (!$secret) {
        return null;
    }

    try {
        // Decode and verify the JWT signature using the shared secret
        $decoded = JWT::decode($token, new Key($secret, 'HS256'));
        return [
            'id' => $decoded->sub ?? null,
            'role' => $decoded->role ?? null,
        ];
    } catch (\Exception $e) {
        // Signature verification failed or token is malformed
        return null;
    }
}

$user = getAuthenticatedUser();
if ($user !== null && $user['role'] === 'admin') {
    echo 'Welcome, admin.';
}
```

## Explanation
The fix uses `firebase/php-jwt`, a widely-maintained library for JWT handling in PHP. The `JWT::decode()` method both decodes the token and verifies its signature using the provided secret key and algorithm (HS256 for HMAC-SHA256).

Key changes:
1. **Signature verification**: `JWT::decode()` validates that the JWT's signature matches the expected value computed from the header, payload, and secret key.
2. **Algorithm specification**: The `Key` object specifies `'HS256'`, ensuring only tokens signed with HMAC-SHA256 are accepted (prevents algorithm-confusion attacks).
3. **Exception handling**: If signature verification fails, decoding throws an exception, which is caught and returns `null`, rejecting the token.
4. **Secret management**: The JWT secret is read from an environment variable (e.g., `JWT_SECRET`), not hardcoded.

The attacker's forged token will fail verification because it is either unsigned, signed with the wrong key, or signed with a different algorithm—all of which are detected and rejected.
