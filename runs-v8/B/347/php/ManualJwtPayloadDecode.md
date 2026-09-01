## Verdict

Exploitable. The code decodes and trusts a JWT payload without verifying its cryptographic signature, allowing an attacker to forge any token and control claims used for authorization.

## Source

`$_SERVER['HTTP_AUTHORIZATION']` (attacker-controlled HTTP header at line 6).

## Fix

**Library Recommendation:** `firebase/php-jwt` version 6.0.0 or later. Pre-6.0.0 versions are vulnerable to algorithm-confusion attacks (CVE-2021-46743) and must be upgraded.

**Vulnerable Code (lines 1-25):**
```php
<?php

// Reads the bearer token from the request and decodes its claims without checking the signature.
function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    $parts = explode('.', $matches[1]);
    if (count($parts) !== 3) {
        return null;
    }

    $payload = strtr($parts[1], '-_', '+/');

    // SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
    $claims = json_decode(base64_decode($payload), true);

    return [
        'id' => $claims['sub'] ?? null,
        'role' => $claims['role'] ?? null,
    ];
}

$user = getAuthenticatedUser();
if ($user !== null && $user['role'] === 'admin') {
    echo 'Welcome, admin.';
}
```

**Fixed Code:**
```php
<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Reads the bearer token from the request and verifies its signature before decoding the claims.
function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    $token = $matches[1];
    
    try {
        // Verify the JWT signature using the public key or secret from configuration.
        // The key must come from configuration or environment, never from the token itself.
        $publicKey = $_ENV['JWT_PUBLIC_KEY'] ?? '';
        if (!$publicKey) {
            return null;
        }
        
        // Bind the key to a specific algorithm to prevent algorithm-confusion attacks.
        // Use the algorithm your issuer employs (e.g., 'RS256' for RSA, 'HS256' for HMAC).
        $key = new Key($publicKey, 'RS256');
        
        // JWT::decode() verifies the signature and returns a decoded object.
        // It throws UnexpectedValueException if the signature is invalid.
        $claims = JWT::decode($token, $key);
        
        return [
            'id' => $claims->sub ?? null,
            'role' => $claims->role ?? null,
        ];
    } catch (\Exception $e) {
        // Signature verification failed, token is malformed, or expired.
        return null;
    }
}

$user = getAuthenticatedUser();
if ($user !== null && $user['role'] === 'admin') {
    echo 'Welcome, admin.';
}
```

## Explanation

The original code extracts the JWT payload and base64-decodes it without performing any cryptographic verification. This allows an attacker to forge or tamper with any claim in the token. The fix replaces manual JWT parsing with `firebase/php-jwt` v6.0.0+, which enforces signature verification using a `Key` object bound to a specific algorithm. The `Key` object prevents algorithm-confusion attacks by rejecting tokens that claim a different algorithm than the one configured. The verification key must be loaded from a trusted configuration source (environment variable, keystore, or hardcoded constant), never from the token itself. If signature verification fails, `JWT::decode()` throws an exception, which is caught and causes the function to return `null`, denying access. The claim values (`$claims->sub`, `$claims->role`) are now trusted only because they have been cryptographically verified as part of the signed token.

## Behaviour changes

- **Return type change:** `JWT::decode()` returns a `stdClass` object, not an associative array. The fix accesses claims as object properties (`$claims->sub`) instead of array keys (`$claims['sub']`). The fix converts back to an associative array at lines 27-30 to preserve the original return type contract.
- **Exception handling added:** The original code had no error handling; the fixed code wraps verification in a try-catch that returns `null` on any failure (malformed token, signature mismatch, expired token, missing key). This is the intended behavior for a security fix - failed verification must deny access.
- **Configuration dependency added:** The fixed code requires `JWT_PUBLIC_KEY` to be available in `$_ENV` or similar configuration. The original code had no such dependency. This is necessary and intentional - the verification key must come from a trusted source.
- **Algorithm must be specified:** The fixed code requires an explicit algorithm (`'RS256'` in the example). The original code had no algorithm at all. This is required by the `firebase/php-jwt` v6+ API to prevent algorithm confusion.
- **No behavior change for the calling code:** The function still returns an array with `'id'` and `'role'` keys, and the downstream authorization check at line 42 remains unchanged.
