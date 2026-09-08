## Verdict
exploitable

## Source
`$_SERVER['HTTP_AUTHORIZATION']` - Bearer token from the HTTP Authorization header (user-controlled)

## Fix

### File: ManualJwtPayloadDecode.php
```php
<?php

require_once 'vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Reads the bearer token from the request and verifies its signature before decoding its claims.
function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    // The secret key used to sign the JWT must be loaded from secure configuration
    $secret = $_ENV['JWT_SECRET'] ?? '';
    if (!$secret) {
        return null;
    }

    try {
        // Verify the signature and decode in one operation
        // The Key object binds the key material to the exact algorithm expected,
        // preventing algorithm confusion attacks
        $decoded = JWT::decode($matches[1], new Key($secret, 'HS256'));
        
        return [
            'id' => $decoded->sub ?? null,
            'role' => $decoded->role ?? null,
        ];
    } catch (\Exception $e) {
        // Signature verification failed or token is malformed - reject
        return null;
    }
}

$user = getAuthenticatedUser();
if ($user !== null && $user['role'] === 'admin') {
    echo 'Welcome, admin.';
}
```

## Explanation
The original code manually extracted and base64-decoded the JWT payload without verifying the cryptographic signature, allowing an attacker to forge tokens with arbitrary claims. The fix replaces manual JWT parsing with `firebase/php-jwt` v6.0.0+, which properly verifies the signature before extracting claims. The key is wrapped in a `Key` object with an explicit algorithm binding (`HS256`), which prevents algorithm confusion attacks (CVE-2021-46743). The `JWT::decode()` call verifies the signature using the secret and only returns the decoded token if verification succeeds; any verification failure or malformed token causes an exception, which is caught and returns null, rejecting the authentication.

## Behaviour changes
- Added dependency on `firebase/php-jwt` v6.0.0 or later; the code now requires this library to be installed and autoloaded.
- The JWT secret key must now be provided via configuration (environment variable `JWT_SECRET` or similar); the code returns null if not available, preventing authentication if configuration is missing.
- Token claims are now accessed as object properties (e.g., `$decoded->sub`) instead of array keys, because `JWT::decode()` returns a `stdClass` object by default; this is a natural consequence of using a proper JWT library and does not introduce security regression.
- Any malformed token, expired token, or invalid signature now causes the function to return null rather than potentially returning a partially decoded claim; this is the intended security-hardening behavior and prevents authentication bypass.
