## Verdict
The vulnerability is confirmed. The code decodes and uses a JWT payload without verifying the cryptographic signature, allowing an attacker to forge authentication tokens by modifying the payload and resubmitting the tampered token.

## Source
Line 19 decodes the JWT payload without signature verification. The code splits the JWT into three parts (header.payload.signature) but only base64-decodes the payload and ignores the signature entirely. JWT security depends on verifying the signature to confirm the token has not been tampered with.

## Fix
Use a dedicated JWT library that performs cryptographic signature verification. Replace the manual parsing with a library like `firebase/php-jwt`:

```php
<?php
require 'vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    try {
        // Decode and verify signature with the secret key
        // Use the same key and algorithm that created the token
        $decoded = JWT::decode($matches[1], new Key('your-secret-key', 'HS256'));
        
        return [
            'id' => $decoded->sub ?? null,
            'role' => $decoded->role ?? null,
        ];
    } catch (Exception $e) {
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
The original code performs no signature verification. It extracts and base64-decodes only the payload portion of the JWT, completely ignoring the third part (the signature). Any attacker can modify the payload (for example, changing `role` from `user` to `admin`) and resubmit the forged token; without signature verification, it will be accepted.

A proper JWT library like `firebase/php-jwt` verifies the signature during decoding using the configured secret key and algorithm. If the signature does not match the header and payload (indicating tampering or a forged token), the decode operation throws an exception. The try-catch block treats invalid tokens as authentication failures, returning null so the subsequent role check fails safely.
