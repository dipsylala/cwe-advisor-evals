## Verdict

The code is vulnerable. It decodes a JWT payload without verifying the cryptographic signature, allowing an attacker to forge claims and escalate privileges (e.g., setting role to 'admin').

## Source

Line 19: `$claims = json_decode(base64_decode($payload), true);`

The vulnerability is the absence of JWT signature verification. The code extracts and decodes the payload (the middle segment of a JWT) without validating that the signature (third segment) is authentic. This allows an attacker to modify claims arbitrarily.

## Fix

Use a JWT library that validates the signature before decoding claims. Replace the manual JWT parsing with:

```php
<?php
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    try {
        $secret = $_ENV['JWT_SECRET'] ?? 'your-secret-key';
        $decoded = JWT::decode($matches[1], new Key($secret, 'HS256'));
        
        return [
            'id' => $decoded->sub ?? null,
            'role' => $decoded->role ?? null,
        ];
    } catch (Exception $e) {
        return null;
    }
}

$user = getAuthenticatedUser();
if ($user !== null && $user['role'] === 'admin') {
    echo 'Welcome, admin.';
}
```

Install firebase/php-jwt: `composer require firebase/php-jwt`

## Explanation

A JWT consists of three base64url-encoded segments separated by dots: header.payload.signature. The signature is computed from header and payload using a secret key known only to the server. Decoding the payload without verifying the signature means accepting any attacker-controlled claims—they can change role, user ID, or any other field.

The fix uses the firebase/php-jwt library, which:
1. Verifies the signature matches the payload and header using the shared secret
2. Only decodes claims if signature verification succeeds
3. Throws an exception if verification fails, preventing the forged token from being accepted

This ensures only tokens signed by the server (with the correct secret) are trusted.
