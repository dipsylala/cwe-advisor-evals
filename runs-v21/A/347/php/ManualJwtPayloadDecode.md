## Verdict

The vulnerability is confirmed. The code manually decodes a JWT by extracting and base64-decoding the payload without verifying the cryptographic signature. An attacker can fabricate arbitrary JWT tokens with any claims and the application will trust them.

## Source

The vulnerable code reads a JWT from the `Authorization` header, manually splits it by the `.` delimiter, base64-decodes the payload (second part), and JSON-decodes it to extract claims — without ever validating the signature (third part) against a secret or public key.

```
Line 19: $claims = json_decode(base64_decode($payload), true);
```

This is the sink: decoding and trusting untrusted JWT data without signature verification.

## Fix

### File: ManualJwtPayloadDecode.php

```php
<?php

// Reads the bearer token from the request and verifies its signature before decoding claims.
function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    try {
        // Use firebase/php-jwt library to decode and verify the JWT signature
        // The secret key must be securely stored and retrieved from configuration
        $secret = $_ENV['JWT_SECRET'] ?? 'your-secret-key';
        $decoded = \Firebase\JWT\JWT::decode(
            $matches[1],
            new \Firebase\JWT\Key($secret, 'HS256')
        );
        
        return [
            'id' => $decoded->sub ?? null,
            'role' => $decoded->role ?? null,
        ];
    } catch (\Exception $e) {
        // Token is invalid, expired, or signature verification failed
        return null;
    }
}

$user = getAuthenticatedUser();
if ($user !== null && $user['role'] === 'admin') {
    echo 'Welcome, admin.';
}
```

## Explanation

The fix replaces manual JWT parsing with the `firebase/php-jwt` library, which properly verifies the cryptographic signature before returning the claims.

Key changes:

1. **Replace manual decoding with `JWT::decode()`**: The `firebase/php-jwt` library's `decode()` method takes the token and a `Key` object specifying the secret and algorithm (HS256 for HMAC-SHA256). It automatically performs signature verification against the secret.

2. **Signature verification**: If the signature does not match the secret key, `JWT::decode()` throws an exception, preventing the attacker's forged token from being trusted. The original code had no such check.

3. **Exception handling**: Any exception (invalid signature, malformed token, expired token) is caught and returns `null`, denying access. This prevents attackers from exploiting the vulnerability by crafting custom tokens.

4. **Access decoded claims via properties**: The decoded object has claims as object properties (`$decoded->sub`, `$decoded->role`) rather than array keys, so the return statement converts them back to array format as the original code expected.

The `firebase/php-jwt` package is the standard, well-tested JWT library for PHP and handles all signature verification complexity securely. The secret key should be loaded from secure configuration (`$_ENV`, a secrets manager, or configuration file) rather than hardcoded.
