## Verdict

The code manually decodes a JWT payload without verifying the cryptographic signature. An attacker can forge a JWT with arbitrary claims by creating a valid base64-encoded payload and skipping or spoofing the signature. The authorization check at line 28 then trusts the forged claims, allowing privilege escalation to admin without a valid signature.

## Source

The JWT comes from the `Authorization` HTTP header at line 6. The code extracts the bearer token and manually splits it, base64-decodes the payload portion, and JSON-decodes it into claims. No signature verification occurs at any point.

## Fix

Replace manual JWT handling with `firebase/php-jwt` v6.0.0 or later, which binds verification keys to specific algorithms and rejects signature mismatches.

**Dependency change**: Add `firebase/php-jwt: ^6.0.0` to `composer.json`.

**Code replacement**:

```php
<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Verify the bearer token signature and return authenticated user claims
function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    // Get the verification key from secure configuration (e.g., keystore, environment, JWKS endpoint)
    // This example uses a pre-shared secret; for RS256, use the issuer's public key
    $verificationKey = getenv('JWT_SECRET_KEY');
    if (!$verificationKey) {
        return null; // Or log error and fail securely
    }

    try {
        // Verify signature using the Key object bound to the expected algorithm
        // JWT::decode() throws UnexpectedValueException if signature is invalid
        $decoded = JWT::decode(
            $matches[1],
            new Key($verificationKey, 'HS256') // Algorithm must match issuer's signing algorithm
        );

        // Cast to array for compatibility with original code
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

**Key changes**:
- Import `Firebase\JWT\JWT` and `Firebase\JWT\Key` classes
- Obtain the verification key from secure configuration, not from the token itself
- Pass a `Key` object bound to the specific algorithm ('HS256' for HMAC; use 'RS256' if the issuer signs with RSA private key and you verify with the public key)
- Wrap the decode in try-catch to handle `UnexpectedValueException` when signature verification fails
- Return `null` on any verification error, treating it as authentication failure

## Explanation

The original code decoded the JWT payload without verifying that it was signed by a trusted issuer. Manual base64-decoding bypasses all cryptographic verification, making it trivial for an attacker to forge a token with arbitrary claims.

The `firebase/php-jwt` library performs HMAC or RSA signature verification automatically. By passing a `Key` object bound to a specific algorithm, you prevent algorithm-confusion attacks (e.g., switching from RS256 to HS256 to sign with a public key treated as a secret). The library rejects any token whose signature does not match the expected key and algorithm, closing the forgery vulnerability.

The fix requires obtaining the verification key from a trusted source (configuration, keystore, or JWKS endpoint), not from the attacker-supplied token. For token rotation via `kid` (key ID), build a server-controlled array of `Key` objects indexed by `kid` and look up the key before decoding.

## Behaviour changes

- **Rejection of forged tokens**: Any JWT without a valid signature from the configured verification key is rejected, preventing privilege escalation.
- **Exception on signature failure**: Invalid signatures throw `UnexpectedValueException`, caught and converted to `null` (failed authentication).
- **Algorithm binding**: The algorithm is no longer negotiable by the token header; the server enforces the expected algorithm.
- **Performance**: Signature verification adds negligible overhead (microseconds per request for HMAC, milliseconds for RSA).
- **Configuration requirement**: The application must provide the verification key securely. For HS256, this is a shared secret; for RS256, the issuer's public key. Token verification will fail if the key is missing or incorrect.
