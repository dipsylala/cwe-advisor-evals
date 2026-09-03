## Verdict

The code decodes and trusts a JWT payload without verifying the cryptographic signature. An attacker can forge any JWT by modifying the payload and signature fields, causing the application to accept forged authentication claims.

## Source

```php
$payload = strtr($parts[1], '-_', '+/');
$claims = json_decode(base64_decode($payload), true);
```

The code splits the JWT into three parts (header, payload, signature) but only decodes the payload. The signature is never validated, so the claims are accepted without authentication.

## Fix

Replace manual JWT decoding with a library that enforces signature verification. Use `firebase/jwt`:

```php
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
```

Key changes:
- Use `firebase/jwt`'s `JWT::decode()`, which verifies the signature before returning claims
- Specify the algorithm (`HS256`) and secret key explicitly
- Wrap the decode in a try-catch to handle invalid or tampered tokens
- The function now returns null if signature verification fails

Ensure the secret key is stored securely (environment variable, secrets manager) and matches what the token issuer used.

## Explanation

CWE-347 occurs when cryptographic signatures are not verified before trusting their content. Manually extracting and decoding a JWT payload bypasses the entire purpose of the signature.

A properly-implemented JWT library like `firebase/jwt` (or alternatives like `lcobucci/jwt`) performs signature verification as part of the decode operation. If verification fails, an exception is thrown and the claims are never extracted.

This fix ensures that:
1. Only tokens signed with the correct secret key are accepted
2. The payload has not been modified since signing
3. Forged or tampered tokens are rejected before use in authorization decisions
