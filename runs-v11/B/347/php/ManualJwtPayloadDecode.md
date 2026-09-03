## Verdict
exploitable

## Source
`$_SERVER['HTTP_AUTHORIZATION']` (line 6) - attacker-controlled bearer token from the HTTP Authorization header.

## Fix

### Vulnerable Code
```php
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

    // VULNERABLE: Decodes JWT payload without verifying signature
    $claims = json_decode(base64_decode($payload), true);

    return [
        'id' => $claims['sub'] ?? null,
        'role' => $claims['role'] ?? null,
    ];
}
```

### Fixed Code
```php
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;

function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    try {
        // Verify JWT signature using firebase/php-jwt
        // Secret key must come from a trusted source (env var, config, keystore)
        $secretKey = getenv('JWT_SECRET_KEY');
        if (!$secretKey) {
            return null;
        }

        // Decode and verify the token in a single call
        // The Key object binds the key material to the specific algorithm
        $decoded = JWT::decode($matches[1], new Key($secretKey, 'HS256'));

        return [
            'id' => $decoded->sub ?? null,
            'role' => $decoded->role ?? null,
        ];
    } catch (ExpiredException $e) {
        // Token has expired
        return null;
    } catch (SignatureInvalidException $e) {
        // Signature verification failed - token is forged or tampered
        return null;
    } catch (\Exception $e) {
        // Other JWT errors (malformed, invalid claims, etc.)
        return null;
    }
}
```

## Explanation
The vulnerability is that the original code manually splits the JWT, extracts the payload, and decodes it without verifying the cryptographic signature. This allows an attacker to forge a JWT with any claims (e.g., `"role": "admin"`) that will be accepted by the application. The fixed code uses the `firebase/php-jwt` library (version 6.0.0 or later) to properly verify the JWT signature before trusting the claims. The `JWT::decode()` method with a `Key` object ensures that the signature is validated, preventing forged tokens. The algorithm is explicitly specified in the `Key` object to prevent algorithm confusion attacks (CVE-2021-46743). The secret key is retrieved from a trusted source (environment variable), never from the token itself.

## Behaviour changes
- **Dependency added**: Requires `firebase/php-jwt` package (version 6.0.0 or later).
- **Secret key requirement**: The function now requires the JWT secret key to be available from `getenv('JWT_SECRET_KEY')`. If the key is not set, the function returns `null` (authentication fails securely).
- **Exception handling**: The function now catches and handles JWT-specific exceptions (`ExpiredException`, `SignatureInvalidException`) as well as general exceptions, returning `null` on any error instead of proceeding with untrusted claims.
- **Return value change**: The decoded object is now a `stdClass` object with properties (accessed via `->sub`, `->role`) rather than an associative array. The return value structure is adapted accordingly to maintain API compatibility.
- **No silent acceptance**: Tokens with invalid or missing signatures will now be rejected, whereas the original code accepted all tokens regardless of signature validity.
