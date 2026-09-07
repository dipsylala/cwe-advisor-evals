## Verdict

Exploitable. The code extracts and decodes the JWT payload without verifying the signature, allowing an attacker to forge a JWT with arbitrary claims (e.g., `role: admin`) and bypass authentication.

## Source

Attacker-supplied JWT in the `Authorization: Bearer` header (`$_SERVER['HTTP_AUTHORIZATION']`), parsed and used to set user identity and role.

## Fix

Vulnerable code (line 19):
```php
$claims = json_decode(base64_decode($payload), true);
```

Fixed code:
```php
require_once 'vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    try {
        $signingKey = new Key('your-rsa-public-key-here', 'RS256');
        $decoded = JWT::decode($matches[1], $signingKey);
        $claims = (array) $decoded;
    } catch (\Exception $e) {
        return null;
    }

    return [
        'id' => $claims['sub'] ?? null,
        'role' => $claims['role'] ?? null,
    ];
}
```

## Explanation

The original code manually decoded the JWT payload without verifying the cryptographic signature, trusting any JWT the client provides. The fix uses `firebase/php-jwt` v6+ to properly verify the signature before accepting any claims. The `Key` object binds the verification key to a specific algorithm (RS256), preventing algorithm-confusion attacks. If signature verification fails (attacker-forged token, expired token, or wrong algorithm), `JWT::decode()` throws an exception, which is caught and returns `null`, denying access. The fix requires the application to provide the correct RSA public key used to verify tokens—this should come from a secure configuration source, not the token itself.

## Behaviour changes

1. **Requires dependency** - code now requires `firebase/php-jwt` v6.0.0+ (upgrade from manual decode). Assumption: this library is added to `composer.json`.
2. **Exception handling** - if token verification fails, the function now catches the exception and returns `null` (access denied) instead of potentially extracting invalid claims. Original code had no error handling; any malformed token would proceed and produce incomplete claims.
3. **Configuration requirement** - the RSA public key must be provided via secure configuration (not shown here as placeholder). Original code needed no external key material.
4. **Return type contract intact** - function still returns `?array` with `id` and `role` keys, or `null` on failure.
