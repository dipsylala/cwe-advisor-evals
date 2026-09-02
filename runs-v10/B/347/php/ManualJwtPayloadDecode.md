## Verdict

**CONFIRMED** — CWE-347 (Improper Verification of Cryptographic Signature). The code decodes a JWT payload without verifying its signature, allowing an attacker to forge authentication tokens with arbitrary claims.

## Source

`$_SERVER['HTTP_AUTHORIZATION']` — attacker-controlled HTTP Authorization header carrying a JWT Bearer token. The JWT is parsed and its claims are trusted without signature verification.

## Fix

Replace manual JWT decoding with signature verification using `firebase/php-jwt` v6.0.0+. Wrap the verification key in a `Firebase\JWT\Key` object bound to the expected algorithm, preventing algorithm-confusion attacks.

**Vulnerable code (line 19):**
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

    // VULNERABILITY: No signature verification - attacker can forge any claims
    $claims = json_decode(base64_decode($payload), true);

    return [
        'id' => $claims['sub'] ?? null,
        'role' => $claims['role'] ?? null,
    ];
}
```

**Fixed code:**
```php
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    $jwt = $matches[1];
    
    try {
        // Verify JWT signature using the configured secret key bound to RS256 algorithm
        $secretKey = getenv('JWT_SECRET_KEY'); // Retrieve from secure config, not token
        $key = new Key($secretKey, 'RS256'); // Bind algorithm to prevent confusion attacks
        
        $claims = JWT::decode($jwt, $key);
        
        return [
            'id' => $claims->sub ?? null,
            'role' => $claims->role ?? null,
        ];
    } catch (\Exception $e) {
        // Signature verification failed - reject request
        return null;
    }
}
```

## Explanation

The original code manually parses a JWT without verifying its cryptographic signature. This allows attackers to forge tokens with any claims (e.g., `role: 'admin'`), bypassing authentication entirely. The fix uses `firebase/php-jwt` v6.0.0+ to properly verify the JWT signature before trusting its contents.

Key changes:
- **Import JWT library:** Use `Firebase\JWT\JWT` and `Firebase\JWT\Key`
- **Load verification key from configuration:** Retrieve the HMAC secret or RSA public key from secure config (environment variable, keystore, or trusted store), never from the token itself
- **Wrap key in `Key` object with explicit algorithm:** This binds the algorithm to the key, preventing algorithm-confusion attacks (CVE-2021-46743) where an attacker could switch from RS256 to HS256
- **Call `JWT::decode()`:** Verifies the signature and validates standard claims (exp, iat, etc.)
- **Handle exceptions:** Any signature verification failure throws `UnexpectedValueException`, which is caught and treated as failed authentication
- **Use decoded claims object:** `JWT::decode()` returns stdClass properties (e.g., `$claims->sub`), not an associative array

The fix ensures that only JWTs signed with the correct key and algorithm are accepted, preventing token forgery attacks.

## Behaviour changes

- **JWT signature verification is now mandatory** — tokens without a valid signature are rejected immediately
- **Failed authentication returns `null`** — any signature mismatch or verification error results in null return, treating it as failed authentication
- **Claim access changes from array to object** — decoded claims are accessed as object properties (`$claims->sub`) instead of array keys (`$claims['sub']`)
- **Configuration dependency** — verification key must be supplied from a secure config source and kept out of the token itself
- **Required dependency** — `firebase/php-jwt` v6.0.0 or later must be installed; earlier versions are vulnerable to algorithm-confusion attacks

