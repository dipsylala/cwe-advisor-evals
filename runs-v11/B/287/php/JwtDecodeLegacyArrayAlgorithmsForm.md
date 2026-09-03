## Verdict
exploitable

## Source
Bearer token from the `Authorization` header (line 34-39, extracted via regex matching).

## Sink
`JWT::decode($jwt, $publicKey, ['RS256', 'HS256'])` at line 44.

## Fix

**Library Recommendation:**
Upgrade `firebase/php-jwt` to version 6.0.0 or later (current stable: 7.1.0). The array-of-algorithms form was removed in 6.0.0 and replaced with the `Key` object pattern.

**Vulnerable Code:**
```php
$decoded = JWT::decode($jwt, $publicKey, ['RS256', 'HS256']);
```

**Fixed Code:**
```php
use Firebase\JWT\Key;

// ... in the class
try {
    $decoded = JWT::decode($jwt, new Key($this->rsaPublicKey, 'RS256'));
} catch (ExpiredException | SignatureInvalidException | \UnexpectedValueException $e) {
    return null;
}
```

## Explanation
The original code is vulnerable to algorithm confusion: it accepts both RS256 and HS256 algorithms with a single key (the RSA public key). An attacker can forge an HS256-signed token using the public RSA key, set the token's `alg` header to "HS256", and the decoder will accept it as valid.

The fixed code binds the RSA public key to RS256 exclusively using the `Key` object, preventing the `alg` header from causing a different algorithm to be used with the key. This eliminates the algorithm confusion attack surface.

Note: HS256 support is removed because the original code did not use the correct key for it—the `$hmacSecret` property was never passed to `JWT::decode()`. If HS256 tokens are genuinely needed, support both algorithms by passing a single `Key` object for RS256 (recommended) or creating separate decode calls with different keys.

## Behaviour changes
- The JWT decoder now accepts only RS256-signed tokens, not HS256.
- If HS256 tokens were being accepted before (they were not with the original key), they will now be rejected with an `UnexpectedValueException`.
- The algorithm in the token's `alg` header must now match the bound algorithm (RS256), preventing algorithm substitution attacks.
- All other behavior (extracting the bearer token, error handling, return value) remains identical.
