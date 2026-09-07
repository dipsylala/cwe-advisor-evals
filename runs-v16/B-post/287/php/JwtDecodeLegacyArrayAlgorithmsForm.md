## Verdict

Exploitable

## Source

HTTP `Authorization` header (line 34: `$authHeader = $headers['Authorization'] ?? ''`), parsed via regex and extracted as `$jwt` (line 39).

## Fix

**Vulnerable code:**
```php
$decoded = JWT::decode($jwt, $publicKey, ['RS256', 'HS256']);
```

**Fixed code:**
```php
$decoded = JWT::decode($jwt, new Key($publicKey, 'RS256'));
```

## Explanation

The vulnerable code uses the deprecated array-of-algorithms form (`JWT::decode($jwt, $key, ['RS256', 'HS256'])`) that was removed in firebase/php-jwt 6.0.0. This form creates an algorithm-confusion vulnerability: by accepting multiple algorithms with the same key, an attacker can forge a valid token by signing with a different algorithm than intended. Specifically, an attacker could sign with HS256 using the public key (which is public knowledge) if the decoder attempts to verify any token's claimed algorithm without binding the key to a specific algorithm first.

The fix migrates to the firebase/php-jwt 6.x+ compatible form using `new Key($publicKey, 'RS256')`, which explicitly binds the RSA public key to RS256 verification only. This prevents the decoder from accepting tokens signed with HS256 or other algorithms, closing the algorithm-confusion vector.

## Behaviour changes

None. The `Key` object form preserves the contract of `JWT::decode()`:
- Returns the same `stdClass` payload on successful verification
- Throws the same `UnexpectedValueException`, `SignatureInvalidException`, or `\UnexpectedValueException` exceptions on failure
- The single-algorithm binding is stricter (security improvement), not a logic change—it rejects tokens signed with algorithms other than RS256, which is the intended behaviour for this RSA verification context
