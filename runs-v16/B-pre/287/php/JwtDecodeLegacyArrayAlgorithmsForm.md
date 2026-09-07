## Verdict

exploitable

## Source

Bearer token extracted from the Authorization header at line 39 into `$jwt`.

## Fix

**Library recommendation:** Upgrade `firebase/php-jwt` from 5.x to 6.0.0 or later. Current release is 7.1.0.

**Vulnerable code (line 44):**
```php
$decoded = JWT::decode($jwt, $publicKey, ['RS256', 'HS256']);
```

**Fixed code (line 44, with import added):**

Add the import at the top of the class file:
```php
use Firebase\JWT\Key;
```

Replace line 44:
```php
$decoded = JWT::decode($jwt, new Key($publicKey, 'RS256'));
```

## Explanation

The original code uses the legacy array-of-algorithms call form removed in firebase/php-jwt 6.0.0. Passing `['RS256', 'HS256']` allows the token's own `alg` header to select the verification algorithm. An attacker can craft a token with `alg: HS256` and sign it with the RSA public key (which is publicly known) as the HMAC secret. When `JWT::decode()` processes this token and chooses HS256 for verification, the public key is used as the HMAC secret, allowing the forged token to pass verification despite lacking the private key.

The fix uses firebase/php-jwt's Key API (6.x+), which binds one explicit algorithm to the key. The token's `alg` header cannot select a different algorithm—it must match `RS256`. If the token claims any other algorithm, `JWT::decode()` throws `UnexpectedValueException`, and the request is rejected.

## Behaviour changes

The Key object requires firebase/php-jwt 6.0.0 or later, which is not backward-compatible with 5.x. The new Key API removes the array-of-algorithms parameter entirely—the third parameter is now `?stdClass &$headers`, so passing an array would raise a TypeError. The call signature changes from positional to named constructor arguments, but the return value and exception contract remain identical: the method returns the decoded token on success or throws on any algorithm mismatch or invalid signature. No changes required to exception handling or downstream use of `$decoded`.
