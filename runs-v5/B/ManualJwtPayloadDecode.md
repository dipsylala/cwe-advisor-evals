## Verdict

Exploitable. Confidence: high.

CWE-347 (Improper Verification of Cryptographic Signature), PHP. `getAuthenticatedUser()` splits the bearer token into its three dot-separated parts but only ever touches `$parts[1]` (the payload) — `$parts[2]`, the signature, is discarded and no verification call of any kind is made before the claims are trusted. Any caller can send `Bearer <base64(header)>.<base64({"sub":"x","role":"admin"})>.<anything>` and be treated as an authenticated admin; the third segment can be empty or garbage and the function still returns the forged claims.

Assumption: no `firebase/php-jwt` (or other JWT library) dependency exists in this snippet, so the fix introduces one rather than correcting a misused call, per `cwe/347/php/INDEX.md`'s recommended library for this ecosystem.

## Source

`$_SERVER['HTTP_AUTHORIZATION']` (line 6) — attacker-controlled request header, matched against `^Bearer\s+(.+)$` and passed through unchanged as the raw token.

## Fix

**Library recommendation:** `firebase/php-jwt`, minimum safe version 6.0.0 (per `cwe/347/php/INDEX.md`; pre-6.0.0 is directly exploitable via CVE-2021-46743 algorithm confusion). Add to `composer.json`:
`"firebase/php-jwt": "^6.0"`
Confirm the resolved version against SCA/dependency-check tooling before merging.

**Vulnerable code:**

```php
$parts = explode('.', $matches[1]);
if (count($parts) !== 3) {
    return null;
}

$payload = strtr($parts[1], '-_', '+/');

// SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
$claims = json_decode(base64_decode($payload), true);
```

**Fixed code:**

```php
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// $jwtSecret must come from server-side configuration/secrets storage - never derived
// from the token itself.
$jwtSecret = getenv('JWT_SIGNING_SECRET');

try {
    $claims = (array) JWT::decode($matches[1], new Key($jwtSecret, 'HS256'));
} catch (\Throwable $e) {
    return null;
}
```

## Explanation

The manual split/base64-decode path never verified the token's signature, so the payload was trusted regardless of who produced it. The fix replaces that entire manual parse with `Firebase\JWT\JWT::decode()`, passing a `Key` object that binds the verification secret to one explicit algorithm (`HS256`) rather than a bare key string or an algorithm read from the token — this closes both the missing-verification gap and the algorithm-confusion variant the library is otherwise exposed to on pre-6.0.0. The secret is read from server-side configuration (`getenv`), never from request data, per the guidance's key-handling principle. Any decode failure (bad signature, malformed token, expired claim) throws, and the surrounding `try`/`catch` maps that to the same `null` "unauthenticated" result the original function already used for a malformed header, so callers see no new failure shape.

## Behaviour changes

- The function now rejects any token whose signature does not verify, where the original accepted every token unconditionally. This is the fix itself, not incidental.
- `JWT::decode()` additionally validates the standard `exp`/`nbf`/`iat` time claims when present, causing an expired or not-yet-valid token to be rejected as well. The original performed no such check. This follows from using the recommended library call and is a strengthening, not a functional regression, but it is a genuine change in accepted input versus the original code.
- No change to the function's return shape (`['id' => ..., 'role' => ...]` or `null`) or to the caller's admin-check logic.
