## Verdict

- **CWE**: CWE-347 (Improper Verification of Cryptographic Signature)
- **Location**: `ManualJwtPayloadDecode.php`, line 19 (sink)
- **Verdict**: exploitable
- **Confidence**: high

## Source

- **Source**: `$_SERVER['HTTP_AUTHORIZATION']` - the bearer token is fully attacker-controlled.
- **Flow**: The header is matched with `/^Bearer\s+(.+)$/`, the token is split on `.` into three parts, and only `$parts[1]` (the payload) is used. `$parts[2]` (the signature) is extracted by `explode()` but never read, never compared, and never passed to any verification routine.
- **Sink**: `json_decode(base64_decode($payload), true)` at line 19 - this decodes and trusts the payload's claims (`sub`, `role`) with no cryptographic check that the payload was issued by the server. An attacker can craft any three-part, dot-separated string with a base64url JSON payload of `{"sub":"x","role":"admin"}` and an arbitrary (or empty) third segment, send it as the bearer token, and be treated as an authenticated admin - the admin-gated `echo` at the bottom of the file confirms this is a real authorization decision, not inert data.

## Fix

### File: ManualJwtPayloadDecode.php

```php
<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Reads the bearer token from the request, verifies its signature, and returns its claims.
function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    // Verification key comes from server-side configuration, never from the token itself.
    $signingKey = getenv('JWT_SIGNING_KEY');
    if ($signingKey === false || $signingKey === '') {
        return null;
    }

    try {
        // Key binds the secret to a single algorithm, so a token can't switch algorithms to
        // trick the verifier (e.g. RS256 -> HS256 key-confusion, CVE-2021-46743).
        $claims = JWT::decode($matches[1], new Key($signingKey, 'HS256'));
    } catch (\Throwable $e) {
        return null;
    }

    return [
        'id' => $claims->sub ?? null,
        'role' => $claims->role ?? null,
    ];
}

$user = getAuthenticatedUser();
if ($user !== null && $user['role'] === 'admin') {
    echo 'Welcome, admin.';
}
```

**Dependency**: add `firebase/php-jwt` at **6.0.0 or later** (`composer require firebase/php-jwt:^6.0`) - versions before 6.0.0 took allowed algorithms as a separate array argument rather than binding them to the key, which is what CVE-2021-46743 (GHSA-8xf4-w7qw-pjjw) exploited. Confirm the resolved version against SCA/dependency-check tooling before merging.

## Explanation

The original code never verified anything: it split the JWT, base64-decoded and JSON-decoded the payload segment, and discarded the signature segment entirely, so any well-formed three-part string was accepted and its claims trusted for an authorization decision. The fix replaces the manual split/decode with `Firebase\JWT\JWT::decode()`, passing the verification secret wrapped in a `Firebase\JWT\Key` bound to a single explicit algorithm (`HS256`). This forces an actual cryptographic check of the token against a server-held key before any claim is read, and the algorithm binding closes the RS256/HS256 key-confusion path (CVE-2021-46743) that the same library was vulnerable to pre-6.0.0. A malformed, unsigned, expired, or signature-mismatched token now throws inside `JWT::decode()`, which is caught and converted into the same "unauthenticated" (`null`) outcome the original code produced for a malformed token, so the authorization behavior for legitimate and rejected callers is unchanged - only forged/tampered tokens, which were previously accepted, are now rejected.

## Behaviour changes

- **Claim access syntax**: `$claims['sub']` / `$claims['role']` became `$claims->sub` / `$claims->role`. Required because `JWT::decode()` returns a `stdClass` object of claims, not an associative array - the function's own return value (`['id' => ..., 'role' => ...]`) is unchanged, so callers see no difference.
- **New failure mode - missing key configuration**: if `JWT_SIGNING_KEY` is unset or empty, the function now returns `null` (treated as unauthenticated) instead of attempting to read any claims. This is intentional and matches the "fail securely" principle in the loaded guidance; it did not exist before because the original code never involved a server-side key at all.
- **Rejects tokens the original accepted**: any token whose signature does not verify (forged, tampered, wrong algorithm, or expired) is now rejected (`null`) where it was previously accepted and its claims trusted. This is the vulnerability being closed, not an unrelated behavior change.
- Everything else - the `Authorization` header parsing, the `Bearer` regex, the three-part shape check (now enforced by the library instead of by hand), and the final admin-gated `echo` - is unchanged.

**Verification**: `php -l` was run against the fixed file and reported no syntax errors. `firebase/php-jwt` is not installed in this sandbox (the case ships a single file with no `composer.json`), so `JWT::decode()`/`Key` were not exercised at runtime; their names, constructor shape (`new Key($keyMaterial, 'RS256')`/equivalent), and the fact that `decode()` returns an object rather than an array are all taken directly from the loaded PHP-specific CWE-347 guidance rather than from recall.

**Assumptions**:
- The issuer's actual signing algorithm and key material are not visible in this single-file case, so a symmetric `HS256` shared secret read from `JWT_SIGNING_KEY` was assumed. If the real issuer signs asymmetrically (e.g. RS256/ES256), swap the `Key` algorithm and supply the issuer's public key instead of a shared secret.
- The signing secret's actual source (env var vs. config service vs. secrets manager) is unspecified in the case; `getenv('JWT_SIGNING_KEY')` is a placeholder for "server-side configuration, never the token" and should be pointed at the application's real secret store.
- `firebase/php-jwt` >= 6.0.0 is recommended per the loaded guidance's cited CVE fix version; the exact version to pin should still be confirmed via SCA tooling before merging.
