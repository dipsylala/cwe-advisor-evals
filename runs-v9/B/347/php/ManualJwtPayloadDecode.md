## Verdict

- **CWE-347** - Improper Verification of Cryptographic Signature
- **Location**: `ManualJwtPayloadDecode.php`, line 19 (sink: `json_decode(base64_decode($payload), true)`)
- **Verdict**: `exploitable`
- **Confidence**: high

## Source

- **Source**: `$_SERVER['HTTP_AUTHORIZATION']` - the raw `Authorization` request header, fully attacker-controlled.
- **Flow**: the header is matched against `/^Bearer\s+(.+)$/` to extract the token, split on `.` into three JWT segments, and only the middle segment (`$parts[1]`, the payload) is used. It is base64url-normalized with `strtr` and passed to `base64_decode()` then `json_decode()`.
- **Sink**: line 19, `json_decode(base64_decode($payload), true)`. The third segment (`$parts[2]`, the signature) is extracted by `explode()` but never read again anywhere in the file - no HMAC/RSA verification, no library call, no comparison against any key ever occurs.
- **Consequence**: `$claims['sub']` and `$claims['role']` are trusted directly from this unverified decode. An attacker can construct any three-part, dot-separated, base64url string with an arbitrary JSON payload (signature segment can be anything, since it's never checked) and set `role` to `admin` in the payload to reach the `echo 'Welcome, admin.'` branch at line 28-30 - a straightforward authentication/authorization bypass, not merely an algorithm-confusion edge case.

## Fix

**Library recommendation**: `firebase/php-jwt`, minimum **6.0.0** (per the loaded PHP guidance for CWE-347; this is the release that requires a `Firebase\JWT\Key` object bound to a specific algorithm, closing CVE-2021-46743 algorithm-confusion). Confirm the resolved version against SCA/dependency-check tooling before merging.

`composer.json`:
```
"require": {
    "firebase/php-jwt": "^6.0"
}
```

**Vulnerable code**:
```php
<?php

// Reads the bearer token from the request and decodes its claims without checking the signature.
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

    // SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
    $claims = json_decode(base64_decode($payload), true);

    return [
        'id' => $claims['sub'] ?? null,
        'role' => $claims['role'] ?? null,
    ];
}

$user = getAuthenticatedUser();
if ($user !== null && $user['role'] === 'admin') {
    echo 'Welcome, admin.';
}
```

**Fixed code**:
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

    $jwt = $matches[1];

    // Verification key comes from server-side configuration, never from the token itself.
    $publicKeyPem = getenv('JWT_PUBLIC_KEY');
    if ($publicKeyPem === false) {
        return null;
    }

    try {
        // Key is bound to a single explicit algorithm; a token whose header claims a
        // different algorithm (e.g. HS256 using this RSA key as an HMAC secret) is rejected.
        $claims = JWT::decode($jwt, new Key($publicKeyPem, 'RS256'));
    } catch (\Throwable $e) {
        // Invalid signature, malformed token, wrong/mismatched algorithm, or expired/not-yet-valid.
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

## Explanation

The original code treated the JWT payload segment as trusted data after decoding it, but never verified the signature segment against any key - `$parts[2]` was extracted and then never used, so any attacker who can set the `Authorization` header can forge arbitrary claims, including `role: admin`. The fix replaces the manual split/base64-decode/json-decode sequence with `Firebase\JWT\JWT::decode()`, which performs full structural, encoding, and cryptographic signature validation before any claim is returned, using a `Key` object that binds the verification key to a single explicit algorithm (`RS256`) as required by `firebase/php-jwt` 6.0+ to prevent algorithm-confusion (CVE-2021-46743). The key material itself is read from server-side configuration (`JWT_PUBLIC_KEY`), never derived from the token, per the guidance's principle that the verification key must come from configuration, a keystore, or a JWKS cache - not from the token being verified. Any verification failure (bad signature, wrong algorithm, malformed token, expired token) is caught and results in `null`, matching the original function's fail-closed return contract for malformed input.

## Behaviour changes

- `$claims` changes from an associative array (`json_decode($x, true)`) to a `stdClass` object, because `JWT::decode()` returns a decoded object rather than an array; claim access changed from `$claims['sub']` / `$claims['role']` to `$claims->sub` / `$claims->role` to match. Reason: required by the safe API's return contract, not a discretionary change.
- A new external dependency on `JWT_PUBLIC_KEY` (or equivalent trusted config source) is introduced. If that value is unset, the function now returns `null` for every request rather than attempting to decode. Reason: the guidance's principle that an unset environment/config value must not select a permissive branch - failing closed here is intentional, not a regression.
- Tokens that previously "succeeded" (decoded to a claims array) because they were syntactically valid base64/JSON but had no real signature now fail and return `null`. Reason: this is the vulnerability being fixed - the previous "success" path was the unauthenticated bypass.
- The manual `strtr()` base64url normalization and the `count($parts) !== 3` structural check are removed; `JWT::decode()` performs its own base64url decoding and structural validation internally and throws on malformed input, which is caught by the same `catch` block. Reason: redundant with, and superseded by, the library's own validation - keeping both would not add safety.
- Everything else (the `Authorization` header parsing regex, the `null`-safe caller pattern, the `role === 'admin'` authorization check, the echo output) is unchanged.

## Assumptions

- The verification key is available server-side as an RSA public key in PEM form via an environment variable (`JWT_PUBLIC_KEY`); the actual configuration source (env var, keystore, JWKS cache) was not specified in the finding, so this is a placeholder for "server-side configuration, not the token" and should be adapted to the application's real key-management mechanism.
- The issuer signs with `RS256`; if the actual algorithm differs, the `Key` object's algorithm argument should be changed to match - it must still be a single explicit algorithm, not derived from the token header.
