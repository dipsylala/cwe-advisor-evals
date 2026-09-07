## Verdict

Real vulnerability - signature verification is completely absent. The code manually parses and decodes the JWT payload without checking the signature, allowing attackers to forge authentication tokens with arbitrary claims.

## Source

Line 19: `$claims = json_decode(base64_decode($payload), true);`

The `$payload` variable (extracted from an attacker-controlled HTTP Authorization header at line 6-14) is base64-decoded and JSON-decoded without any cryptographic verification. The JWT signature is never validated, so a forged token with any claims will be accepted.

Data flow:
- Source: `$_SERVER['HTTP_AUTHORIZATION']` (attacker-controlled HTTP header)
- Extraction: Bearer token parsed via regex
- Parsing: JWT structure split by dots (line 11)
- Payload isolation: middle segment URL-decoded (line 16)
- Sink: Unverified decode at line 19
- Use: Claims extracted and used in security decision (role check at line 28)

## Fix

### File: ManualJwtPayloadDecode.php

```php
<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Reads the bearer token from the request and verifies its signature before decoding claims.
function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    $token = $matches[1];
    
    // Retrieve the signing key from configuration (e.g., from environment or keystore).
    // For RS256/ES256, this should be the public key; for HS256, the shared secret.
    $signingKey = $_ENV['JWT_SIGNING_KEY'] ?? null;
    if (!$signingKey) {
        return null; // Key not configured
    }

    try {
        // Verify the JWT signature and decode claims.
        // The Key object binds the key material to the exact algorithm expected.
        // Token with mismatched algorithm (e.g., attempting algorithm confusion) will be rejected.
        $claims = JWT::decode($token, new Key($signingKey, 'RS256'));
        
        // Convert the decoded object to an array for consistent access.
        $claimsArray = (array) $claims;

        return [
            'id' => $claimsArray['sub'] ?? null,
            'role' => $claimsArray['role'] ?? null,
        ];
    } catch (\Exception $e) {
        // Signature verification failed or token is malformed.
        // Fail securely by returning null (no authenticated user).
        return null;
    }
}

$user = getAuthenticatedUser();
if ($user !== null && $user['role'] === 'admin') {
    echo 'Welcome, admin.';
}
```

## Explanation

The original code bypassed all signature verification by manually parsing and decoding the JWT payload. This allowed an attacker to forge any JWT with arbitrary claims (e.g., `role: admin`) without needing the signing key.

The fix uses `Firebase\JWT\JWT::decode()` with a `Key` object that binds the key material to a specific algorithm (RS256 in this example). This enforces:

1. **Signature verification** - the token's signature is cryptographically validated before claims are extracted
2. **Algorithm binding** - the `Key` object prevents algorithm-confusion attacks where an attacker switches RS256 to HS256
3. **Secure failure** - any verification error (forged signature, mismatched algorithm, malformed token) returns null instead of partial data

The signing key (`$_ENV['JWT_SIGNING_KEY']`) should be stored in secure configuration (environment variable, secrets manager, or keystore), never embedded in code or derived from the token itself.

The fix requires `firebase/php-jwt` version 6.0.0 or later. Older versions are vulnerable to CVE-2021-46743 (algorithm confusion) and use a different API signature.

## Behaviour changes

- **Accepts only signed tokens**: Unsigned tokens or tokens with invalid signatures are rejected with a return value of `null` (authentication fails).
- **Rejects forged tokens**: Tokens signed with a different key or algorithm are rejected.
- **Error handling**: Any JWT processing error (invalid format, verification failure) is caught and results in `null` return (fail-secure).
- **Algorithm specification**: The fix hard-codes RS256; adjust the algorithm string in the `Key` constructor to match your issuer (e.g., `ES256`, `HS256`).
- **Configuration requirement**: Requires the signing key to be available in `$_ENV['JWT_SIGNING_KEY']`; application startup will fail gracefully if this is not configured.
