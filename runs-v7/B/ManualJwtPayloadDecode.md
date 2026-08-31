## Verdict

**Vulnerable** - CWE-347: Improper Verification of Cryptographic Signature

The code extracts and decodes a JWT payload without verifying the JWT signature. An attacker can forge a token with arbitrary claims (e.g., `role: admin`) and the application will trust them.

## Source

Line 6: `$_SERVER['HTTP_AUTHORIZATION']` - attacker-controlled Authorization header containing a forged JWT.

## Fix

Replace the manual JWT parsing and decoding with proper signature verification using `firebase/php-jwt` v6.0.0+:

```php
<?php

require 'vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Reads the bearer token from the request and verifies the signature before decoding claims.
function getAuthenticatedUser(): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
        return null;
    }

    try {
        // Wrap the verification key in a Key object bound to the expected algorithm
        $key = new Key('your-secret-key-or-public-key', 'HS256');  // Use 'RS256' for RSA public keys
        
        // JWT::decode verifies the signature before returning claims
        $claims = JWT::decode($matches[1], $key);
        
        // Validate expected claims after signature verification
        if (!isset($claims->sub)) {
            return null;
        }
        
        return [
            'id' => $claims->sub ?? null,
            'role' => $claims->role ?? null,
        ];
    } catch (\Exception $e) {
        // Signature verification failed - reject the token
        return null;
    }
}

$user = getAuthenticatedUser();
if ($user !== null && $user['role'] === 'admin') {
    echo 'Welcome, admin.';
}
```

## Explanation

The original code manually parsed and decoded the JWT payload without verifying the signature, trusting any claims an attacker supplied. The fix uses `Firebase\JWT\Key` (v6.0.0+) to bind the verification key to a specific algorithm and `JWT::decode()` to verify the signature before accepting the claims. The `Key` object prevents algorithm confusion attacks (CVE-2021-46743) by rejecting tokens that claim a different algorithm than the one bound to the key. Any verification failure (invalid signature, wrong algorithm, tampered data) raises an exception, which the code catches and rejects by returning `null`, failing securely.

## Behaviour changes

- **Signature verification is now mandatory**: tokens without a valid signature are rejected (exceptions caught and return `null`)
- **Algorithm is now bound to the key**: tokens claiming a different algorithm are rejected by the library
- **Unverified tokens are never decoded or trusted**: claims are only extracted after signature verification succeeds
- **Invalid bearer tokens cause function to return `null`** instead of attempting to parse malformed JWTs
