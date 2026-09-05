## Verdict
Confirmed. Algorithm confusion vulnerability in JWT validation.

## Source
Line 44 of `AuthController.php`:
```php
$decoded = JWT::decode($jwt, $publicKey, ['RS256', 'HS256']);
```

The `$publicKey` is an RSA public key (PEM-encoded). By accepting both RS256 (asymmetric) and HS256 (symmetric HMAC), the code allows an attacker to forge tokens using the public key as an HMAC secret.

## Fix
Remove HS256 from the algorithm list. Only RS256 should be accepted when using an RSA public key:

```php
$decoded = JWT::decode($jwt, $publicKey, ['RS256']);
```

## Explanation
JWT algorithm confusion exploits occur when a server accepts multiple signature algorithms for the same key material. RS256 uses asymmetric cryptography (the public key verifies signatures the server's private key created). HS256 uses symmetric HMAC (the same secret signs and verifies). 

When both are accepted and `$publicKey` (public, known to attackers) is reused as an HMAC secret, an attacker can sign arbitrary claims with HS256 and bypass authentication entirely.

The fix restricts validation to the asymmetric algorithm matching the key type. This prevents the public key from being misused as a symmetric secret.
