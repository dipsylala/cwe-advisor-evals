## Verdict

Algorithm confusion vulnerability in JWT decoding. The code accepts both RS256 and HS256 as valid algorithms, allowing an attacker to forge valid tokens by signing with HS256 using the public RSA key as an HMAC secret.

## Source

Line 44 in AuthController.php passes an array containing multiple algorithms to `JWT::decode()`:

```
$decoded = JWT::decode($jwt, $publicKey, ['RS256', 'HS256']);
```

The `$publicKey` is a public RSA key intended only for RS256 verification. By including HS256 in the allowed algorithms, the verification accepts tokens signed with the public key as an HMAC secret, which the attacker can create without the private key.

## Fix

Restrict the allowed algorithms to only RS256:

```php
$decoded = JWT::decode($jwt, $publicKey, ['RS256']);
```

Alternatively, if the firebase/php-jwt version supports a string argument instead of an array (which is preferred in version 6.0+), use:

```php
$decoded = JWT::decode($jwt, $publicKey, 'RS256');
```

## Explanation

The vulnerability is an algorithm confusion attack. RSA signatures (RS256) require the private key to sign, which only the legitimate server possesses. HMAC signatures (HS256) only require a shared secret, and when the "shared secret" is the public RSA key, an attacker can create valid tokens.

By accepting both RS256 and HS256, the code creates a window where an attacker can bypass authentication. Restricting to only RS256 closes this window—the attacker cannot create a valid RS256 token without the private key, and any HS256 token will be rejected because HS256 is no longer allowed.

This vulnerability is specific to accepting multiple algorithms with asymmetric keys. The fix is to accept only the algorithm(s) that match the key type being used for verification.
