## Verdict

Exploitable

## Source

Attacker-controlled JWT token passed as the `token` parameter to `ValidateToken()`.

## Sink

`JwtSecurityTokenHandler.ValidateToken(token, parameters, out _)` at line 32, called with `TokenValidationParameters` that lacks algorithm restriction and uses an untrusted key resolver.

## Fix

**Vulnerable code:**

```csharp
public ClaimsPrincipal ValidateToken(string token)
{
    var handler = new JwtSecurityTokenHandler();

    var parameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = "https://auth.example.com",
        ValidateAudience = true,
        ValidAudience = "api://reports",
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKeyResolver = (rawToken, securityToken, kid, _) =>
        {
            var jwt = (JwtSecurityToken)securityToken;
            var jku = jwt.Header["jku"]?.ToString();
            var keySet = JsonWebKeySetFetcher.Fetch(jku);
            return keySet.Keys.Where(k => k.KeyId == kid);
        }
    };

    return handler.ValidateToken(token, parameters, out _);
}
```

**Fixed code:**

```csharp
public ClaimsPrincipal ValidateToken(string token)
{
    var handler = new JwtSecurityTokenHandler();

    // Load trusted signing keys from server-side configuration
    var trustedKeys = new List<SecurityKey>
    {
        new RsaSecurityKey(GetTrustedPublicKey()) // Fetch from configuration/keystore
    };

    var parameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = "https://auth.example.com",
        ValidateAudience = true,
        ValidAudience = "api://reports",
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKeys = trustedKeys,
        ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
        RequireSignedTokens = true,
        RequireExpirationTime = true
    };

    return handler.ValidateToken(token, parameters, out _);
}

private RSA GetTrustedPublicKey()
{
    // Load the trusted issuer's public key from server-side configuration, not from token
    // This could be from environment variables, a key management service, or a pinned JWKS endpoint
    // Example: return _config.GetRsaPublicKey("https://auth.example.com");
    throw new NotImplementedException("Load from trusted configuration");
}
```

## Explanation

The vulnerability occurs because `TokenValidationParameters` does not specify `ValidAlgorithms`, allowing an attacker to perform an algorithm confusion attack: take a legitimate RS256 token, change the algorithm header to HS256, and sign it using the server's public key as an HMAC secret. The fix enforces a specific approved algorithm and eliminates the second critical flaw: the `IssuerSigningKeyResolver` that trusts the token's `jku` header to fetch keys. Instead, keys must come from a trusted server-side source (configuration, environment, or a pinned JWKS endpoint) that is not controlled by the token. Setting `ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 }` restricts signature verification to RSA with SHA-256, preventing the HS256 confusion attack. Using `IssuerSigningKeys` with keys loaded from trusted configuration prevents attackers from injecting or redirecting key fetches.

## Behaviour changes

1. **ValidAlgorithms restriction**: The handler now rejects tokens with algorithm headers other than RsaSha256, raising `SecurityTokenInvalidSignatureException` for mismatched algorithms. This is intentional security hardening and matches the documented expected behavior.

2. **IssuerSigningKeys source**: Keys now come from server-side configuration (`GetTrustedPublicKey()`) rather than from a URL specified in the token header. Tokens with `jku` headers are no longer trusted; only the pre-configured keys are used. This is the intended fix for the vulnerability.

3. **RequireSignedTokens and RequireExpirationTime**: These flags are now explicitly set to `true` for defense-in-depth. By default, `RequireSignedTokens` is already `true`, but `RequireExpirationTime` defaults to `false`. This change ensures tokens without expiration are rejected, preventing indefinite token validity.

4. **Return value and exceptions**: The handler will throw `SecurityTokenInvalidSignatureException` if the token cannot be verified with the trusted keys or if the algorithm is not in `ValidAlgorithms`. This is the expected failure mode for verification failure and should be caught by the calling code's exception handler.

5. **The IssuerSigningKeyResolver callback is removed**: This eliminates the untrusted key-fetching mechanism entirely. Any code path that relied on dynamic key resolution from token headers will fail validation, which is correct behavior.
