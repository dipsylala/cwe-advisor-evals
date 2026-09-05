## Verdict

Exploitable.

## Source

Attacker-controlled JWT token passed as the `token` parameter to `ValidateToken()`.

## Fix

**Vulnerable code:**

```csharp
IssuerSigningKeyResolver = (rawToken, securityToken, kid, _) =>
{
    var jwt = (JwtSecurityToken)securityToken;
    var jku = jwt.Header["jku"]?.ToString();
    var keySet = JsonWebKeySetFetcher.Fetch(jku);
    return keySet.Keys.Where(k => k.KeyId == kid);
}
```

**Fixed code:**

```csharp
public ClaimsPrincipal ValidateToken(string token)
{
    var handler = new JwtSecurityTokenHandler();
    
    // Fetch JWKS from a trusted, server-side configuration, not from the token header
    var trustedJwksUrl = "https://auth.example.com/.well-known/jwks.json"; // from configuration
    var keySet = JsonWebKeySetFetcher.Fetch(trustedJwksUrl);

    var parameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = "https://auth.example.com",
        ValidateAudience = true,
        ValidAudience = "api://reports",
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKeys = keySet.Keys  // use pre-fetched keys from trusted source
    };

    return handler.ValidateToken(token, parameters, out _);
}
```

## Explanation

The vulnerability occurs because the `IssuerSigningKeyResolver` reads the `jku` (JSON Web Key Set URL) from the JWT header itself, then fetches the JWKS from that attacker-supplied URL. This allows an attacker to create a JWT with a malicious `jku` header pointing to their own server, causing the application to fetch keys from the attacker's JWKS endpoint. The attacker can then sign tokens using their own keys, bypassing signature verification and gaining unauthorized access.

The fix pre-fetches the JWKS from a trusted, server-side configuration instead of reading from the token header. The keys are stored in `IssuerSigningKeys` before token validation, ensuring signature verification uses only trusted keys. This prevents the attacker from redirecting the key fetch to their own server.

## Behaviour changes

The JWKS is now fetched once from a trusted source during initialization rather than on every token validation. If the issuer rotates keys, the application must refresh the JWKS separately (either by restarting, polling for updates, or using a cache invalidation strategy). The `IssuerSigningKeyResolver` is removed entirely, which changes the validation flow: the `kid` claim is now matched against the pre-fetched trusted keys only, not against dynamically-fetched keys. If token validation requires supporting multiple issuers with different JWKS URLs, the trusted source must be configured per-issuer and keys from all trusted issuers must be included in `IssuerSigningKeys`.
