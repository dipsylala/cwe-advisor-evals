## Verdict

The application is vulnerable to JWK Set Poisoning (CWE-347). The code extracts the `jku` (JWK Set URL) from the untrusted JWT header and fetches the public key set from that URL, allowing an attacker to provide their own signing key.

## Source

The vulnerability is in the `IssuerSigningKeyResolver` defined at lines 22–28. Line 25 retrieves the `jku` claim directly from the JWT header:

```csharp
var jku = jwt.Header["jku"]?.ToString();
var keySet = JsonWebKeySetFetcher.Fetch(jku);
```

An attacker can set this URL to a server under their control, sign the token with their own key, and the application will fetch and trust the attacker's public key to validate the signature.

## Fix

Replace the dynamic `jku`-based key resolver with a pre-configured, trusted JWKS endpoint:

```csharp
var parameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "https://auth.example.com",
    ValidateAudience = true,
    ValidAudience = "api://reports",
    ValidateLifetime = true,
    ValidateIssuerSigningKey = true,
    IssuerSigningKeys = JsonWebKeySetFetcher.Fetch("https://auth.example.com/.well-known/jwks.json").Keys
};

return handler.ValidateToken(token, parameters, out _);
```

Alternatively, cache the JWKS periodically to avoid fetching on every validation:

```csharp
private static IEnumerable<SecurityKey>? _cachedKeys;
private static DateTime _keysCacheExpiry = DateTime.MinValue;
private const string TrustedJwksUrl = "https://auth.example.com/.well-known/jwks.json";

private IEnumerable<SecurityKey> GetIssuerSigningKeys()
{
    if (_cachedKeys == null || DateTime.UtcNow > _keysCacheExpiry)
    {
        _cachedKeys = JsonWebKeySetFetcher.Fetch(TrustedJwksUrl).Keys;
        _keysCacheExpiry = DateTime.UtcNow.AddHours(1);
    }
    return _cachedKeys;
}

var parameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "https://auth.example.com",
    ValidateAudience = true,
    ValidAudience = "api://reports",
    ValidateLifetime = true,
    ValidateIssuerSigningKey = true,
    IssuerSigningKeys = GetIssuerSigningKeys()
};
```

## Explanation

The root cause is trusting the `jku` claim in the JWT header, which is part of the untrusted token data. An attacker can craft a JWT with an arbitrary `jku` URL pointing to a server they control, sign it with their own key, and when the application fetches the key set from that URL, it will successfully validate a forged token.

The fix uses a hardcoded, pre-configured JWKS endpoint that belongs to the trusted issuer. The JWKS URL is determined at application startup or configuration time, not extracted from the token. This ensures that key validation happens against keys owned by the trusted issuer, not the attacker.

Caching the keys improves performance and reduces dependency on the availability of the issuer's JWKS endpoint, while still allowing for key rotation through cache expiry.
