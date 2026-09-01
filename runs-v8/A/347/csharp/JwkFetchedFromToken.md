## Verdict

Real vulnerability confirmed. The code allows an attacker to control the signing key by supplying a malicious `jku` claim in the JWT header, bypassing cryptographic signature verification.

## Source

The vulnerability originates in the `IssuerSigningKeyResolver` callback at lines 22-28. The code extracts the `jku` (JSON Web Key URL) value directly from the JWT header without validation:

```csharp
var jku = jwt.Header["jku"]?.ToString();
var keySet = JsonWebKeySetFetcher.Fetch(jku);
```

An attacker can forge a JWT with an arbitrary `jku` value pointing to a URL they control, serving a key set containing their own public key. When the handler validates the token, it fetches keys from the attacker's URL and uses those keys to verify the signature, allowing the attacker to forge valid tokens.

## Fix

Replace the dynamic `jku`-based key resolution with a static, pre-configured trusted key set URL:

```csharp
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
        // Use a fixed, trusted JKU URL, not one from the token
        const string trustedJkuUrl = "https://auth.example.com/.well-known/jwks.json";
        var keySet = JsonWebKeySetFetcher.Fetch(trustedJkuUrl);
        return keySet.Keys.Where(k => k.KeyId == kid);
    }
};
```

Alternatively, pre-load the key set once and reuse it:

```csharp
var handler = new JwtSecurityTokenHandler();
var trustedKeySet = JsonWebKeySetFetcher.Fetch("https://auth.example.com/.well-known/jwks.json");

var parameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "https://auth.example.com",
    ValidateAudience = true,
    ValidAudience = "api://reports",
    ValidateLifetime = true,
    ValidateIssuerSigningKey = true,
    IssuerSigningKeys = trustedKeySet.Keys
};

return handler.ValidateToken(token, parameters, out _);
```

## Explanation

CWE-347 occurs when the verification of a cryptographic signature depends on data supplied by an untrusted source. Here, the attacker controls the `jku` claim in the token header, effectively choosing which public key is used to verify the signature they created. This is a complete bypass of cryptographic protection.

The fix removes the attacker's ability to influence key selection by:
1. Hard-coding the trusted key source URL (the issuer's well-known endpoint)
2. Not reading or trusting the `jku` claim from the token itself
3. Ensuring only the issuer's pre-configured keys are used for verification

This enforces the security boundary: the issuer's identity and key set are trust anchors supplied by the application configuration, not by the token being verified.
