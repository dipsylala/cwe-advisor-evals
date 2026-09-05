## Verdict

Exploitable. The `TokenValidationParameters` at line 15 omits `ValidAlgorithms`, leaving the accepted signing algorithm determined by the key type rather than explicitly pinned. An attacker can craft a JWT with `alg: "none"` or algorithm-confusion attacks to bypass signature validation entirely or switch to a weaker algorithm, forging an authentication token.

## Source

The JWT token supplied in the `Authorization: Bearer` header by the client. The token claims (subject, issuer, audience, expiry) are trusted only if the signature validates under the pinned algorithm.

## Fix

**Vulnerable code (line 15-26):**
```csharp
options.TokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = builder.Configuration["Jwt:Issuer"],
    ValidateAudience = true,
    ValidAudience = builder.Configuration["Jwt:Audience"],
    ValidateLifetime = true,
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(signingKeyBytes)
    // No ValidAlgorithms set: the accepted signing algorithm(s) are left to whatever
    // the resolved key type supports, rather than pinned to what the issuer signs with.
};
```

**Fixed code:**
```csharp
options.TokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = builder.Configuration["Jwt:Issuer"],
    ValidateAudience = true,
    ValidAudience = builder.Configuration["Jwt:Audience"],
    ValidateLifetime = true,
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(signingKeyBytes),
    ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 }
};
```

## Explanation

The fix adds `ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 }` to explicitly pin the accepted signing algorithm. This prevents algorithm-confusion and `alg: none` attacks by rejecting tokens signed with any algorithm other than the one the issuer actually uses. The `ValidateIssuerSigningKey = true` setting ensures the signature is verified, but without `ValidAlgorithms`, the validation scope is decided by the key type (SymmetricSecurityKey supports HMAC algorithms) rather than configuration. Pinning `ValidAlgorithms` to the exact algorithm closes this gap. If the issuer uses a different algorithm (RS256, ES256, etc.), substitute the corresponding `SecurityAlgorithms` constant.

## Behaviour changes

None. The fix adds configuration that was missing and closes the weakness without altering what gets validated, the return type of token validation, or any other part of the authentication contract. The handler still validates issuer, audience, lifetime, and signature exactly as before; it now additionally rejects tokens not signed with the pinned algorithm.
