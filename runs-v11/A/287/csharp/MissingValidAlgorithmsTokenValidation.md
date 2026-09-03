## Verdict

**CWE-287: Improper Authentication** — Confirmed. The JWT token validation parameters do not restrict accepted signing algorithms, allowing algorithm substitution attacks.

## Source

Lines 15–26 in `Program.cs` configure `TokenValidationParameters` without specifying `ValidAlgorithms`. The absence of this constraint means the handler will accept any algorithm the resolved key type supports, rather than pinning to the intended signing algorithm(s).

## Fix

Add the `ValidAlgorithms` property to the `TokenValidationParameters` assignment to explicitly restrict accepted algorithms:

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
    ValidAlgorithms = new[] { "HS256" }  // Explicitly pin accepted algorithm(s)
};
```

## Explanation

JWT tokens include a `alg` header field that specifies which algorithm was used to sign the token. Without `ValidAlgorithms`, the validation handler trusts this unverified claim and accepts any algorithm compatible with the signing key type. An attacker can exploit this by crafting a token with a different algorithm—for example, switching from the intended HS256 to a weaker or unrestricted algorithm—while the handler still validates it against the configured key.

By setting `ValidAlgorithms` to an explicit list (e.g., `["HS256"]` for symmetric keys), the handler rejects any token bearing an algorithm not in that list, closing the substitution gap. For asymmetric keys (RSA, ECDSA), use the corresponding algorithm name (e.g., `"RS256"`, `"ES256"`). This constraint must match the algorithm(s) the issuer actually uses to sign tokens.
