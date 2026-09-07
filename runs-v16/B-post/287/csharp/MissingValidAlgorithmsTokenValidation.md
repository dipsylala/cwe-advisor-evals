## Verdict
exploitable

## Source
`TokenValidationParameters` object created on line 15 without setting the `ValidAlgorithms` property, allowing JWT tokens to be accepted with any algorithm supported by the symmetric key type rather than being pinned to the issuer's intended algorithm.

## Fix

**Vulnerable code (lines 15-26):**
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

The `TokenValidationParameters` object controls how JWT tokens are validated by the ASP.NET Core authentication middleware. Without the `ValidAlgorithms` property explicitly set, validation falls back to accepting whatever algorithms the resolved signing key (a `SymmetricSecurityKey`) supports by default. This enables algorithm-confusion attacks where an attacker can craft a token using a different signing algorithm—potentially a weaker one or even `alg: none`—that is still accepted because the algorithm check is not pinned. Setting `ValidAlgorithms` to an array containing only `SecurityAlgorithms.HmacSha256` (or the specific algorithm(s) the issuer actually uses) ensures that tokens with any other algorithm are rejected, closing the algorithm-confusion attack surface.

## Behaviour changes

- Added `ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 }` property to `TokenValidationParameters`. This is a restrictive change that does not alter the contract of validation—it only narrows the set of accepted algorithms from "whatever the key type supports" to the specific algorithm intended. Tokens that previously passed validation with an alternative algorithm will now correctly be rejected.
- Added a trailing comma after `IssuerSigningKey` property to accommodate the new property in the object initializer.
