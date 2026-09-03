## Verdict

Exploitable.

## Source

The `token` parameter in the `SignatureValidator` delegate receives an untrusted JWT from the HTTP `Authorization` header, supplied entirely by the client.

## Fix

**Vulnerable code (lines 19-32):**
```csharp
options.TokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = configuration["Auth:Issuer"],
    ValidateAudience = true,
    ValidAudience = configuration["Auth:Audience"],
    ValidateLifetime = true,
};

// VULNERABLE: Custom validator bypasses signature checking
options.TokenValidationParameters.SignatureValidator = (token, validationParameters) => new JsonWebToken(token);
```

**Fixed code:**
```csharp
options.TokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = configuration["Auth:Issuer"],
    ValidateAudience = true,
    ValidAudience = configuration["Auth:Audience"],
    ValidateLifetime = true,
    ValidateIssuerSigningKey = true,
    ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
};

// REMOVED: Custom SignatureValidator that bypassed verification
// The default validator enforces proper JWT signature validation
```

## Explanation

The original code assigns a custom `SignatureValidator` delegate that returns the token without checking its signature, completely bypassing JWT signature verification. This allows an attacker to forge any JWT and pass authentication. The fix removes the custom validator entirely and configures the built-in validation mechanism with explicit `ValidAlgorithms` and `ValidateIssuerSigningKey` to enforce proper cryptographic signature validation before accepting any token. The default validator checks the token's signature against the configured signing key, preventing forged tokens from being accepted. Additionally, `ValidAlgorithms` is explicitly set to the algorithm the issuer actually uses (in this case `HmacSha256`), preventing algorithm-confusion attacks where an attacker might try to switch to a weaker or `none` algorithm.

## Behaviour changes

- **ValidateIssuerSigningKey = true**: Explicitly enables signature validation (this is the default, but making it explicit ensures it is not accidentally overridden). No behavior change in practice, but improves clarity of the security intent.
- **ValidAlgorithms set to { SecurityAlgorithms.HmacSha256 }**: Restricts accepted signing algorithms to only the one configured for this issuer. This prevents algorithm-confusion attacks. Any token signed with a different algorithm (including `none`) will be rejected.
- **SignatureValidator delegate removed**: The default validation logic now handles signature verification, preventing tokens without valid signatures from being accepted.
