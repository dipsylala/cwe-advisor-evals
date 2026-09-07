## Verdict

Exploitable.

## Source

JWT bearer token from the HTTP `Authorization` header, extracted and decoded by the JwtBearer middleware.

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

The fixed code adds `ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 }` to `TokenValidationParameters`. This pins the JWT validation to accept only the HmacSha256 signing algorithm, preventing algorithm-confusion attacks where an attacker modifies the token's `alg` header to a different algorithm (or `"none"`). Without this constraint, the validation falls back to what the `SymmetricSecurityKey` key type supports, leaving the decision to the key's capabilities rather than explicit configuration. Since the code uses a symmetric key with base64-encoded bytes, HmacSha256 is the appropriate choice. If the actual signing algorithm differs, substitute the matching value from the `SecurityAlgorithms` class (e.g., `HmacSha512` if that is what the issuer uses).

## Behaviour changes

None. `ValidAlgorithms` is a new property that tightens algorithm validation without altering the signature verification logic, return values, or error handling. The validation process remains the same; only the set of accepted algorithms is now explicitly constrained.
