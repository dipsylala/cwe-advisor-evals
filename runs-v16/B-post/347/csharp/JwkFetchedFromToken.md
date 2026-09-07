## Verdict

**Confirmed.** The code is vulnerable to algorithm confusion (CWE-347). `TokenValidationParameters` lacks `ValidAlgorithms`, permitting an attacker to sign a token with `alg: HS256` using the server's RSA public key (which is public) as an HMAC secret, bypassing signature verification.

## Source

**File:** `evals/cases/347/csharp/JwkFetchedFromToken/JwkFetchedFromToken.cs`  
**Line:** 32  
**Sink:** `JwtSecurityTokenHandler.ValidateToken()`

**Data Flow:**  
The token parameter (attacker-controlled) passes through `ValidateToken()` with `TokenValidationParameters` that sets `ValidateIssuerSigningKey = true` but does NOT restrict `ValidAlgorithms`. The handler accepts whatever algorithm the token's unverified header declares. An attacker crafts a token with `alg: HS256` and signs it with the server's RSA public key (known from JWKS or OpenID metadata) used as an HMAC secret. The unguarded `IssuerSigningKeyResolver` (lines 22-28) fetches keys from the attacker-controlled `jku` header, but verification still succeeds because no algorithm validation blocks HS256.

## Fix

Add `ValidAlgorithms` to the `TokenValidationParameters` to restrict accepted algorithms to RS256:

```csharp
var parameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "https://auth.example.com",
    ValidateAudience = true,
    ValidAudience = "api://reports",
    ValidateLifetime = true,
    ValidateIssuerSigningKey = true,
    ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
    IssuerSigningKeyResolver = (rawToken, securityToken, kid, _) =>
    {
        var jwt = (JwtSecurityToken)securityToken;
        var jku = jwt.Header["jku"]?.ToString();
        var keySet = JsonWebKeySetFetcher.Fetch(jku);
        return keySet.Keys.Where(k => k.KeyId == kid);
    }
};
```

The `ValidAlgorithms` field (line 8, new) supplies a fixed array of permitted algorithms. `JwtSecurityTokenHandler` rejects tokens declaring any algorithm outside this set before verification proceeds.

## Explanation

`System.IdentityModel.Tokens.Jwt` defaults to accepting any algorithm the JWT header declares. Without `ValidAlgorithms`, a token claiming `alg: HS256` (HMAC-SHA256) is accepted even when the server intends RS256 (RSA-SHA256). An attacker knowing the server's RSA public key (published in JWKS endpoints and OpenID metadata) can sign a forged token using that key as an HMAC secret, producing a valid signature the server verifies. This is algorithm confusion and breaks authentication.

Setting `ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 }` pins the accepted algorithm to RS256 only. Any token claiming HS256 (or any other algorithm) fails validation with `SecurityTokenInvalidSignatureException` before the resolver is invoked or the key is used.

The unguarded `IssuerSigningKeyResolver` and `jku` header fetching remain; they are a second concern (SSRF/CWE-918 if the endpoint is untrusted, or key confusion if RSA public keys and HMAC secrets share the same keystore keyed only by `kid`). The present fix closes algorithm confusion; the resolver's trust model is orthogonal.

## Behaviour changes

- **Before:** Tokens with `alg: HS256`, `alg: none`, or any other declared algorithm pass validation if they verify under the resolver-supplied key.
- **After:** Only tokens with `alg: RS256` reach the resolver. Tokens declaring any other algorithm are rejected immediately with `SecurityTokenInvalidSignatureException`.

**API change:** None. `ValidateToken()` and `IssuerSigningKeyResolver` signatures remain unchanged. Return type and exception contract are preserved.

**Compatibility:** No breaking changes to calling code. Legitimate tokens already using RS256 validate as before. Clients already sending tokens with mismatched algorithms will now fail, which is the intended security improvement.

**Testing:** Mint a test token signed with RS256 (correct) and confirm it validates. Mint a second token with the same claims but altered header to `alg: HS256`, signed using the public key as an HMAC secret, and confirm `ValidateToken()` throws `SecurityTokenInvalidSignatureException`.
