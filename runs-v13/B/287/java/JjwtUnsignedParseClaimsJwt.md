## Verdict

Exploitable. The vulnerability exists on line 58 where an unsigned JWT parser accepts tokens with `alg: none` without signature verification. An attacker can forge any JWT and authenticate as any user.

## Source

`request.getHeader(AUTH_HEADER)` (line 53) obtains an untrusted Authorization header from the incoming HTTP request. The token value is extracted (line 55) and flows directly to the sink.

## Fix

**Vulnerable code (line 58):**
```java
Jwt<?, Claims> jwt = Jwts.parser().parseClaimsJwt(token);
```

**Fixed code:**
```java
Jwt<?, Claims> jwt = Jwts.parser().setSigningKey(signingKey).parseClaimsJws(token);
```

The `signingKey` must be a `SecretKey` (for HMAC algorithms) or `PublicKey` (for asymmetric algorithms) loaded from configuration or a secure store, never hardcoded. In a Spring filter, inject it via constructor:

```java
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private final SecretKey signingKey;

    public JwtAuthenticationFilter(SecretKey signingKey) {
        this.signingKey = signingKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader(AUTH_HEADER);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length());
            Jwt<?, Claims> jwt = Jwts.parser().setSigningKey(signingKey).parseClaimsJws(token);
            Claims claims = jwt.getBody();
            String username = claims.getSubject();
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }
}
```

The signing key should be generated with sufficient entropy (e.g., `Jwts.SIG.HS256.key().build()` for HMAC-SHA256) and loaded from a secure configuration source or secrets manager at application startup, not embedded in code.

## Explanation

The vulnerability stems from using `parseClaimsJwt()`, an unsigned JWT parser that accepts tokens with `alg: none` and performs no signature verification. This allows an attacker to forge any JWT and impersonate any user. The fix replaces `parseClaimsJwt()` with `parseClaimsJws()` (JWS = signed) and provides a verification key via `setSigningKey()`. Now the parser validates the token's cryptographic signature against the server's key, ensuring only tokens signed by the application are accepted. A forged token or one signed with a different key will be rejected with a `JwtException`. The key must be managed securely (loaded from config/secrets, never hardcoded) and must match the algorithm family used to sign tokens (HMAC key for HS256, etc.).

## Behaviour changes

1. **Signature enforcement**: The original code accepts any JWT including unsigned ones; the fixed code rejects all tokens that are not cryptographically signed with the provided key.
2. **Error handling**: Tokens with invalid signatures, wrong algorithms, or `alg: none` now throw `JwtException` instead of succeeding. The filter should catch this exception and return a 401 response rather than allowing an unauthenticated request to proceed.
3. **Key management requirement**: A signing key must now be provided to the filter. This is a new runtime dependency that must be loaded from configuration before the filter is instantiated. If the key is unavailable at startup, bean initialization will fail, preventing the application from running without authentication properly configured.
4. **Algorithm validation**: The verification key implicitly pins the acceptable algorithm family (HMAC for symmetric keys, RSA/EC for asymmetric keys), preventing algorithm-confusion attacks.
