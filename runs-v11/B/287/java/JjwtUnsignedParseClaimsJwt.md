## Verdict

CONFIRMED. The vulnerability is real and exploitable.

## Source

The vulnerability is in `JwtAuthenticationFilter.java` at line 58. The `Authorization` header provides an attacker-controlled JWT token that flows directly to the authentication logic.

**Data flow:**
1. Attacker sends HTTP request with `Authorization: Bearer <malicious_jwt>`
2. Header value is extracted at line 53
3. Bearer token is stripped at line 55
4. Token is parsed at line 58 without signature verification
5. Claims are extracted and username is read at line 61
6. Unauthenticated `UsernamePasswordAuthenticationToken` is created and set in security context at lines 63-65
7. Request proceeds with attacker-supplied identity

## Fix

```java
// VULNERABLE - line 58:
Jwt<?, Claims> jwt = Jwts.parser().parseClaimsJwt(token);

// FIXED - replace with:
Jwt<?, Claims> jwt = Jwts.parser()
        .setSigningKey(signingKey)
        .parseClaimsJws(token);
```

**Complete fixed method:**

```java
@Override
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {

    String header = request.getHeader(AUTH_HEADER);
    if (header != null && header.startsWith(BEARER_PREFIX)) {
        String token = header.substring(BEARER_PREFIX.length());

        try {
            // Parse and verify the JWT signature against the configured signing key
            Jwt<?, Claims> jwt = Jwts.parser()
                    .setSigningKey(signingKey)
                    .parseClaimsJws(token);

            Claims claims = jwt.getBody();
            String username = claims.getSubject();

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (io.jsonwebtoken.JwtException e) {
            // Token is invalid, expired, or signature verification failed
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or unsigned JWT");
            return;
        }
    }

    chain.doFilter(request, response);
}
```

The `signingKey` must be injected as a dependency (e.g., via constructor or `@Value` annotation) and loaded from configuration or a secret store, never hardcoded:

```java
private final SecretKey signingKey;

public JwtAuthenticationFilter(SecretKey signingKey) {
    this.signingKey = signingKey;
}

// Or with Spring configuration:
@Value("${jwt.signing.key}")
private String signingKeyString;

@PostConstruct
private void init() {
    this.signingKey = Keys.hmacShaKeyFor(signingKeyString.getBytes(StandardCharsets.UTF_8));
}
```

## Explanation

The vulnerability occurs because `Jwts.parser().parseClaimsJwt(token)` accepts unsigned JWTs and tokens with `alg: none`. An attacker can craft a JWT header claiming no signature algorithm (`"alg":"none"`) and include arbitrary claims like `"sub":"admin"`. The vulnerable filter accepts this token without any cryptographic verification, extracts the attacker-controlled username claim, and uses it to create an authenticated session.

The fix replaces the unsigned parser with `parseClaimsJws()`, which requires the JWT to be signed. By providing `setSigningKey(signingKey)`, the parser verifies the signature against the server's key. Any token with a missing signature, an invalid algorithm, or a signature that does not match is rejected with a `JwtException`, preventing authentication bypass.

The try-catch block ensures that parsing failures return HTTP 401 Unauthorized rather than allowing unauthenticated access. The signing key is loaded from configuration, not hardcoded, so key rotation and environment-specific secrets are possible.

## Behaviour changes

- **Before fix:** Any JWT, signed or unsigned, with any claims, is accepted and authenticated immediately.
- **After fix:** Only JWTs signed with the server's key are accepted. Unsigned JWTs, tokens with wrong signatures, and tokens with `alg: none` are rejected.
- **Error handling:** Invalid tokens now return 401 Unauthorized instead of silently failing or proceeding unauthenticated.
- **Performance:** Added cryptographic signature verification per request (negligible overhead for standard HMAC or RSA algorithms).
- **Configuration requirement:** The signing key must be provided at runtime; it cannot be null or empty.
