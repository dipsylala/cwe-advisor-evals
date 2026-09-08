## Verdict

**Confirmed.** Line 58 uses `parseClaimsJwt()`, which accepts unsigned JWTs with `"alg":"none"` and never verifies a signature. This allows an attacker to forge an arbitrary JWT and authenticate as any user without possessing the signing key.

## Source

**File:** JwtAuthenticationFilter.java  
**Line:** 58  
**Code:** `Jwt<?, Claims> jwt = Jwts.parser().parseClaimsJwt(token);`

**Vulnerability:** The `parseClaimsJwt()` method is designed for parsing unsigned (unverified) JWTs. The parser is constructed without a signing key, and no signature verification occurs. An attacker can send a JWT with `"alg":"none"` in the header, and it will be accepted by this code, bypassing all authentication checks.

## Fix

### File: JwtAuthenticationFilter.java

```java
package com.example.security;

// jjwt (io.jsonwebtoken) 0.11.5 -- pom.xml:
//   <dependency>
//     <groupId>io.jsonwebtoken</groupId>
//     <artifactId>jjwt-api</artifactId>
//     <version>0.11.5</version>
//   </dependency>
//   <dependency>
//     <groupId>io.jsonwebtoken</groupId>
//     <artifactId>jjwt-impl</artifactId>
//     <version>0.11.5</version>
//     <scope>runtime</scope>
//   </dependency>
//   <dependency>
//     <groupId>io.jsonwebtoken</groupId>
//     <artifactId>jjwt-jackson</artifactId>
//     <version>0.11.5</version>
//     <scope>runtime</scope>
//   </dependency>

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

/**
 * Authenticates incoming requests from a bearer JWT on the Authorization header.
 *
 * On jjwt 0.11.5, this filter uses Jwts.parserBuilder().setSigningKey().build().parseClaimsJws(token)
 * to parse and verify the signature of JWTs. The signing key is required and validated on every parse,
 * preventing unsigned tokens (alg: none) from being accepted.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final SecretKey signingKey;

    public JwtAuthenticationFilter(@Value("${jwt.secret}") String secret) {
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader(AUTH_HEADER);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length());

            try {
                // Parse and verify the JWT signature with the signing key.
                // parseClaimsJws() (with 's' for 'signed') requires signature verification.
                // It rejects unsigned tokens (alg: none) and any token with an invalid signature.
                Jwt<?, Claims> jwt = Jwts.parserBuilder()
                        .setSigningKey(signingKey)
                        .build()
                        .parseClaimsJws(token);

                Claims claims = jwt.getBody();
                String username = claims.getSubject();

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (JwtException e) {
                // Invalid signature or malformed JWT. Do not authenticate the request.
                // Allow the request to proceed unauthenticated so downstream handlers can reject it.
            }
        }

        chain.doFilter(request, response);
    }
}
```

## Explanation

**Root Cause:** The original code calls `Jwts.parser().parseClaimsJwt(token)`. The `parseClaimsJwt()` method parses unsigned JWTs and performs no signature verification. An attacker can craft a JWT with `"alg":"none"` and forge any claims without possessing the signing key.

**Fix Mechanism:**

1. **Use `parseClaimsJws()` instead of `parseClaimsJwt()`:** The 's' in `parseClaimsJws` stands for 'signed'. This method requires a valid signature and rejects unsigned tokens.

2. **Provide a signing key via `setSigningKey()`:** The parser is configured with the HMAC secret key via `Keys.hmacShaKeyFor()`. Every JWT parse operation verifies the signature against this key.

3. **Use `parserBuilder()`:** Replace the deprecated `parser()` API with `parserBuilder()`, which is the modern jjwt 0.11.5 approach and properly separates key setup from parsing.

4. **Inject the secret:** The signing secret is injected via constructor and `@Value` annotation, allowing configuration per deployment (e.g., from environment variables or property files).

5. **Add exception handling:** `JwtException` (thrown by `parseClaimsJws()` on invalid signatures or malformed tokens) is caught. Invalid JWTs do not authenticate the request; downstream handlers can reject them with a 401/403 response if needed.

**Verification:** The fix prevents unsigned JWTs from being accepted because `parseClaimsJws()` unconditionally validates the signature. The attacker must now possess the signing key to forge a valid JWT, restoring proper authentication.
