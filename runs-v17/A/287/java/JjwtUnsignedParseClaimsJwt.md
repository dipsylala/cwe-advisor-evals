## Verdict

The code parses a JWT using `parseClaimsJwt()`, which accepts unsigned JWTs with `"alg":"none"` and never verifies a signature. This allows an attacker to forge arbitrary claims and authenticate as any user. The vulnerability is confirmed.

## Source

Line 58 in JwtAuthenticationFilter.java:
```
Jwt<?, Claims> jwt = Jwts.parser().parseClaimsJwt(token);
```

The `parseClaimsJwt()` method is designed for parsing unsigned JWTs only. It does not perform signature verification, allowing attackers to mint forged tokens with arbitrary claims.

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
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
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
 * Uses Jwts.parser().setSigningKey() with parseSignedClaims(token) to verify
 * the JWT signature before trusting the claims. This prevents authentication
 * bypass via forged unsigned tokens.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    @Value("${jwt.secret}")
    private String jwtSecret;

    private SecretKey signingKey;

    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        // Initialize the signing key from the secret string.
        // For production, ensure jwtSecret is at least 256 bits (32 bytes) for HS256.
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader(AUTH_HEADER);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length());

            try {
                // Verify the JWT signature by providing the signing key.
                // parseSignedClaims() rejects unsigned tokens and validates the signature.
                Jws<Claims> jws = Jwts.parser()
                        .setSigningKey(signingKey)
                        .parseSignedClaims(token);

                Claims claims = jws.getBody();
                String username = claims.getSubject();

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception e) {
                // Token is invalid or signature verification failed. Do not authenticate.
                // Continue the filter chain without setting authentication.
            }
        }

        chain.doFilter(request, response);
    }
}
```

## Explanation

The vulnerability stems from using `parseClaimsJwt()`, which is designed to parse unsigned JWTs and never verifies a signature. An attacker can create a JWT with `"alg":"none"` and arbitrary claims, and the application will accept it as valid authentication.

The fix uses `parseSignedClaims()` instead, which requires a signing key and verifies the JWT's signature before trusting the claims. The signing key is injected via Spring's `@Value` annotation and initialized in `afterPropertiesSet()`. The key is derived from the secret using `Keys.hmacShaKeyFor()`, which is appropriate for HMAC-SHA algorithms (default is HS256).

The import statement is changed from `Jwt<?, Claims>` to `Jws<Claims>` because `parseSignedClaims()` returns a signed JWT type. The return type `Jws` (JSON Web Signature) indicates that signature verification has been performed.

Error handling is added to catch exceptions from invalid or tampered tokens. If signature verification fails or the token is malformed, the exception is caught and the authentication is not set, denying the request.

This ensures that only tokens signed with the correct secret key are accepted, preventing authentication bypass via forged tokens.
