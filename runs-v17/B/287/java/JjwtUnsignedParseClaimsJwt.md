## Verdict

CONFIRMED. The code uses `parseClaimsJwt()`, an unsigned JWT parser that accepts tokens with `alg: none` and never validates a signature. An attacker can forge a JWT, be authenticated as any user, and bypass all authorization checks.

## Source

Attacker-controlled JWT token from HTTP Authorization header (line 55: `header.substring(BEARER_PREFIX.length())`).

## Fix

Replace the unsigned `parseClaimsJwt()` call with the signed variant `parseClaimsJws()` bound to a server-side verification key. The key must be injected or loaded from secure configuration, never hardcoded.

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
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

/**
 * Authenticates incoming requests from a bearer JWT on the Authorization header.
 *
 * Uses jjwt 0.11.5 parseClaimsJws() to validate the JWT signature with a
 * server-side secret key. Rejects unsigned tokens ("alg":"none"), expired tokens,
 * and tokens with invalid signatures with a 401 response.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final String signingSecret;

    public JwtAuthenticationFilter(@Value("${jwt.signing.secret}") String signingSecret) {
        this.signingSecret = signingSecret;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader(AUTH_HEADER);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length());

            try {
                // Parse and validate the JWT signature with the server-side key.
                // parseClaimsJws() requires a signature and rejects alg:none tokens.
                byte[] decodedSecret = signingSecret.getBytes(StandardCharsets.UTF_8);
                javax.crypto.SecretKey key = new SecretKeySpec(decodedSecret, 0, decodedSecret.length, "HmacSHA256");
                
                Jwt<?, Claims> jwt = Jwts.parser()
                        .setSigningKey(key)
                        .parseClaimsJws(token);

                Claims claims = jwt.getBody();
                String username = claims.getSubject();

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (JwtException e) {
                // Signature validation failed, token is expired, malformed, or uses alg:none.
                // Fail closed: do not set authentication and let the request proceed unauthenticated.
                // The application's authorization layer will reject the unauthenticated request with 401.
                SecurityContextHolder.clearContext();
            }
        }

        chain.doFilter(request, response);
    }
}
```

## Explanation

The fix replaces `parseClaimsJwt()` with `parseClaimsJws()`, which requires and validates the JWT signature. The signature is validated using a server-side secret key (`signingSecret`) injected via Spring configuration. The key is encoded from the configuration string using HMAC-SHA256.

The original code called `parseClaimsJwt()`, which is jjwt's unsigned JWT parser. It accepts any JWT, including those with `"alg":"none"`, and returns claims without any cryptographic proof. This allows an attacker to forge a token and impersonate any user.

The fixed code:
- Uses `setSigningKey(key)` to bind the parser to the server's secret key
- Calls `parseClaimsJws(token)` instead, which validates the signature and rejects unsigned tokens
- Wraps the parse in a try-catch for `JwtException`, which covers signature validation failures, expiry, malformed tokens, and algorithm mismatches
- On any validation failure, clears the security context so the request proceeds unauthenticated (the framework's authorization layer will return 401)

The signature validation ensures only tokens signed with the server's secret key are accepted, preventing forgery.

## Behaviour changes

- Tokens with `alg: none` are now rejected (previously accepted)
- Tokens with invalid signatures are rejected (previously accepted)
- Expired tokens are rejected (now checked)
- On invalid/expired tokens, `SecurityContextHolder` is cleared and the request proceeds unauthenticated; the framework's authorization layer returns 401 (previously would have been authenticated as the attacker's claimed user)
- Valid tokens signed with the server's secret are accepted (same as before, but now cryptographically verified)
